use anyhow::Context;
use axum::{
    Json, Router,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use futures_util::SinkExt;
use robox_core::{ScanEngine, ScanResult, ScanSource, SourceFile};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, process::Command, sync::Arc};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "ROBOX_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    #[arg(
        long,
        env = "ROBOX_DEMO_PATH",
        default_value = "examples/vulnerable-anchor"
    )]
    demo_path: PathBuf,
}

#[derive(Clone)]
struct AppState {
    scans: Arc<RwLock<HashMap<String, ScanResult>>>,
    demo_path: Arc<PathBuf>,
}

#[derive(Deserialize)]
struct ScanRequest {
    project: String,
    source: SourceRequest,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SourceRequest {
    Path { path: PathBuf },
    Inline { files: Vec<SourceFile> },
    Github { url: String, branch: Option<String> },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let state = AppState {
        scans: Arc::new(RwLock::new(HashMap::new())),
        demo_path: Arc::new(args.demo_path),
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({ "status": "ok", "service": "robox-api" })) }),
        )
        .route("/api/v1/demo", get(scan_demo))
        .route("/api/v1/scans", post(create_scan))
        .route("/api/v1/scans/{id}", get(get_scan))
        .route("/api/v1/scans/{id}/report/{format}", get(get_report))
        .route("/api/v1/ws/{id}", get(scan_socket))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    tracing::info!(address = %args.bind, "Robox API listening");
    axum::serve(tokio::net::TcpListener::bind(args.bind).await?, app).await?;
    Ok(())
}

async fn scan_demo(State(state): State<AppState>) -> Result<Json<ScanResult>, ApiError> {
    let result = ScanEngine::default().scan(
        "sentinel-vault",
        ScanSource::Directory((*state.demo_path).clone()),
    )?;
    state
        .scans
        .write()
        .await
        .insert(result.id.clone(), result.clone());
    Ok(Json(result))
}

async fn create_scan(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanResult>), ApiError> {
    let result = match request.source {
        SourceRequest::Path { path } => {
            ScanEngine::default().scan(request.project, ScanSource::Directory(path))?
        }
        SourceRequest::Inline { files } => {
            ScanEngine::default().scan(request.project, ScanSource::Inline(files))?
        }
        SourceRequest::Github { url, branch } => {
            scan_github(&request.project, &url, branch.as_deref())?
        }
    };
    state
        .scans
        .write()
        .await
        .insert(result.id.clone(), result.clone());
    Ok((StatusCode::CREATED, Json(result)))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScanResult>, ApiError> {
    state
        .scans
        .read()
        .await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("scan not found"))
}

async fn get_report(
    State(state): State<AppState>,
    Path((id, format)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let result = state
        .scans
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("scan not found"))?;
    let (content_type, body) = match format.as_str() {
        "json" => ("application/json", robox_report::json_report(&result)?),
        "sarif" => (
            "application/sarif+json",
            robox_report::sarif_report(&result)?,
        ),
        "md" | "markdown" => (
            "text/markdown; charset=utf-8",
            robox_report::markdown_report(&result),
        ),
        _ => {
            return Err(ApiError::bad_request(
                "format must be json, sarif, or markdown",
            ));
        }
    };
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        )],
        body,
    )
        .into_response())
}

async fn scan_socket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| socket_session(socket, state, id))
}

async fn socket_session(mut socket: WebSocket, state: AppState, id: String) {
    let payload = match state.scans.read().await.get(&id) {
        Some(result) => serde_json::json!({ "event": "scan.completed", "scan": result }),
        None => serde_json::json!({ "event": "scan.not_found", "scan_id": id }),
    };
    let _ = socket.send(Message::Text(payload.to_string().into())).await;
    let _ = socket.close().await;
}

fn scan_github(project: &str, url: &str, branch: Option<&str>) -> Result<ScanResult, ApiError> {
    validate_github_url(url)?;
    let temp = tempfile::tempdir().context("unable to allocate clone directory")?;
    let mut command = Command::new("git");
    command.args(["clone", "--depth", "1"]);
    if let Some(branch) = branch {
        if branch.is_empty()
            || !branch
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_/.".contains(c))
        {
            return Err(ApiError::bad_request("invalid branch name"));
        }
        command.args(["--branch", branch]);
    }
    let output = command
        .arg(url)
        .arg(temp.path())
        .output()
        .context("unable to execute git")?;
    if !output.status.success() {
        return Err(ApiError::bad_request(
            "GitHub clone failed; verify the public repository URL and branch",
        ));
    }
    Ok(ScanEngine::default().scan(project, ScanSource::Directory(temp.path().to_path_buf()))?)
}

fn validate_github_url(url: &str) -> Result<(), ApiError> {
    let Some(path) = url.strip_prefix("https://github.com/") else {
        return Err(ApiError::bad_request(
            "only https://github.com URLs are accepted",
        ));
    };
    let parts: Vec<_> = path.trim_end_matches(".git").split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        })
    {
        return Err(ApiError::bad_request(
            "GitHub URL must identify one owner/repository",
        ));
    }
    Ok(())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}
impl From<robox_core::EngineError> for ApiError {
    fn from(error: robox_core::EngineError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
