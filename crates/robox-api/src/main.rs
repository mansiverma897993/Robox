mod audit_requests;

use anyhow::Context;
use audit_requests::{
    AuditRequestInput, AuditRequestReceipt, AuditRequestRecord, AuditRequestStore,
};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use futures_util::SinkExt;
use robox_core::{RuleMetadata, RuleRegistry, ScanEngine, ScanResult, ScanSource, SourceFile};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{RwLock, Semaphore},
    time::Duration,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "ROBOX_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    #[arg(long, env = "ROBOX_DATABASE", default_value = "data/robox.sqlite3")]
    database: PathBuf,
}

#[derive(Clone)]
struct AppState {
    scans: Arc<RwLock<HashMap<String, ScanResult>>>,
    jobs: Arc<RwLock<HashMap<String, ScanJob>>>,
    audit_requests: Arc<AuditRequestStore>,
    admin_token: Option<Arc<String>>,
    scan_slots: Arc<Semaphore>,
}

#[derive(Clone, Deserialize)]
struct ScanRequest {
    project: String,
    source: SourceRequest,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SourceRequest {
    Path { path: PathBuf },
    Inline { files: Vec<SourceFile> },
    Github { url: String, branch: Option<String> },
}

#[derive(Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum JobStatus {
    Queued,
    Scanning,
    Completed,
    Failed,
}

#[derive(Clone, Serialize)]
struct ScanJob {
    id: String,
    project: String,
    status: JobStatus,
    stage: String,
    progress: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<ScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct AuditRequestListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let audit_requests = AuditRequestStore::initialize(&args.database)?;
    let state = AppState {
        scans: Arc::new(RwLock::new(HashMap::new())),
        jobs: Arc::new(RwLock::new(HashMap::new())),
        audit_requests: Arc::new(audit_requests),
        admin_token: std::env::var("ROBOX_ADMIN_TOKEN")
            .ok()
            .filter(|token| token.len() >= 32)
            .map(Arc::new),
        scan_slots: Arc::new(Semaphore::new(2)),
    };
    let cors = if let Ok(origin) = std::env::var("ROBOX_ALLOWED_ORIGIN") {
        CorsLayer::new()
            .allow_origin(HeaderValue::from_str(&origin).context("invalid ROBOX_ALLOWED_ORIGIN")?)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    } else {
        CorsLayer::permissive()
    };
    let app = Router::new()
        .route("/", get(api_index))
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({ "status": "ok", "service": "robox-api" })) }),
        )
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/scans", get(list_scans).post(create_scan))
        .route("/api/v1/scans/{id}", get(get_scan))
        .route("/api/v1/scans/{id}/report/{format}", get(get_report))
        .route("/api/v1/jobs", post(create_job))
        .route("/api/v1/jobs/{id}", get(get_job))
        .route("/api/v1/ws/{id}", get(scan_socket))
        .route(
            "/api/v1/audit-requests",
            post(create_audit_request).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/api/v1/admin/audit-requests", get(list_audit_requests))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    tracing::info!(address = %args.bind, "Robox API listening");
    axum::serve(tokio::net::TcpListener::bind(args.bind).await?, app).await?;
    Ok(())
}

async fn api_index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "robox-api",
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "documentation": "https://github.com/mansiverma897993/Robox/tree/main/docs",
        "health": "/health",
        "endpoints": {
            "rules": "GET /api/v1/rules",
            "scans": "GET|POST /api/v1/scans",
            "scan": "GET /api/v1/scans/{id}",
            "reports": "GET /api/v1/scans/{id}/report/{format}",
            "jobs": "POST /api/v1/jobs",
            "job": "GET /api/v1/jobs/{id}",
            "progress": "WS /api/v1/ws/{id}",
            "audit_requests": "POST /api/v1/audit-requests"
        }
    }))
}

async fn list_rules() -> Json<Vec<RuleMetadata>> {
    Json(RuleRegistry::default().metadata())
}

async fn create_audit_request(
    State(state): State<AppState>,
    Json(request): Json<AuditRequestInput>,
) -> Result<(StatusCode, Json<AuditRequestReceipt>), ApiError> {
    let request = request.normalize().map_err(ApiError::bad_request)?;
    let store = state.audit_requests.clone();
    let receipt = tokio::task::spawn_blocking(move || store.insert(request))
        .await
        .map_err(|error| ApiError::internal(format!("audit request worker failed: {error}")))??;
    Ok((StatusCode::CREATED, Json(receipt)))
}

async fn list_audit_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditRequestListQuery>,
) -> Result<Response, ApiError> {
    let token = state
        .admin_token
        .as_deref()
        .ok_or_else(|| ApiError::not_found("not found"))?;
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_equal(supplied.as_bytes(), token.as_bytes()) {
        return Err(ApiError::unauthorized());
    }
    let store = state.audit_requests.clone();
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).min(1_000_000);
    let records: Vec<AuditRequestRecord> =
        tokio::task::spawn_blocking(move || store.list(limit, offset))
            .await
            .map_err(|error| {
                ApiError::internal(format!("audit request worker failed: {error}"))
            })??;
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(records),
    )
        .into_response())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

async fn list_scans(State(state): State<AppState>) -> Json<Vec<ScanResult>> {
    let mut scans: Vec<_> = state.scans.read().await.values().cloned().collect();
    scans.sort_by_key(|scan| std::cmp::Reverse(scan.completed_at));
    Json(scans)
}

async fn create_scan(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanResult>), ApiError> {
    validate_request(&request)?;
    let slot = state
        .scan_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy())?;
    let result = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        perform_scan(request)
    })
    .await
    .map_err(|error| ApiError::internal(format!("scan worker failed: {error}")))??;
    remember_scan(&state, &result).await;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn create_job(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanJob>), ApiError> {
    validate_request(&request)?;
    let slot = state
        .scan_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy())?;
    let job = ScanJob {
        id: new_job_id(),
        project: request.project.clone(),
        status: JobStatus::Queued,
        stage: "Preparing project".into(),
        progress: 5,
        scan: None,
        error: None,
    };
    {
        let mut jobs = state.jobs.write().await;
        if jobs.len() >= 100 {
            let oldest = jobs
                .iter()
                .filter(|(_, item)| matches!(item.status, JobStatus::Completed | JobStatus::Failed))
                .map(|(id, _)| id.clone())
                .min();
            if let Some(id) = oldest {
                jobs.remove(&id);
            } else {
                return Err(ApiError::busy());
            }
        }
        jobs.insert(job.id.clone(), job.clone());
    }

    let worker_state = state.clone();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        let _slot = slot;
        update_job(
            &worker_state,
            &job_id,
            JobStatus::Scanning,
            "Loading source files",
            20,
        )
        .await;
        let scan = tokio::task::spawn_blocking(move || perform_scan(request)).await;
        match scan {
            Ok(Ok(result)) => {
                update_job(
                    &worker_state,
                    &job_id,
                    JobStatus::Scanning,
                    "Generating findings and graph",
                    85,
                )
                .await;
                remember_scan(&worker_state, &result).await;
                if let Some(job) = worker_state.jobs.write().await.get_mut(&job_id) {
                    job.status = JobStatus::Completed;
                    job.stage = "Audit complete".into();
                    job.progress = 100;
                    job.scan = Some(result);
                }
            }
            Ok(Err(error)) => fail_job(&worker_state, &job_id, error.message).await,
            Err(error) => {
                fail_job(
                    &worker_state,
                    &job_id,
                    format!("scan worker failed: {error}"),
                )
                .await
            }
        }
    });

    Ok((StatusCode::ACCEPTED, Json(job)))
}

async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScanJob>, ApiError> {
    state
        .jobs
        .read()
        .await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("scan job not found"))
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
    let (content_type, body): (&str, Vec<u8>) = match format.as_str() {
        "pdf" => ("application/pdf", robox_report::pdf_report(&result)),
        "json" => (
            "application/json",
            robox_report::json_report(&result)?.into_bytes(),
        ),
        "sarif" => (
            "application/sarif+json",
            robox_report::sarif_report(&result)?.into_bytes(),
        ),
        "md" | "markdown" => (
            "text/markdown; charset=utf-8",
            robox_report::markdown_report(&result).into_bytes(),
        ),
        _ => {
            return Err(ApiError::bad_request(
                "format must be pdf, json, sarif, or markdown",
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
    loop {
        let job = state.jobs.read().await.get(&id).cloned();
        let (payload, terminal) = if let Some(job) = job {
            let terminal = matches!(job.status, JobStatus::Completed | JobStatus::Failed);
            (
                serde_json::json!({ "event": "scan.progress", "job": job }),
                terminal,
            )
        } else if let Some(result) = state.scans.read().await.get(&id).cloned() {
            (
                serde_json::json!({ "event": "scan.completed", "scan": result }),
                true,
            )
        } else {
            (
                serde_json::json!({ "event": "scan.not_found", "scan_id": id }),
                true,
            )
        };
        if socket
            .send(Message::Text(payload.to_string().into()))
            .await
            .is_err()
            || terminal
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
    let _ = socket.close().await;
}

fn perform_scan(request: ScanRequest) -> Result<ScanResult, ApiError> {
    match request.source {
        SourceRequest::Path { path } => {
            Ok(ScanEngine::default().scan(request.project, ScanSource::Directory(path))?)
        }
        SourceRequest::Inline { files } => {
            Ok(ScanEngine::default().scan(request.project, ScanSource::Inline(files))?)
        }
        SourceRequest::Github { url, branch } => {
            scan_github(&request.project, &url, branch.as_deref())
        }
    }
}

fn scan_github(project: &str, url: &str, branch: Option<&str>) -> Result<ScanResult, ApiError> {
    validate_github_url(url)?;
    let temp = tempfile::tempdir().context("unable to allocate clone directory")?;
    let mut command = Command::new("git");
    command.args([
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--filter=blob:none",
    ]);
    if let Some(branch) = branch.filter(|branch| !branch.trim().is_empty()) {
        validate_branch(branch)?;
        command.args(["--branch", branch]);
    }
    let mut child = command
        .arg(url)
        .arg(temp.path())
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("unable to execute git")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("unable to wait for git clone")? {
            if !status.success() {
                return Err(ApiError::bad_request(
                    "GitHub clone failed; verify the public repository URL and branch",
                ));
            }
            break;
        }
        if started.elapsed() > std::time::Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ApiError::bad_request(
                "GitHub clone exceeded the 60 second limit",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(ScanEngine::default().scan(project, ScanSource::Directory(temp.path().to_path_buf()))?)
}

fn validate_request(request: &ScanRequest) -> Result<(), ApiError> {
    if request.project.trim().is_empty() || request.project.len() > 120 {
        return Err(ApiError::bad_request(
            "project name must be between 1 and 120 characters",
        ));
    }
    if matches!(&request.source, SourceRequest::Path { .. })
        && std::env::var("ROBOX_ALLOW_PATH_SCAN").as_deref() != Ok("1")
    {
        return Err(ApiError::bad_request(
            "server-side path scans are disabled; upload source files or use a public GitHub URL",
        ));
    }
    if let SourceRequest::Inline { files } = &request.source {
        if files.is_empty() {
            return Err(ApiError::bad_request(
                "select at least one Rust or manifest file",
            ));
        }
        if files.len() > 2_000
            || files.iter().map(|file| file.content.len()).sum::<usize>() > 12 * 1024 * 1024
        {
            return Err(ApiError::bad_request(
                "project upload exceeds the 2,000 file or 12 MB limit",
            ));
        }
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<(), ApiError> {
    if branch.len() > 200
        || !branch.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '/' | '.')
        })
    {
        return Err(ApiError::bad_request("invalid branch name"));
    }
    Ok(())
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
                    .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        })
    {
        return Err(ApiError::bad_request(
            "GitHub URL must identify one owner/repository",
        ));
    }
    Ok(())
}

async fn remember_scan(state: &AppState, result: &ScanResult) {
    let mut scans = state.scans.write().await;
    if scans.len() >= 100
        && let Some(id) = scans
            .iter()
            .min_by_key(|(_, scan)| scan.completed_at)
            .map(|(id, _)| id.clone())
    {
        scans.remove(&id);
    }
    scans.insert(result.id.clone(), result.clone());
}

async fn update_job(state: &AppState, id: &str, status: JobStatus, stage: &str, progress: u8) {
    if let Some(job) = state.jobs.write().await.get_mut(id) {
        job.status = status;
        job.stage = stage.into();
        job.progress = progress;
    }
}

async fn fail_job(state: &AppState, id: &str, error: String) {
    if let Some(job) = state.jobs.write().await.get_mut(id) {
        job.status = JobStatus::Failed;
        job.stage = "Audit failed".into();
        job.error = Some(error);
    }
}

fn new_job_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("job-{nanos:x}")
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid admin token".into(),
        }
    }
    fn busy() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "scan capacity is full; retry when a current scan finishes".into(),
        }
    }
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
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal(error.to_string())
    }
}
impl From<robox_core::EngineError> for ApiError {
    fn from(error: robox_core::EngineError) -> Self {
        Self::bad_request(error.to_string())
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::internal(error.to_string())
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
