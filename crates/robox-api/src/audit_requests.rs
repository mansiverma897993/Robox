use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = include_str!("../migrations/001_audit_requests.sql");
const ALLOWED_CHAINS: &[&str] = &["solana", "eclipse_svm", "other_svm", "not_sure"];

#[derive(Clone)]
pub struct AuditRequestStore {
    path: Arc<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditRequestInput {
    pub project_name: String,
    pub website_url: Option<String>,
    pub repository_url: String,
    pub chains: Vec<String>,
    pub prior_review: String,
    pub scope: String,
    pub email: String,
    pub telegram: Option<String>,
    pub contact_consent: bool,
    #[serde(default)]
    pub company_fax: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditRequestReceipt {
    pub id: String,
    pub status: &'static str,
    pub received_at: String,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuditRequestRecord {
    pub id: String,
    pub project_name: String,
    pub website_url: Option<String>,
    pub repository_url: String,
    pub chains: Vec<String>,
    pub prior_review: String,
    pub scope: String,
    pub email: String,
    pub telegram: Option<String>,
    pub status: String,
    pub received_at: String,
}

impl AuditRequestStore {
    pub fn initialize(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("unable to create database directory {}", parent.display())
            })?;
        }
        let connection = open_connection(&path)?;
        connection
            .execute_batch(SCHEMA)
            .context("unable to initialize audit request database")?;
        connection.execute_batch("PRAGMA optimize;")?;
        Ok(Self {
            path: Arc::new(path),
        })
    }

    pub fn insert(&self, request: AuditRequestInput) -> Result<AuditRequestReceipt> {
        let request = request.normalize().map_err(anyhow::Error::msg)?;
        let id = new_request_id();
        let received_at = chrono::Utc::now().to_rfc3339();
        let chains_json = serde_json::to_string(&request.chains)?;
        let connection = open_connection(self.path.as_ref())?;
        connection.execute(
            "INSERT INTO audit_requests (
                id, project_name, website_url, repository_url, chains_json,
                prior_review, scope, email, telegram, contact_consent, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 'new', ?10)",
            params![
                id,
                request.project_name,
                request.website_url,
                request.repository_url,
                chains_json,
                request.prior_review,
                request.scope,
                request.email,
                request.telegram,
                received_at,
            ],
        )?;
        Ok(AuditRequestReceipt {
            id,
            status: "received",
            received_at,
            message: "Your project was submitted securely. The Robox team will contact you using the details provided.",
        })
    }

    pub fn list(&self, limit: usize, offset: usize) -> Result<Vec<AuditRequestRecord>> {
        let connection = open_connection(self.path.as_ref())?;
        let mut statement = connection.prepare(
            "SELECT id, project_name, website_url, repository_url, chains_json,
                    prior_review, scope, email, telegram, status, created_at
             FROM audit_requests ORDER BY created_at DESC, id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map([limit.min(100) as i64, offset as i64], |row| {
            let chains_json: String = row.get(4)?;
            let chains = serde_json::from_str(&chains_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(AuditRequestRecord {
                id: row.get(0)?,
                project_name: row.get(1)?,
                website_url: row.get(2)?,
                repository_url: row.get(3)?,
                chains,
                prior_review: row.get(5)?,
                scope: row.get(6)?,
                email: row.get(7)?,
                telegram: row.get(8)?,
                status: row.get(9)?,
                received_at: row.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("unable to read audit requests")
    }
}

impl AuditRequestInput {
    pub fn normalize(mut self) -> std::result::Result<Self, String> {
        self.project_name = self.project_name.trim().to_owned();
        self.repository_url = self.repository_url.trim().to_owned();
        self.scope = self.scope.trim().to_owned();
        self.email = self.email.trim().to_lowercase();
        self.website_url = clean_optional(self.website_url);
        self.telegram = clean_optional(self.telegram).map(|value| {
            if value.starts_with('@') {
                value
            } else {
                format!("@{value}")
            }
        });

        if self
            .company_fax
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("submission could not be accepted".into());
        }
        if !(2..=120).contains(&self.project_name.chars().count()) {
            return Err("project name must be between 2 and 120 characters".into());
        }
        if let Some(url) = &self.website_url {
            validate_web_url(url, "website URL")?;
        }
        validate_web_url(&self.repository_url, "repository URL")?;
        if self.chains.is_empty() || self.chains.len() > ALLOWED_CHAINS.len() {
            return Err("select at least one supported deployment environment".into());
        }
        let unique: HashSet<_> = self.chains.iter().map(String::as_str).collect();
        if unique.len() != self.chains.len()
            || self
                .chains
                .iter()
                .any(|chain| !ALLOWED_CHAINS.contains(&chain.as_str()))
        {
            return Err("deployment environment contains an unsupported value".into());
        }
        if !matches!(self.prior_review.as_str(), "yes" | "no" | "not_sure") {
            return Err("prior review must be yes, no, or not sure".into());
        }
        if !(20..=4_000).contains(&self.scope.chars().count()) {
            return Err("project scope must be between 20 and 4,000 characters".into());
        }
        if !valid_email(&self.email) {
            return Err("enter a valid email address".into());
        }
        if self
            .telegram
            .as_ref()
            .is_some_and(|value| value.len() > 100)
        {
            return Err("Telegram handle must be 100 characters or fewer".into());
        }
        if !self.contact_consent {
            return Err("contact consent is required to submit a project".into());
        }
        self.company_fax = None;
        Ok(self)
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)
        .with_context(|| format!("unable to open audit request database {}", path.display()))?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    Ok(connection)
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
}

fn validate_web_url(url: &str, label: &str) -> std::result::Result<(), String> {
    if url.len() > 500
        || url.chars().any(char::is_whitespace)
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(format!("{label} must be a valid HTTP or HTTPS URL"));
    }
    let host = url
        .split("//")
        .nth(1)
        .unwrap_or_default()
        .split('/')
        .next()
        .unwrap_or_default();
    if host.is_empty() || !host.contains('.') {
        return Err(format!("{label} must include a valid host"));
    }
    Ok(())
}

fn valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && parts.next().is_none()
}

fn new_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("audit-{nanos:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> AuditRequestInput {
        AuditRequestInput {
            project_name: "Treasury Protocol".into(),
            website_url: Some("https://example.com".into()),
            repository_url: "https://github.com/example/treasury".into(),
            chains: vec!["solana".into()],
            prior_review: "no".into(),
            scope: "Review the Anchor treasury program and authority boundaries.".into(),
            email: "Security@Example.com".into(),
            telegram: Some("security-team".into()),
            contact_consent: true,
            company_fax: None,
        }
    }

    #[test]
    fn validates_and_normalizes_audit_request() {
        let request = valid_request().normalize().expect("valid request");
        assert_eq!(request.email, "security@example.com");
        assert_eq!(request.telegram.as_deref(), Some("@security-team"));
    }

    #[test]
    fn rejects_missing_contact_consent() {
        let mut request = valid_request();
        request.contact_consent = false;
        assert!(request.normalize().is_err());
    }

    #[test]
    fn persists_request_to_sqlite() {
        let directory = tempfile::tempdir().expect("temp database directory");
        let path = directory.path().join("requests.sqlite3");
        let store = AuditRequestStore::initialize(&path).expect("initialize store");
        let receipt = store.insert(valid_request()).expect("insert request");
        assert!(receipt.id.starts_with("audit-"));

        let connection = Connection::open(path).expect("open database");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM audit_requests", [], |row| row.get(0))
            .expect("count requests");
        assert_eq!(count, 1);
        let records = store.list(10, 0).expect("list requests");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].email, "security@example.com");
        assert_eq!(records[0].telegram.as_deref(), Some("@security-team"));
    }
}
