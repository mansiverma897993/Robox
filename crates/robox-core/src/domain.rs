use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ScanSource {
    Directory(PathBuf),
    Inline(Vec<SourceFile>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectKind {
    Anchor,
    SolanaProgram,
    RustCrate,
}

impl ProjectKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Anchor => "Anchor program",
            Self::SolanaProgram => "Native Solana program",
            Self::RustCrate => "Rust crate",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectProfile {
    pub kind: ProjectKind,
    pub frameworks: Vec<String>,
    pub program_ids: Vec<String>,
    pub manifests: Vec<String>,
    pub has_anchor_workspace: bool,
    pub has_solana_dependency: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Self::Critical => 30,
            Self::High => 18,
            Self::Medium => 10,
            Self::Low => 4,
            Self::Informational => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Informational => "Informational",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: f32,
    pub cvss: f32,
    pub cwe: String,
    pub category: String,
    #[serde(default)]
    pub sensitive_asset: String,
    pub location: CodeLocation,
    pub summary: String,
    pub root_cause: String,
    pub attack_scenario: String,
    pub remediation: String,
    pub secure_example: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectMetrics {
    pub rust_files: usize,
    pub parsed_files: usize,
    pub lines_of_code: usize,
    pub functions: usize,
    pub account_structs: usize,
    pub pda_constraints: usize,
    pub cpi_calls: usize,
    pub dependencies: usize,
    pub instructions: usize,
    pub programs: usize,
    pub signer_accounts: usize,
    pub unchecked_accounts: usize,
    pub token_accounts: usize,
    pub sysvar_reads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub project: String,
    pub project_kind: ProjectKind,
    pub profile: ProjectProfile,
    pub engine_version: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub security_score: u32,
    pub findings: Vec<Finding>,
    pub metrics: ProjectMetrics,
    pub graph: ProjectGraph,
    pub limitations: Vec<String>,
}

impl ScanResult {
    pub fn severity_count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}
