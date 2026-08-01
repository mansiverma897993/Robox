use crate::{
    GraphEdge, GraphNode, ProjectGraph, ProjectMetrics, RuleContext, RuleRegistry, ScanResult,
    ScanSource, SourceFile,
};
use chrono::Utc;
use quote::ToTokens;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("project path does not exist: {0}")]
    MissingPath(String),
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("project contains no Rust source files")]
    NoRustFiles,
}

pub struct ScanEngine {
    registry: RuleRegistry,
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self {
            registry: RuleRegistry::default(),
        }
    }
}

impl ScanEngine {
    pub fn new(registry: RuleRegistry) -> Self {
        Self { registry }
    }

    pub fn scan(
        &self,
        project: impl Into<String>,
        source: ScanSource,
    ) -> Result<ScanResult, EngineError> {
        let started_at = Utc::now();
        let project = project.into();
        let files = match source {
            ScanSource::Directory(path) => load_directory(&path)?,
            ScanSource::Inline(files) => files
                .into_iter()
                .filter(|file| file.path.ends_with(".rs") || file.path.ends_with("Cargo.toml"))
                .collect(),
        };
        if !files.iter().any(|file| file.path.ends_with(".rs")) {
            return Err(EngineError::NoRustFiles);
        }

        let mut findings = Vec::new();
        let mut metrics = ProjectMetrics::default();
        let mut graph = ProjectGraph {
            level: "AST-derived project relationship graph (MVP)".into(),
            ..Default::default()
        };
        for file in &files {
            if file.path.ends_with("Cargo.toml") {
                metrics.dependencies += dependency_count(&file.content);
                continue;
            }
            metrics.rust_files += 1;
            metrics.lines_of_code += file
                .content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            metrics.pda_constraints += file.content.matches("seeds =").count();
            metrics.cpi_calls += file.content.matches("invoke(").count()
                + file.content.matches("invoke_signed(").count();
            let syntax = syn::parse_file(&file.content).ok();
            if let Some(ast) = syntax.as_ref() {
                metrics.parsed_files += 1;
                collect_ast(ast, &file.path, &mut metrics, &mut graph);
            }
            findings.extend(self.registry.analyze(&RuleContext {
                path: &file.path,
                source: &file.content,
                syntax: syntax.as_ref(),
            }));
        }

        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity.weight()));
        let penalty: u32 = findings
            .iter()
            .map(|finding| finding.severity.weight())
            .sum();
        let security_score = 100_u32.saturating_sub(penalty.min(100));
        let completed_at = Utc::now();
        let mut hasher = DefaultHasher::new();
        (project.as_str(), started_at.timestamp_nanos_opt()).hash(&mut hasher);
        Ok(ScanResult {
            id: format!("scan_{:x}", hasher.finish()), project, engine_version: env!("CARGO_PKG_VERSION").into(), started_at, completed_at, security_score, findings, metrics, graph,
            limitations: vec!["CFG/DFG and symbolic execution are extension points, not implemented analyses in this MVP.".into(), "Rules identify review candidates and do not replace a manual security audit.".into(), "AI-assisted reasoning is not enabled until an explicit provider adapter is configured.".into()],
        })
    }
}

fn load_directory(root: &Path) -> Result<Vec<SourceFile>, EngineError> {
    if !root.exists() {
        return Err(EngineError::MissingPath(root.display().to_string()));
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_str(),
                Some("target" | "node_modules" | ".git")
            )
        })
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file()
            || !(path.extension().is_some_and(|ext| ext == "rs")
                || path.file_name().is_some_and(|name| name == "Cargo.toml"))
        {
            continue;
        }
        let content = fs::read_to_string(path).map_err(|source| EngineError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        files.push(SourceFile {
            path: relative,
            content,
        });
    }
    Ok(files)
}

fn dependency_count(cargo: &str) -> usize {
    let mut in_dependencies = false;
    cargo
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_dependencies = trimmed.ends_with("dependencies]");
                return false;
            }
            in_dependencies
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && trimmed.contains('=')
        })
        .count()
}

fn collect_ast(
    ast: &syn::File,
    path: &str,
    metrics: &mut ProjectMetrics,
    graph: &mut ProjectGraph,
) {
    let file_id = format!("file:{path}");
    graph.nodes.push(GraphNode {
        id: file_id.clone(),
        label: path.into(),
        kind: "file".into(),
    });
    collect_items(&ast.items, path, &file_id, metrics, graph);
}

fn collect_items(
    items: &[syn::Item],
    path: &str,
    parent: &str,
    metrics: &mut ProjectMetrics,
    graph: &mut ProjectGraph,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                metrics.functions += 1;
                let name = function.sig.ident.to_string();
                let id = format!("fn:{path}:{name}");
                graph.nodes.push(GraphNode {
                    id: id.clone(),
                    label: name,
                    kind: "instruction".into(),
                });
                graph.edges.push(GraphEdge {
                    source: parent.into(),
                    target: id,
                    relation: "contains".into(),
                });
            }
            syn::Item::Struct(structure) => {
                let is_accounts = structure.attrs.iter().any(|attr| {
                    attr.path()
                        .segments
                        .last()
                        .is_some_and(|segment| segment.ident == "derive")
                }) && structure
                    .fields
                    .iter()
                    .any(|field| field.ty.to_token_stream().to_string().contains("Account"));
                if is_accounts {
                    metrics.account_structs += 1;
                    let name = structure.ident.to_string();
                    let id = format!("account:{path}:{name}");
                    graph.nodes.push(GraphNode {
                        id: id.clone(),
                        label: name,
                        kind: "accounts".into(),
                    });
                    graph.edges.push(GraphEdge {
                        source: parent.into(),
                        target: id,
                        relation: "declares".into(),
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_items(nested, path, parent, metrics, graph);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_signer_and_panic_issues() {
        let source = SourceFile {
            path: "lib.rs".into(),
            content: "pub authority: AccountInfo<'info>,\nlet x = value.unwrap();".into(),
        };
        let result = ScanEngine::default()
            .scan("demo", ScanSource::Inline(vec![source]))
            .unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "RBX001"));
        assert!(result.findings.iter().any(|f| f.rule_id == "RBX004"));
    }
}
