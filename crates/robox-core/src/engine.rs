use crate::{
    GraphEdge, GraphNode, ProjectGraph, ProjectKind, ProjectMetrics, ProjectProfile, RuleContext,
    RuleRegistry, ScanResult, ScanSource, SourceFile,
};
use chrono::Utc;
use quote::ToTokens;
use std::collections::{HashSet, hash_map::DefaultHasher};
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
            ScanSource::Inline(files) => files.into_iter().filter(is_supported_source).collect(),
        };
        if !files.iter().any(|file| file.path.ends_with(".rs")) {
            return Err(EngineError::NoRustFiles);
        }

        let profile = detect_profile(&files);
        let mut findings = Vec::new();
        let mut metrics = ProjectMetrics::default();
        let project_node = format!("project:{project}");
        let mut graph = ProjectGraph {
            level: "AST and Anchor account relationship graph".into(),
            nodes: vec![GraphNode {
                id: project_node.clone(),
                label: project.clone(),
                kind: match profile.kind {
                    ProjectKind::Anchor => "anchor_program",
                    ProjectKind::SolanaProgram => "solana_program",
                    ProjectKind::RustCrate => "rust_crate",
                }
                .into(),
            }],
            edges: Vec::new(),
        };

        for file in &files {
            if file.path.ends_with("Cargo.toml") {
                metrics.dependencies += dependency_count(&file.content);
                continue;
            }
            if !file.path.ends_with(".rs") {
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
            metrics.signer_accounts += file.content.matches("Signer<'info>").count();
            metrics.unchecked_accounts += file.content.matches("UncheckedAccount<'info>").count()
                + file.content.matches("AccountInfo<'info>").count();
            metrics.token_accounts += file.content.matches("TokenAccount").count();
            metrics.sysvar_reads += file.content.matches("Clock::get()").count()
                + file.content.matches("Rent::get()").count();

            let syntax = syn::parse_file(&file.content).ok();
            if let Some(ast) = syntax.as_ref() {
                metrics.parsed_files += 1;
                collect_ast(ast, &file.path, &project_node, &mut metrics, &mut graph);
            }
            collect_solana_relationships(file, &mut graph);
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
            id: format!("scan_{:x}", hasher.finish()),
            project,
            project_kind: profile.kind,
            profile,
            engine_version: env!("CARGO_PKG_VERSION").into(),
            started_at,
            completed_at,
            security_score,
            findings,
            metrics,
            graph,
            limitations: vec![
                "AST, Anchor constraints, CPI sites, PDAs, token accounts, and project manifests are analyzed; compiler CFG/DFG is not yet implemented.".into(),
                "Rules identify review candidates and do not replace a manual Solana security audit.".into(),
                "AI-assisted reasoning remains an explicit extension and cannot silently alter deterministic findings.".into(),
            ],
        })
    }
}

fn is_supported_source(file: &SourceFile) -> bool {
    file.path.ends_with(".rs") || file.path.ends_with(".toml")
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
                Some("target" | "node_modules" | ".git" | ".next" | ".anchor")
            )
        })
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file()
            || !(path
                .extension()
                .is_some_and(|ext| ext == "rs" || ext == "toml"))
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

fn detect_profile(files: &[SourceFile]) -> ProjectProfile {
    let combined = files
        .iter()
        .map(|file| file.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let has_anchor_workspace = files.iter().any(|file| file.path.ends_with("Anchor.toml"));
    let has_anchor_dependency = combined.contains("anchor-lang")
        || combined.contains("anchor_lang")
        || combined.contains("#[program]");
    let has_solana_dependency = combined.contains("solana-program")
        || combined.contains("solana_program")
        || combined.contains("entrypoint!");
    let kind = if has_anchor_workspace || has_anchor_dependency {
        ProjectKind::Anchor
    } else if has_solana_dependency {
        ProjectKind::SolanaProgram
    } else {
        ProjectKind::RustCrate
    };

    let mut frameworks = Vec::new();
    if has_anchor_workspace || has_anchor_dependency {
        frameworks.push("Anchor".into());
    }
    if has_solana_dependency || matches!(kind, ProjectKind::Anchor) {
        frameworks.push("Solana Program".into());
    }
    if combined.contains("anchor-spl")
        || combined.contains("anchor_spl")
        || combined.contains("spl-token")
    {
        frameworks.push("SPL Token".into());
    }

    let manifests = files
        .iter()
        .filter(|file| file.path.ends_with(".toml"))
        .map(|file| file.path.clone())
        .collect();

    ProjectProfile {
        kind,
        frameworks,
        program_ids: extract_program_ids(files),
        manifests,
        has_anchor_workspace,
        has_solana_dependency,
    }
}

fn extract_program_ids(files: &[SourceFile]) -> Vec<String> {
    let mut ids = HashSet::new();
    for file in files {
        for line in file.content.lines() {
            let trimmed = line.trim();
            if (trimmed.contains("declare_id!(") || trimmed.contains('='))
                && let Some(start) = trimmed.find('"')
                && let Some(end) = trimmed[start + 1..].find('"')
            {
                let candidate = &trimmed[start + 1..start + 1 + end];
                if (32..=44).contains(&candidate.len())
                    && candidate
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric())
                {
                    ids.insert(candidate.to_string());
                }
            }
        }
    }
    let mut ids: Vec<_> = ids.into_iter().collect();
    ids.sort();
    ids
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
    project_node: &str,
    metrics: &mut ProjectMetrics,
    graph: &mut ProjectGraph,
) {
    let file_id = format!("file:{path}");
    graph.nodes.push(GraphNode {
        id: file_id.clone(),
        label: path.into(),
        kind: "file".into(),
    });
    graph.edges.push(GraphEdge {
        source: project_node.into(),
        target: file_id.clone(),
        relation: "contains".into(),
    });
    collect_items(&ast.items, path, &file_id, false, metrics, graph);
}

fn collect_items(
    items: &[syn::Item],
    path: &str,
    parent: &str,
    in_program: bool,
    metrics: &mut ProjectMetrics,
    graph: &mut ProjectGraph,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                metrics.functions += 1;
                if in_program {
                    metrics.instructions += 1;
                }
                let name = function.sig.ident.to_string();
                let id = format!("fn:{path}:{name}");
                graph.nodes.push(GraphNode {
                    id: id.clone(),
                    label: name,
                    kind: if in_program {
                        "instruction"
                    } else {
                        "function"
                    }
                    .into(),
                });
                graph.edges.push(GraphEdge {
                    source: parent.into(),
                    target: id,
                    relation: if in_program { "exposes" } else { "contains" }.into(),
                });
            }
            syn::Item::Struct(structure) => {
                let attributes = structure
                    .attrs
                    .iter()
                    .map(ToTokens::to_token_stream)
                    .map(|tokens| tokens.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                if attributes.contains("Accounts") {
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
                        relation: "validates".into(),
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    let is_program = module
                        .attrs
                        .iter()
                        .any(|attribute| attribute.path().is_ident("program"));
                    let module_id = if is_program {
                        metrics.programs += 1;
                        let id = format!("program:{path}:{}", module.ident);
                        graph.nodes.push(GraphNode {
                            id: id.clone(),
                            label: module.ident.to_string(),
                            kind: "program".into(),
                        });
                        graph.edges.push(GraphEdge {
                            source: parent.into(),
                            target: id.clone(),
                            relation: "declares".into(),
                        });
                        id
                    } else {
                        parent.to_string()
                    };
                    collect_items(
                        nested,
                        path,
                        &module_id,
                        in_program || is_program,
                        metrics,
                        graph,
                    );
                }
            }
            _ => {}
        }
    }
}

fn collect_solana_relationships(file: &SourceFile, graph: &mut ProjectGraph) {
    let file_id = format!("file:{}", file.path);
    for (line_index, line) in file.content.lines().enumerate() {
        let (kind, relation) = if line.contains("seeds =") {
            ("pda", "derives")
        } else if line.contains("invoke(") || line.contains("invoke_signed(") {
            ("cpi", "invokes")
        } else if line.contains("TokenAccount") {
            ("token_account", "uses")
        } else {
            continue;
        };
        let id = format!("{kind}:{}:{}", file.path, line_index + 1);
        graph.nodes.push(GraphNode {
            id: id.clone(),
            label: match kind {
                "pda" => format!("PDA · line {}", line_index + 1),
                "cpi" => format!("CPI · line {}", line_index + 1),
                _ => format!("Token account · line {}", line_index + 1),
            },
            kind: kind.into(),
        });
        graph.edges.push(GraphEdge {
            source: file_id.clone(),
            target: id,
            relation: relation.into(),
        });
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

    #[test]
    fn recognizes_anchor_projects_and_instructions() {
        let result = ScanEngine::default()
            .scan(
                "anchor-demo",
                ScanSource::Inline(vec![
                    SourceFile {
                        path: "Anchor.toml".into(),
                        content: "[programs.localnet]\ndemo = \"11111111111111111111111111111111\""
                            .into(),
                    },
                    SourceFile {
                        path: "Cargo.toml".into(),
                        content: "[dependencies]\nanchor-lang = \"0.31\"".into(),
                    },
                    SourceFile {
                        path: "programs/demo/src/lib.rs".into(),
                        content: "#[program]\npub mod demo { pub fn initialize() {} }".into(),
                    },
                ]),
            )
            .unwrap();

        assert_eq!(result.project_kind, ProjectKind::Anchor);
        assert_eq!(result.metrics.instructions, 1);
        assert!(result.profile.has_anchor_workspace);
    }
}
