use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use robox_core::{ScanEngine, ScanSource};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "robox", version, about = "Solana and Anchor security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long, value_enum, default_value = "terminal")]
        format: Format,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        fail_on_score_below: u32,
    },
    Rules,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Markdown,
    Sarif,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Rules => println!(
            "RBX001 missing signer\nRBX002 unchecked account\nRBX003 arbitrary CPI\nRBX004 panic path\nRBX005 PDA bump\nRBX006 unsafe Rust"
        ),
        Command::Scan {
            path,
            format,
            output,
            fail_on_score_below,
        } => {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("project");
            let result = ScanEngine::default()
                .scan(name, ScanSource::Directory(path.clone()))
                .with_context(|| format!("unable to scan {}", path.display()))?;
            let report = match format {
                Format::Terminal => terminal_report(&result),
                Format::Json => robox_report::json_report(&result)?,
                Format::Markdown => robox_report::markdown_report(&result),
                Format::Sarif => robox_report::sarif_report(&result)?,
            };
            if let Some(output) = output {
                std::fs::write(&output, report)
                    .with_context(|| format!("unable to write {}", output.display()))?;
            } else {
                println!("{report}");
            }
            if fail_on_score_below > 0 && result.security_score < fail_on_score_below {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn terminal_report(result: &robox_core::ScanResult) -> String {
    let mut out = format!(
        "Robox scan · {} · score {}/100 · {} findings\n",
        result.project,
        result.security_score,
        result.findings.len()
    );
    for finding in &result.findings {
        out.push_str(&format!(
            "[{:<8}] {} ({}:{})\n",
            finding.severity.label(),
            finding.title,
            finding.location.file,
            finding.location.line_start
        ));
    }
    out
}
