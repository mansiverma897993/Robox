# Robox

Robox is a Rust-native security analysis foundation for Solana and Anchor programs. It scans local projects, browser-uploaded source files, and public GitHub repositories; returns explainable findings with exact code locations; and exports terminal, JSON, Markdown, and SARIF 2.1.0 reports.

This repository is intentionally honest about scope. Version `0.1.0` implements syntax-aware project discovery with `syn`, six deterministic security rules, project metrics, a lightweight relationship graph, report generation, a CLI, and REST/WebSocket access. It does **not** claim compiler-quality CFG/DFG, symbolic execution, or AI reasoning. Those capabilities have documented extension seams.

## What is included

- `robox-core`: source loading, Rust AST parsing, project metrics, relationship graph, rule registry, score calculation
- `robox-report`: JSON, Markdown, and GitHub-compatible SARIF 2.1.0
- `robox-cli`: local and CI-friendly scanning with score thresholds
- `robox-api`: Axum REST API, WebSocket result stream, inline upload scanning, restricted public-GitHub cloning
- `apps/web`: polished Next.js 16 dashboard with local file input, GitHub import, findings, remediation, graph, and report views
- `examples/vulnerable-anchor`: safe local fixture containing five deliberate review findings
- `.github/workflows/robox.yml`: SARIF CI example

## Quick start

Requirements: Rust stable, Node.js 22+, npm, and Git.

On Windows:

```powershell
cd D:\robooxx
.\scripts\setup.ps1
.\scripts\dev.ps1
```

On macOS or Linux:

```bash
cd /path/to/robooxx
./scripts/setup.sh
./scripts/dev.sh
```

Open `http://127.0.0.1:3000`. The Rust API listens on `http://127.0.0.1:8080`. Click **Run scan** for the bundled end-to-end demo, choose Rust/Cargo files for inline scanning, or enter a public `https://github.com/owner/repository` URL.

## CLI

```powershell
cargo run -p robox-cli -- scan examples/vulnerable-anchor
cargo run -p robox-cli -- scan path/to/anchor-project --format json --output report.json
cargo run -p robox-cli -- scan path/to/anchor-project --format markdown --output report.md
cargo run -p robox-cli -- scan path/to/anchor-project --format sarif --output report.sarif
cargo run -p robox-cli -- scan path/to/anchor-project --fail-on-score-below 70
```

Exit code `2` is used when `--fail-on-score-below` is configured and the score misses the threshold.

## API surface

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service health |
| `GET` | `/api/v1/demo` | Scan the bundled vulnerable fixture |
| `POST` | `/api/v1/scans` | Scan a local path, inline files, or public GitHub repository |
| `GET` | `/api/v1/scans/{id}` | Retrieve a completed scan |
| `GET` | `/api/v1/scans/{id}/report/{json|sarif|markdown}` | Export a report |
| `GET` | `/api/v1/ws/{id}` | Receive the current scan result over WebSocket |

Inline scan example:

```json
{
  "project": "vault",
  "source": {
    "type": "inline",
    "files": [
      { "path": "programs/vault/src/lib.rs", "content": "use anchor_lang::prelude::*;" }
    ]
  }
}
```

GitHub input is restricted to canonical HTTPS repository URLs and shallow clones. Private-repository credentials are deliberately not accepted by the MVP.

## Verification

```powershell
cargo fmt --all -- --check
cargo test --workspace
cd apps/web
npm run build
```

The generated demo artifacts are in `reports/`. See [Architecture](docs/architecture.md) and [Rule authoring](docs/rules.md) for extension guidance.

## Security model

Robox findings are review candidates, not proof that a program is vulnerable or secure. Production hardening should add sandboxed repository isolation, authentication and authorization, durable scan storage, rate and size limits, signed plugin distribution, and independent manual audit coverage.

Licensed under Apache-2.0.

