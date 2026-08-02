# Architecture

## Current data flow

```mermaid
flowchart LR
  A[Local path] --> E[Source loader]
  B[Browser files] --> E
  C[Public GitHub repository] --> D[Validated shallow clone]
  D --> E
  E --> Q[In-process scan job]
  Q --> F
  E --> F[syn Rust AST]
  F --> G[Solana profile, metrics, and relationship model]
  F --> H[Rule registry]
  H --> I[Scored findings]
  G --> J[Scan result]
  I --> J
  J --> K[CLI]
  J --> L[REST and WebSocket API]
  J --> M[JSON / Markdown / SARIF]
  L --> N[Next.js dashboard]
```

Security-critical analysis and orchestration are implemented in Rust. The web app is a presentation and input layer; it does not decide whether a finding exists.

## Crate boundaries

`robox-core` owns stable domain types and deterministic analysis. `ScanEngine` accepts directory or inline sources, reads Rust and TOML manifests, classifies Anchor/native Solana/Rust projects, parses Rust with `syn`, collects Solana metrics and relationship nodes, runs a `RuleRegistry`, and computes a transparent score.

`robox-report` is a pure projection layer. It accepts a `ScanResult` and cannot mutate or reclassify findings. Its PDF output contains four core audit sections and adds finding pages as needed so exact evidence and remediation are not truncated.

`robox-api` owns transport and orchestration concerns. GitHub cloning is constrained to public canonical HTTPS URLs. Jobs expose queued/scanning/completed/failed state over REST and WebSocket. Job and completed-scan storage is in-memory for the MVP.

`robox-cli` is the CI surface. It supports machine-readable formats and an explicit score gate.

## Extension seams

- **Rules:** implement `Rule` and register it with `RuleRegistry`.
- **Compiler analysis:** introduce an `AnalysisProvider` that enriches the project model with rust-analyzer or rustc-derived call, control-flow, and data-flow edges. Do not label syntax adjacency as CFG/DFG.
- **Symbolic execution:** consume a validated MIR-like intermediate representation behind a bounded execution service.
- **AI review:** use a provider adapter that receives evidence packages, never raw credentials. AI output should be separately attributed, confidence-scored, and prohibited from silently changing deterministic severity.
- **Plugins:** the current registry is compile-time and memory-safe. A production plugin system should prefer WASI components with capability restrictions, versioned schemas, time/memory limits, and signed distribution over native dynamic libraries.
- **Persistence:** replace the in-memory scan map with a repository trait backed by PostgreSQL or object storage.
- **Queueing:** replace the in-process `/jobs` worker with durable isolated workers for horizontal scale and stronger untrusted-repository isolation.

## Production hardening checklist

1. Run every untrusted repository in a network-restricted, read-only sandbox with CPU, memory, file-count, and wall-clock limits.
2. Add workspace authentication, per-project authorization, audit logs, and encrypted provider secrets.
3. Enforce upload size, file type, decompression, path traversal, and repository host policies.
4. Pin and audit dependencies; sign release binaries and rule bundles.
5. Store immutable scan inputs and detector versions for reproducible results.
6. Add integration tests against representative Anchor versions and a labeled vulnerability corpus.
