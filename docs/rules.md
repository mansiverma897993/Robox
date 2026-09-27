# Rule authoring

Rules are small, deterministic Rust components. They receive a `RuleContext` containing the normalized relative path, source, and optional parsed `syn::File`, then return zero or more complete findings.

```rust
use robox_core::{Finding, Rule, RuleContext, RuleMetadata, Severity};

struct MyRule;

impl Rule for MyRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "RBX100",
            title: "Example invariant is missing",
            severity: Severity::Medium,
            confidence: 0.80,
            cvss: 5.0,
            cwe: "CWE-20",
            category: "Input validation",
        }
    }

    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {
        // Inspect context.syntax whenever an AST representation is appropriate.
        // Report exact source locations and evidence; avoid vague project-level alerts.
        Vec::new()
    }
}
```

Rule quality requirements:

- One stable rule ID and narrowly defined invariant.
- Exact file, line, and snippet evidence.
- A documented false-positive model and calibrated confidence.
- Root cause, plausible attack scenario, and concrete remediation.
- Tests for vulnerable, secure, malformed, and irrelevant fixtures.
- No network access, secret access, or mutation of the scanned project.

The 22 built-in rules cover signer authorization, account identity, CPI targets, panic paths, PDA bump handling, unsafe blocks, time gates, lamport accounting, numeric casts, SPL Token owner and authority relationships, sysvar identity, duplicate mutable accounts, type discrimination, reinitialization, manual close, and PDA signer sharing. Account checks are scoped to each Anchor field and its own constraints; findings remain review candidates because handler checks and business logic need human verification. See [the benchmark](benchmark.md) for paired insecure and repaired examples.
