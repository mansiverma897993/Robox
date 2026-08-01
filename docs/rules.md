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

The six built-in MVP rules cover missing signer typing, unchecked accounts, potentially arbitrary CPI, panic paths, PDA bump omission, and unsafe blocks. Their pattern-based limitations are intentional and should be improved toward AST semantics before expanding breadth.

