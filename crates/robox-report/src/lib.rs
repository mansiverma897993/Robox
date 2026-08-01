use robox_core::ScanResult;
use serde_json::{Value, json};

pub fn json_report(result: &ScanResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result)
}

pub fn markdown_report(result: &ScanResult) -> String {
    let mut output = format!(
        "# Robox security audit: {}\n\n**Security score:** {}/100  \n**Findings:** {}  \n**Engine:** {}\n\n",
        result.project,
        result.security_score,
        result.findings.len(),
        result.engine_version
    );
    output.push_str("## Executive summary\n\n");
    output.push_str(if result.findings.is_empty() { "No rule-based findings were detected. This is not a guarantee of security.\n\n" } else { "Robox found issues requiring review. Prioritize critical and high-severity items before deployment.\n\n" });
    output.push_str("## Findings\n\n");
    for finding in &result.findings {
        output.push_str(&format!("### {} — {}\n\n- Rule: `{}`\n- Confidence: {:.0}%\n- CVSS: {:.1}\n- CWE: {}\n- Location: `{}` line {}\n\n{}\n\n```rust\n{}\n```\n\n**Attack scenario.** {}\n\n**Remediation.** {}\n\n```rust\n{}\n```\n\n", finding.severity.label(), finding.title, finding.rule_id, finding.confidence * 100.0, finding.cvss, finding.cwe, finding.location.file, finding.location.line_start, finding.summary, finding.location.snippet, finding.attack_scenario, finding.remediation, finding.secure_example));
    }
    output.push_str("## Scope and limitations\n\n");
    for limitation in &result.limitations {
        output.push_str(&format!("- {limitation}\n"));
    }
    output
}

pub fn sarif_report(result: &ScanResult) -> Result<String, serde_json::Error> {
    let rules: Vec<Value> = result.findings.iter().map(|finding| json!({ "id": finding.rule_id, "name": finding.title, "shortDescription": { "text": finding.summary }, "help": { "text": finding.remediation }, "properties": { "security-severity": finding.cvss.to_string(), "tags": [finding.cwe, finding.category] } })).collect();
    let results: Vec<Value> = result.findings.iter().map(|finding| json!({
        "ruleId": finding.rule_id,
        "level": match finding.severity { robox_core::Severity::Critical | robox_core::Severity::High => "error", robox_core::Severity::Medium => "warning", _ => "note" },
        "message": { "text": finding.summary },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": finding.location.file }, "region": { "startLine": finding.location.line_start, "endLine": finding.location.line_end, "snippet": { "text": finding.location.snippet } } } }],
        "partialFingerprints": { "roboxFindingId": finding.id }
    })).collect();
    serde_json::to_string_pretty(
        &json!({ "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "Robox", "version": result.engine_version, "informationUri": "https://github.com/robox-security/robox", "rules": rules } }, "results": results }] }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use robox_core::{ScanEngine, ScanSource, SourceFile};

    #[test]
    fn sarif_has_expected_version() {
        let result = ScanEngine::default()
            .scan(
                "demo",
                ScanSource::Inline(vec![SourceFile {
                    path: "lib.rs".into(),
                    content: "fn ok() {}".into(),
                }]),
            )
            .unwrap();
        assert!(sarif_report(&result).unwrap().contains("2.1.0"));
    }
}
