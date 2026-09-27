use robox_core::{ScanResult, Severity};
use serde_json::{Value, json};
use std::collections::HashSet;

pub fn json_report(result: &ScanResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result)
}

pub fn markdown_report(result: &ScanResult) -> String {
    let mut output = format!(
        "# Robox security audit: {}\n\n**Project type:** {}  \n**Security score:** {}/100  \n**Findings:** {}  \n**Engine:** {}\n\n",
        result.project,
        result.project_kind.label(),
        result.security_score,
        result.findings.len(),
        result.engine_version
    );
    output.push_str("## Executive summary\n\n");
    output.push_str(if result.findings.is_empty() {
        "No deterministic rule findings were detected. This is not a guarantee of security.\n\n"
    } else {
        "Robox found issues requiring review. Prioritize critical and high-severity items before deployment.\n\n"
    });
    output.push_str("## Findings\n\n");
    for finding in &result.findings {
        output.push_str(&format!(
            "### {} - {}\n\n- Rule: `{}`\n- Confidence: {:.0}%\n- CVSS: {:.1}\n- CWE: {}\n- Sensitive asset: {}\n- Location: `{}` line {}\n\n{}\n\n```rust\n{}\n```\n\n**Root cause.** {}\n\n**Attack scenario.** {}\n\n**Remediation.** {}\n\n```rust\n{}\n```\n\n",
            finding.severity.label(),
            finding.title,
            finding.rule_id,
            finding.confidence * 100.0,
            finding.cvss,
            finding.cwe,
            finding.sensitive_asset,
            finding.location.file,
            finding.location.line_start,
            finding.summary,
            finding.location.snippet,
            finding.root_cause,
            finding.attack_scenario,
            finding.remediation,
            finding.secure_example
        ));
    }
    output.push_str("## Scope and limitations\n\n");
    for limitation in &result.limitations {
        output.push_str(&format!("- {limitation}\n"));
    }
    output
}

/// Generates a self-contained PDF using standard PDF fonts. The report always
/// contains four core sections and expands when all finding details need more
/// room. No browser or external rendering service is involved.
pub fn pdf_report(result: &ScanResult) -> Vec<u8> {
    let mut pages = Vec::new();
    pages.push(executive_page(result));
    pages.push(scope_page(result));
    pages.extend(finding_pages(result));
    pages.push(remediation_page(result));
    encode_pdf(pages, result)
}

pub fn sarif_report(result: &ScanResult) -> Result<String, serde_json::Error> {
    let mut seen = HashSet::new();
    let rules: Vec<Value> = result.findings.iter().filter(|finding| seen.insert(finding.rule_id.as_str())).map(|finding| json!({ "id": finding.rule_id, "name": finding.title, "shortDescription": { "text": finding.summary }, "help": { "text": finding.remediation }, "properties": { "security-severity": finding.cvss.to_string(), "tags": [finding.cwe, finding.category] } })).collect();
    let results: Vec<Value> = result.findings.iter().map(|finding| json!({
        "ruleId": finding.rule_id,
        "level": match finding.severity { Severity::Critical | Severity::High => "error", Severity::Medium => "warning", _ => "note" },
        "message": { "text": finding.summary },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": finding.location.file }, "region": { "startLine": finding.location.line_start, "endLine": finding.location.line_end, "snippet": { "text": finding.location.snippet } } } }],
        "partialFingerprints": { "roboxFindingId": finding.id }
    })).collect();
    serde_json::to_string_pretty(
        &json!({ "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "Robox", "version": result.engine_version, "informationUri": "https://github.com/mansiverma897993/Robox", "rules": rules } }, "results": results }] }),
    )
}

#[derive(Default)]
struct PdfPage {
    ops: String,
}

impl PdfPage {
    fn text(&mut self, x: f32, y: f32, size: f32, font: &str, value: &str) {
        self.ops.push_str(&format!(
            "BT /{font} {size:.1} Tf {x:.1} {y:.1} Td ({}) Tj ET\n",
            pdf_escape(value)
        ));
    }

    fn colored_text(
        &mut self,
        x: f32,
        y: f32,
        size: f32,
        font: &str,
        value: &str,
        color: (f32, f32, f32),
    ) {
        self.ops.push_str(&format!(
            "q {:.3} {:.3} {:.3} rg BT /{font} {size:.1} Tf {x:.1} {y:.1} Td ({}) Tj ET Q\n",
            color.0,
            color.1,
            color.2,
            pdf_escape(value)
        ));
    }

    fn rect(&mut self, x: f32, y: f32, width: f32, height: f32, color: (f32, f32, f32)) {
        self.ops.push_str(&format!(
            "q {:.3} {:.3} {:.3} rg {x:.1} {y:.1} {width:.1} {height:.1} re f Q\n",
            color.0, color.1, color.2
        ));
    }

    fn line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, gray: f32) {
        self.ops.push_str(&format!(
            "q {gray:.3} G 0.6 w {x1:.1} {y1:.1} m {x2:.1} {y2:.1} l S Q\n"
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn wrapped(
        &mut self,
        x: f32,
        mut y: f32,
        size: f32,
        width: usize,
        leading: f32,
        font: &str,
        value: &str,
    ) -> f32 {
        for line in wrap_text(value, width) {
            self.text(x, y, size, font, &line);
            y -= leading;
        }
        y
    }
}

fn page_header(page: &mut PdfPage, section: &str, title: &str) {
    page.rect(0.0, 790.0, 595.0, 52.0, (0.07, 0.075, 0.065));
    page.colored_text(38.0, 810.0, 9.0, "F2", "ROBOX", (0.84, 1.0, 0.27));
    page.colored_text(88.0, 810.0, 8.0, "F1", section, (0.78, 0.79, 0.75));
    page.text(38.0, 754.0, 22.0, "F2", title);
    page.line(38.0, 738.0, 557.0, 738.0, 0.82);
}

fn page_footer(page: &mut PdfPage, page_number: usize, result: &ScanResult) {
    page.line(38.0, 38.0, 557.0, 38.0, 0.85);
    page.colored_text(
        38.0,
        23.0,
        7.0,
        "F1",
        &format!(
            "{} | scan {} | Robox {}",
            result.project, result.id, result.engine_version
        ),
        (0.38, 0.4, 0.36),
    );
    page.text(531.0, 23.0, 7.0, "F2", &page_number.to_string());
}

fn executive_page(result: &ScanResult) -> PdfPage {
    let mut page = PdfPage::default();
    page.rect(0.0, 0.0, 595.0, 842.0, (0.97, 0.973, 0.955));
    page.rect(0.0, 690.0, 595.0, 152.0, (0.07, 0.075, 0.065));
    page.colored_text(
        42.0,
        808.0,
        11.0,
        "F2",
        "ROBOX / SOLANA SECURITY",
        (0.84, 1.0, 0.27),
    );
    page.colored_text(42.0, 752.0, 30.0, "F2", "SMART CONTRACT", (1.0, 1.0, 0.98));
    page.colored_text(42.0, 716.0, 30.0, "F2", "SECURITY AUDIT", (1.0, 1.0, 0.98));
    page.text(42.0, 650.0, 23.0, "F2", &result.project);
    page.colored_text(
        42.0,
        629.0,
        9.0,
        "F1",
        &format!(
            "{} | Completed {}",
            result.project_kind.label(),
            result.completed_at.format("%Y-%m-%d %H:%M UTC")
        ),
        (0.35, 0.37, 0.33),
    );

    page.text(42.0, 566.0, 10.0, "F2", "SECURITY SCORE");
    let score_color = if result.security_score >= 80 {
        (0.19, 0.55, 0.28)
    } else if result.security_score >= 50 {
        (0.84, 0.55, 0.10)
    } else {
        (0.90, 0.19, 0.13)
    };
    page.colored_text(
        42.0,
        490.0,
        64.0,
        "F2",
        &result.security_score.to_string(),
        score_color,
    );
    page.text(124.0, 500.0, 13.0, "F1", "/ 100");

    let severities = [
        (
            "CRITICAL",
            result.severity_count(Severity::Critical),
            (0.90, 0.19, 0.13),
        ),
        (
            "HIGH",
            result.severity_count(Severity::High),
            (0.94, 0.43, 0.12),
        ),
        (
            "MEDIUM",
            result.severity_count(Severity::Medium),
            (0.78, 0.59, 0.10),
        ),
        (
            "LOW",
            result.severity_count(Severity::Low),
            (0.35, 0.37, 0.33),
        ),
    ];
    for (index, (label, count, color)) in severities.iter().enumerate() {
        let x = 222.0 + index as f32 * 83.0;
        page.rect(x, 490.0, 72.0, 76.0, (0.94, 0.945, 0.925));
        page.colored_text(x + 11.0, 531.0, 22.0, "F2", &count.to_string(), *color);
        page.colored_text(x + 11.0, 508.0, 7.0, "F2", label, (0.35, 0.37, 0.33));
    }

    page.text(42.0, 430.0, 12.0, "F2", "EXECUTIVE ASSESSMENT");
    let assessment = if result.findings.is_empty() {
        "No deterministic rule findings were identified in the imported source. This is a positive signal, not proof of security. Manual business-logic review, adversarial testing, and deployment verification remain required."
    } else if result.severity_count(Severity::Critical) + result.severity_count(Severity::High) > 0
    {
        "Deployment is not recommended until critical and high-severity findings are remediated and independently verified. The detailed section identifies exact evidence, attack paths, and secure implementation patterns."
    } else {
        "The project contains review findings that should be addressed before production deployment. Resolve each item, add regression tests, and rerun Robox to confirm the deterministic signals are cleared."
    };
    page.wrapped(42.0, 408.0, 10.0, 92, 15.0, "F1", assessment);

    page.rect(42.0, 262.0, 511.0, 82.0, (0.91, 0.925, 0.875));
    page.text(57.0, 321.0, 9.0, "F2", "LIVE SOURCE EVIDENCE");
    page.wrapped(57.0, 302.0, 8.5, 101, 13.0, "F1", "This report was generated from an imported project by the Rust analysis engine. It contains no placeholder score, example finding, or fabricated code location.");

    page.text(42.0, 210.0, 10.0, "F2", "AUDIT IDENTIFIERS");
    page.text(42.0, 188.0, 8.0, "F1", &format!("Scan ID: {}", result.id));
    page.text(
        42.0,
        173.0,
        8.0,
        "F1",
        &format!("Engine: {}", result.engine_version),
    );
    page.text(
        42.0,
        158.0,
        8.0,
        "F1",
        &format!("Graph model: {}", result.graph.level),
    );
    page.text(
        42.0,
        143.0,
        8.0,
        "F1",
        &format!(
            "Source files parsed: {} / {}",
            result.metrics.parsed_files, result.metrics.rust_files
        ),
    );
    page
}

fn scope_page(result: &ScanResult) -> PdfPage {
    let mut page = PdfPage::default();
    page_header(&mut page, "ANALYSIS SCOPE", "Project surface and coverage");
    page.text(38.0, 708.0, 10.0, "F2", "DETECTED PROJECT PROFILE");
    page.text(
        38.0,
        688.0,
        8.5,
        "F1",
        &format!("Project type: {}", result.project_kind.label()),
    );
    page.text(
        38.0,
        673.0,
        8.5,
        "F1",
        &format!("Frameworks: {}", join_or_none(&result.profile.frameworks)),
    );
    page.text(
        38.0,
        658.0,
        8.5,
        "F1",
        &format!("Manifests: {}", join_or_none(&result.profile.manifests)),
    );
    let program_ids = join_or_none(&result.profile.program_ids);
    page.wrapped(
        38.0,
        643.0,
        8.5,
        92,
        13.0,
        "F1",
        &format!("Program IDs: {program_ids}"),
    );

    page.text(38.0, 590.0, 10.0, "F2", "MEASURED PROGRAM SURFACE");
    let metrics = [
        ("Rust files", result.metrics.rust_files),
        ("Lines of code", result.metrics.lines_of_code),
        ("Functions", result.metrics.functions),
        ("Instructions", result.metrics.instructions),
        ("Account groups", result.metrics.account_structs),
        ("Signer accounts", result.metrics.signer_accounts),
        ("Unchecked accounts", result.metrics.unchecked_accounts),
        ("Token accounts", result.metrics.token_accounts),
        ("PDA constraints", result.metrics.pda_constraints),
        ("CPI calls", result.metrics.cpi_calls),
        ("Sysvar reads", result.metrics.sysvar_reads),
        ("Dependencies", result.metrics.dependencies),
    ];
    for (index, (label, value)) in metrics.iter().enumerate() {
        let column = index % 3;
        let row = index / 3;
        let x = 38.0 + column as f32 * 174.0;
        let y = 536.0 - row as f32 * 58.0;
        page.rect(x, y, 160.0, 46.0, (0.95, 0.952, 0.94));
        page.text(x + 10.0, y + 25.0, 14.0, "F2", &value.to_string());
        page.colored_text(x + 49.0, y + 26.0, 7.5, "F1", label, (0.37, 0.39, 0.35));
    }

    page.text(38.0, 284.0, 10.0, "F2", "DETERMINISTIC CHECK COVERAGE");
    let checks = [
        "Authority signer typing and access control",
        "Unchecked account substitution and ownership boundaries",
        "Cross-program invocation target validation",
        "Panic-prone execution and checked arithmetic",
        "Canonical PDA bump constraints",
        "Unsafe Rust in on-chain paths",
        "Clock/timestamp dependence and lamport mutation",
        "Lossy numeric casts and token-account constraints",
        "Untyped external program accounts",
    ];
    for (index, check) in checks.iter().enumerate() {
        let column = index % 2;
        let row = index / 2;
        let x = 38.0 + column as f32 * 260.0;
        let y = 257.0 - row as f32 * 31.0;
        page.rect(x, y - 2.0, 8.0, 8.0, (0.15, 0.17, 0.14));
        page.text(x + 16.0, y - 1.0, 7.5, "F1", check);
    }
    page
}

fn finding_pages(result: &ScanResult) -> Vec<PdfPage> {
    let mut pages = Vec::new();
    let mut page = PdfPage::default();
    page_header(
        &mut page,
        "DETAILED FINDINGS",
        "Evidence and corrective action",
    );
    let mut y = 704.0;

    if result.findings.is_empty() {
        page.rect(38.0, 574.0, 519.0, 108.0, (0.91, 0.94, 0.89));
        page.text(
            56.0,
            648.0,
            14.0,
            "F2",
            "No deterministic findings detected",
        );
        page.wrapped(56.0, 624.0, 9.0, 92, 14.0, "F1", "The imported source did not match the active rule set. This result does not cover undiscovered business-logic flaws, economic attacks, runtime-only behavior, or vulnerabilities outside the imported files.");
    } else {
        for finding in &result.findings {
            let estimated = 144.0
                + wrap_text(&finding.summary, 88).len() as f32 * 11.0
                + wrap_text(&finding.remediation, 88).len() as f32 * 11.0
                + wrap_text(&finding.secure_example, 84).len() as f32 * 10.0;
            if y - estimated < 70.0 {
                pages.push(page);
                page = PdfPage::default();
                page_header(
                    &mut page,
                    "DETAILED FINDINGS / CONTINUED",
                    "Evidence and corrective action",
                );
                y = 704.0;
            }
            let accent = severity_color(finding.severity);
            page.rect(38.0, y - 3.0, 5.0, 23.0, accent);
            page.colored_text(52.0, y + 8.0, 7.5, "F2", finding.severity.label(), accent);
            page.text(112.0, y + 7.0, 11.0, "F2", &finding.title);
            y -= 17.0;
            page.colored_text(
                52.0,
                y,
                7.0,
                "F1",
                &format!(
                    "{} | {:.0}% confidence | CVSS {:.1} | {} | {}",
                    finding.rule_id,
                    finding.confidence * 100.0,
                    finding.cvss,
                    finding.cwe,
                    finding.category
                ),
                (0.38, 0.4, 0.36),
            );
            y -= 16.0;
            page.text(52.0, y, 7.5, "F2", "LOCATION");
            page.text(
                108.0,
                y,
                7.5,
                "F3",
                &format!("{}:{}", finding.location.file, finding.location.line_start),
            );
            y -= 15.0;
            page.text(52.0, y, 7.5, "F2", "SENSITIVE ASSET");
            y = page.wrapped(159.0, y, 8.0, 76, 11.0, "F1", &finding.sensitive_asset);
            y -= 3.0;
            y = page.wrapped(
                52.0,
                y,
                8.0,
                96,
                11.0,
                "F3",
                &format!("> {}", finding.location.snippet),
            );
            y -= 5.0;
            page.text(52.0, y, 7.5, "F2", "RISK");
            y -= 13.0;
            y = page.wrapped(52.0, y, 8.0, 96, 11.0, "F1", &finding.summary);
            y = page.wrapped(
                52.0,
                y - 2.0,
                8.0,
                96,
                11.0,
                "F1",
                &format!("Attack path: {}", finding.attack_scenario),
            );
            page.text(52.0, y - 2.0, 7.5, "F2", "RECOMMENDED FIX");
            y = page.wrapped(52.0, y - 16.0, 8.0, 96, 11.0, "F1", &finding.remediation);
            y = page.wrapped(
                52.0,
                y - 2.0,
                7.5,
                96,
                10.0,
                "F3",
                &format!("Secure pattern: {}", finding.secure_example),
            );
            y -= 12.0;
            page.line(52.0, y, 557.0, y, 0.88);
            y -= 22.0;
        }
    }
    pages.push(page);
    pages
}

fn remediation_page(result: &ScanResult) -> PdfPage {
    let mut page = PdfPage::default();
    page_header(&mut page, "REMEDIATION", "Fix plan and assurance boundary");
    page.text(38.0, 704.0, 10.0, "F2", "PRIORITIZED ACTION PLAN");
    let priorities = [
        (
            "1. BLOCK RELEASE",
            "Resolve every critical and high-severity finding. Verify authority, owner, address, PDA, CPI, and token invariants at each trust boundary.",
        ),
        (
            "2. ADD REGRESSION TESTS",
            "For every fix, add a failing exploit or misuse test first, then confirm the secure path and expected program error behavior.",
        ),
        (
            "3. RERUN AND COMPARE",
            "Run Robox again on the exact fixed revision. Archive JSON or SARIF output so resolved and newly introduced findings are traceable.",
        ),
        (
            "4. INDEPENDENT REVIEW",
            "Perform manual business-logic, economic-invariant, upgrade-authority, deployment, and integration review before mainnet release.",
        ),
    ];
    let mut y = 674.0;
    for (title, body) in priorities {
        page.text(38.0, y, 8.5, "F2", title);
        y = page.wrapped(178.0, y, 8.0, 69, 11.0, "F1", body) - 14.0;
    }

    page.text(38.0, 478.0, 10.0, "F2", "VERIFICATION CHECKLIST");
    let checklist = [
        "All privileged authorities are Signer accounts and bound to stored state.",
        "Every account owner, discriminator, address, mint, and authority invariant is enforced.",
        "Every PDA uses canonical seeds and bump handling consistently.",
        "Every CPI program ID is pinned and signer seeds are narrowly scoped.",
        "Arithmetic is checked and errors are returned without panic paths.",
        "Token transfers validate mint, token program, source, destination, and authority.",
        "Upgrade, close-account, rent, replay, and initialization behavior is tested.",
    ];
    y = 451.0;
    for item in checklist {
        page.rect(40.0, y - 3.0, 7.0, 7.0, (0.15, 0.17, 0.14));
        page.text(56.0, y - 2.0, 7.8, "F1", item);
        y -= 25.0;
    }

    page.text(38.0, 254.0, 10.0, "F2", "ANALYSIS LIMITATIONS");
    y = 230.0;
    for limitation in &result.limitations {
        page.colored_text(40.0, y, 8.0, "F2", "!", (0.78, 0.42, 0.10));
        y = page.wrapped(56.0, y, 7.8, 96, 11.0, "F1", limitation) - 7.0;
    }
    page.rect(38.0, 67.0, 519.0, 54.0, (0.94, 0.90, 0.82));
    page.wrapped(52.0, 100.0, 8.0, 102, 12.0, "F2", "Conclusion: Robox reports deterministic evidence from the imported source. It reduces review effort but does not guarantee that all vulnerabilities have been found or that the program is safe to deploy.");
    page
}

fn encode_pdf(mut pages: Vec<PdfPage>, result: &ScanResult) -> Vec<u8> {
    let page_count = pages.len();
    for (index, page) in pages.iter_mut().enumerate() {
        page_footer(page, index + 1, result);
    }
    let mut objects: Vec<Vec<u8>> = vec![Vec::new(); 5 + page_count * 2];
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();
    let kids = (0..page_count)
        .map(|index| format!("{} 0 R", 6 + index * 2))
        .collect::<Vec<_>>()
        .join(" ");
    objects[1] = format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>").into_bytes();
    objects[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec();
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_vec();
    objects[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec();
    for (index, page) in pages.into_iter().enumerate() {
        let page_object = 5 + index * 2;
        let page_id = page_object + 1;
        let content_id = page_id + 1;
        objects[page_object] = format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {content_id} 0 R >>").into_bytes();
        let content = page.ops.into_bytes();
        let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        stream.extend(content);
        stream.extend_from_slice(b"endstream");
        objects[page_object + 1] = stream;
    }

    let mut pdf = b"%PDF-1.4\n%ROBOX\n".to_vec();
    let mut offsets = vec![0usize];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let normalized = value
        .chars()
        .map(|character| if character.is_ascii() { character } else { ' ' })
        .collect::<String>();
    let mut lines = Vec::new();
    for paragraph in normalized.lines() {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if !current.is_empty() && current.len() + word.len() + 1 > width {
                lines.push(current);
                current = String::new();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            if word.len() > width {
                current.push_str(&word[..width]);
            } else {
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn pdf_escape(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '(' => "\\(".into(),
            ')' => "\\)".into(),
            '\\' => "\\\\".into(),
            character if character.is_ascii() && !character.is_control() => character.to_string(),
            _ => " ".into(),
        })
        .collect()
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "None detected".into()
    } else {
        values.join(", ")
    }
}

fn severity_color(severity: Severity) -> (f32, f32, f32) {
    match severity {
        Severity::Critical => (0.90, 0.19, 0.13),
        Severity::High => (0.94, 0.43, 0.12),
        Severity::Medium => (0.78, 0.59, 0.10),
        Severity::Low => (0.35, 0.37, 0.33),
        Severity::Informational => (0.20, 0.45, 0.64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robox_core::{ScanEngine, ScanSource, SourceFile};

    fn scan() -> ScanResult {
        ScanEngine::default()
            .scan(
                "demo",
                ScanSource::Inline(vec![SourceFile {
                    path: "lib.rs".into(),
                    content: "fn ok() {}".into(),
                }]),
            )
            .unwrap()
    }

    #[test]
    fn sarif_has_expected_version() {
        assert!(sarif_report(&scan()).unwrap().contains("2.1.0"));
    }

    #[test]
    fn sarif_deduplicates_rule_descriptors_for_multiple_findings() {
        let result = ScanEngine::default()
            .scan(
                "two-panics",
                ScanSource::Inline(vec![SourceFile {
                    path: "lib.rs".into(),
                    content:
                        "fn test() {\n let a = Some(1).unwrap();\n let b = Some(2).unwrap();\n}"
                            .into(),
                }]),
            )
            .unwrap();
        let sarif: Value = serde_json::from_str(&sarif_report(&result).unwrap()).unwrap();
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn pdf_is_valid_shape_and_has_four_core_pages() {
        let pdf = pdf_report(&scan());
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        assert!(String::from_utf8_lossy(&pdf).contains("/Count 4"));
        assert!(pdf.len() > 10_000);
    }
}
