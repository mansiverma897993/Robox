"use client";

import Image from "next/image";
import Link from "next/link";
import { useMemo, useState } from "react";
import styles from "./docs.module.css";

const navigation = [
  { group: "Start here", items: [["introduction", "Introduction"], ["quick-start", "Quick start"], ["importing", "Import a project"], ["reading-results", "Read a scan"]] },
  { group: "Analysis", items: [["coverage", "Detection coverage"], ["program-model", "Program model"], ["findings", "Findings & fixes"], ["security-boundary", "Security boundary"]] },
  { group: "Integrate", items: [["reports", "Reports"], ["rest-api", "REST API"], ["websocket", "WebSocket"], ["cli", "CLI"], ["ci-cd", "CI / CD"]] },
  { group: "Build on Robox", items: [["architecture", "Architecture"], ["custom-rules", "Custom rules"], ["roadmap", "Extension points"], ["troubleshooting", "Troubleshooting"]] },
] as const;

const searchable = navigation.flatMap((section) => section.items.map(([id, label]) => ({ id, label, group: section.group })));

const rules = [
  ["RBX001", "Missing signer typing", "Identifies authority-shaped accounts that are not enforced as signers."],
  ["RBX002", "Unchecked account substitution", "Flags unchecked accounts crossing security-sensitive instruction boundaries."],
  ["RBX003", "Attacker-controlled CPI", "Finds cross-program invocations where the target program may not be constrained."],
  ["RBX004", "Panic-prone execution", "Surfaces unwrap, expect, panic, and assert paths that can abort on-chain execution."],
  ["RBX005", "Non-canonical PDA bump", "Checks PDA constraints for canonical bump handling."],
  ["RBX006", "Unsafe Rust on-chain", "Highlights unsafe blocks in program code for focused manual review."],
  ["RBX007", "Timestamp dependence", "Finds clock-dependent authorization or value logic that needs tolerance analysis."],
  ["RBX008", "Direct lamport mutation", "Detects direct lamport balance changes that require ownership and rent checks."],
  ["RBX009", "Lossy numeric cast", "Flags narrowing `as` conversions that may truncate amounts or counters."],
  ["RBX010", "Token account constraints", "Checks SPL token account declarations for mint and authority constraints."],
  ["RBX011", "External program as AccountInfo", "Finds external programs modeled without executable/program identity validation."],
];

function Code({ title, children }: { title: string; children: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(children);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }
  return <div className={styles.code}><div><span>{title}</span><button onClick={copy}>{copied ? "Copied" : "Copy"}</button></div><pre><code>{children}</code></pre></div>;
}

function DocSection({ id, eyebrow, title, children }: { id: string; eyebrow: string; title: string; children: React.ReactNode }) {
  return <section id={id} className={styles.section} data-doc-section><span className={styles.eyebrow}>{eyebrow}</span><h2>{title}</h2>{children}</section>;
}

export default function DocsPage() {
  const [query, setQuery] = useState("");
  const matches = useMemo(() => {
    const value = query.trim().toLowerCase();
    if (!value) return searchable;
    return searchable.filter((item) => `${item.label} ${item.group} ${item.id}`.toLowerCase().includes(value));
  }, [query]);

  return <div className={styles.docsShell}>
    <header className={styles.header}>
      <Link className={styles.brand} href="/" aria-label="Robox auditor home"><Image src="/robox-logo-transparent.png" width={392} height={352} alt="" priority /><strong>ROBOX</strong><span>Documentation</span></Link>
      <label className={styles.search}><span aria-hidden="true">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search documentation" aria-label="Search documentation" /><kbd>/</kbd></label>
      <Link className={styles.openApp} href="/">Open auditor <span>↗</span></Link>
    </header>

    <aside className={styles.sidebar} aria-label="Documentation navigation">
      <div className={styles.version}><span>ROBOX DOCS</span><b>v0.1.0</b></div>
      {navigation.map((section) => {
        const visible = section.items.filter(([id]) => matches.some((item) => item.id === id));
        if (!visible.length) return null;
        return <nav key={section.group}><strong>{section.group}</strong>{visible.map(([id, label]) => <a href={`#${id}`} key={id}>{label}<span>›</span></a>)}</nav>;
      })}
      {!matches.length && <p className={styles.noMatches}>No matching topic. Try “API”, “rules”, or “reports”.</p>}
      <div className={styles.sidebarNote}><i /> <div><strong>Engine status</strong><span>11 deterministic rules</span></div></div>
    </aside>

    <main className={styles.main}>
      <section className={styles.hero}>
        <div><span className={styles.heroTag}><i /> SOLANA SECURITY, EXPLAINED</span><h1>Build safer programs<br />with <em>evidence.</em></h1><p>The practical guide to auditing Anchor, native Solana, and Rust smart-contract projects with Robox.</p><div className={styles.heroActions}><a href="#quick-start">Start auditing <span>↓</span></a><a href="#architecture">Explore architecture</a></div></div>
        <div className={styles.heroModel} aria-hidden="true"><span className={styles.modelCore}>R</span><i className={styles.ringOne} /><i className={styles.ringTwo} /><b className={styles.modelLabelOne}>AST</b><b className={styles.modelLabelTwo}>CPI</b><b className={styles.modelLabelThree}>PDA</b></div>
      </section>

      <div className={styles.statusStrip}><span><i className={styles.statusDot} /> Current foundation</span><b>Real source input</b><b>Rust-native engine</b><b>Explainable findings</b><b>4 report formats</b></div>

      <DocSection id="introduction" eyebrow="OVERVIEW" title="What is Robox?">
        <p>Robox is a local-first security auditor for software built on Solana. It accepts Anchor workspaces, native Solana programs, and general Rust crates, then turns the source into a structured project profile, program relationships, security findings, and remediation guidance.</p>
        <div className={styles.featureGrid}><article><span>01</span><h3>Solana-aware</h3><p>Understands instruction handlers, account structs, signers, PDAs, CPIs, token accounts, sysvars, program IDs, and manifests.</p></article><article><span>02</span><h3>Evidence first</h3><p>Every finding contains a rule, severity, confidence, code location, source snippet, root cause, attack scenario, and secure example.</p></article><article><span>03</span><h3>Built for workflows</h3><p>Use the web workspace, Rust CLI, REST endpoints, WebSocket progress events, or SARIF output in continuous integration.</p></article></div>
        <aside className={styles.callout}><b>Honest by design</b><p>Robox is an automated review aid, not a proof of safety. Version 0.1.0 provides deterministic syntax and relationship analysis. It does not claim compiler-quality CFG/DFG, symbolic execution, runtime simulation, or complete business-logic detection.</p></aside>
      </DocSection>

      <DocSection id="quick-start" eyebrow="GETTING STARTED" title="Run your first live audit">
        <p>Keep the Robox API and web workspace running, then open the auditor. The dashboard remains empty until you import real source code—there are no sample scores or fabricated findings.</p>
        <div className={styles.steps}><article><b>1</b><div><h3>Choose your source</h3><p>Select a local project folder or paste a public GitHub repository URL.</p></div></article><article><b>2</b><div><h3>Start the security audit</h3><p>Robox queues the project, profiles it, parses Rust source, runs every active rule, and prepares reports.</p></div></article><article><b>3</b><div><h3>Review and remediate</h3><p>Work from highest severity to lowest, verify each exact code location, and use the suggested secure pattern as guidance.</p></div></article></div>
        <Code title="Local development">{`# Terminal 1 — Rust API\ncargo run -p robox-api\n\n# Terminal 2 — web workspace\ncd apps/web\nnpm run dev`}</Code>
      </DocSection>

      <DocSection id="importing" eyebrow="INPUTS" title="Import a project safely">
        <div className={styles.split}><div><h3>Project folder</h3><p>Choose the workspace root. The browser reads Rust and TOML source files and sends their paths and content to your local Robox API. Build outputs and unrelated assets are not needed.</p><ul><li><code>programs/**/src/*.rs</code></li><li><code>Cargo.toml</code> and workspace manifests</li><li><code>Anchor.toml</code> when present</li></ul></div><div><h3>Public GitHub</h3><p>Enter an HTTPS URL in <code>github.com/owner/repository</code> form and optionally provide a branch. The API applies repository and size restrictions before scanning.</p><ul><li>Public repositories only in the current UI</li><li>No credentials embedded in repository URLs</li><li>Branch is optional; the repository default is used otherwise</li></ul></div></div>
      </DocSection>

      <DocSection id="reading-results" eyebrow="WORKSPACE" title="Understand a completed scan">
        <div className={styles.definitionList}><div><dt>Security score</dt><dd>A prioritization signal derived from detected finding severity. It is not a certification or probability of exploitation.</dd></div><div><dt>Severity</dt><dd>Potential consequence if the issue is reachable: critical, high, medium, low, or informational.</dd></div><div><dt>Confidence</dt><dd>How strongly the available syntax and project context support the finding. Confirm findings during review.</dd></div><div><dt>Program surface</dt><dd>Measured instructions, accounts, PDAs, CPI calls, dependencies, files, functions, and source lines.</dd></div><div><dt>Project graph</dt><dd>A lightweight relationship view built from parsed source: program, instruction, account, PDA, and CPI nodes.</dd></div><div><dt>Limitations</dt><dd>Scan-specific boundaries carried into every result and professional report.</dd></div></div>
      </DocSection>

      <DocSection id="coverage" eyebrow="ANALYSIS" title="Detection coverage">
        <p>Version 0.1.0 ships eleven deterministic checks. The catalog is returned live by <code>GET /api/v1/rules</code>, so the UI and integrations can display the active engine rather than hard-coded demo results.</p>
        <div className={styles.ruleTable}>{rules.map(([id, title, description]) => <article key={id}><code>{id}</code><div><h3>{title}</h3><p>{description}</p></div><span>ACTIVE</span></article>)}</div>
      </DocSection>

      <DocSection id="program-model" eyebrow="RELATIONSHIPS" title="Program model and graph">
        <p>Robox parses Rust syntax with <code>syn</code> and combines source discoveries with Cargo and Anchor manifests. The resulting relationship graph helps reviewers move from program entry points to instructions, accounts, PDA constraints, and external calls.</p>
        <div className={styles.pipeline}><div><span>01</span><b>Discover</b><small>Manifests + Rust files</small></div><i>→</i><div><span>02</span><b>Parse</b><small>Syntax + attributes</small></div><i>→</i><div><span>03</span><b>Profile</b><small>Solana surfaces</small></div><i>→</i><div><span>04</span><b>Analyze</b><small>Rules + evidence</small></div><i>→</i><div><span>05</span><b>Report</b><small>Fix guidance</small></div></div>
        <aside className={styles.note}><b>Current graph level</b><p>This is a source-derived relationship model, not a rustc control-flow graph or whole-program data-flow graph. Those deeper analyses remain explicit extension points.</p></aside>
      </DocSection>

      <DocSection id="findings" eyebrow="REMEDIATION" title="From finding to verified fix">
        <p>A Robox finding is designed to answer four review questions: what was detected, where is the evidence, how could it matter, and what should change?</p>
        <div className={styles.findingAnatomy}><article><b>Rule &amp; classification</b><span>Stable rule ID, category, CWE, severity, CVSS, and confidence.</span></article><article><b>Exact location</b><span>Relative source path, start and end lines, and a nearby source snippet.</span></article><article><b>Security reasoning</b><span>Summary, root cause, and a concrete attack or failure scenario.</span></article><article><b>Repair guidance</b><span>Actionable remediation plus a secure code pattern to adapt and test.</span></article></div>
        <p>After changing the program, rerun the scan and confirm the finding disappears for the intended reason. Then run project tests and have a human reviewer validate authorization, economics, state transitions, and protocol assumptions.</p>
      </DocSection>

      <DocSection id="security-boundary" eyebrow="TRUST" title="What Robox can—and cannot—prove">
        <div className={styles.boundary}><div><h3>Robox helps detect</h3><ul><li>Repeatable security anti-patterns visible in source</li><li>Missing or weak Solana/Anchor account constraints</li><li>Risky CPI, PDA, token, numeric, panic, and unsafe-code surfaces</li><li>Program structure that deserves focused manual review</li></ul></div><div><h3>Robox does not guarantee</h3><ul><li>That every vulnerability or exploit path is found</li><li>Correctness of protocol economics or off-chain components</li><li>Runtime behavior across every transaction composition</li><li>A replacement for tests, simulation, and independent audit</li></ul></div></div>
      </DocSection>

      <DocSection id="reports" eyebrow="OUTPUTS" title="Professional reports">
        <p>Reports are generated from the completed live scan by the Rust reporting engine. Each format carries the project profile, score, findings, code locations, recommendations, metrics, graph summary, engine version, and limitations appropriate to the format.</p>
        <div className={styles.reportGrid}><article><b>PDF</b><span>Human-readable audit document for review and delivery.</span></article><article><b>SARIF</b><span>Static-analysis exchange format for code-scanning systems.</span></article><article><b>JSON</b><span>Complete structured result for automation or custom dashboards.</span></article><article><b>Markdown</b><span>Portable report for repositories, tickets, and review notes.</span></article></div>
        <Code title="Download a PDF report">{`GET /api/v1/scans/{scan_id}/report/pdf`}</Code>
      </DocSection>

      <DocSection id="rest-api" eyebrow="INTEGRATION" title="REST API reference">
        <p>The local API listens on <code>http://127.0.0.1:8080</code> by default. Scan creation accepts local paths for trusted local callers, inline source from the browser, or restricted public GitHub sources.</p>
        <div className={styles.apiTable}><div><b>GET</b><code>/health</code><span>Service and engine health</span></div><div><b>GET</b><code>/api/v1/rules</code><span>Active rule metadata</span></div><div><b>GET</b><code>/api/v1/scans</code><span>Completed scans in this process</span></div><div><b className={styles.post}>POST</b><code>/api/v1/scans</code><span>Run a synchronous scan</span></div><div><b>GET</b><code>/api/v1/scans/{`{id}`}</code><span>Retrieve one completed scan</span></div><div><b>GET</b><code>/api/v1/scans/{`{id}`}/report/{`{format}`}</code><span>PDF, JSON, SARIF, or Markdown</span></div><div><b className={styles.post}>POST</b><code>/api/v1/jobs</code><span>Start an asynchronous scan</span></div><div><b>GET</b><code>/api/v1/jobs/{`{id}`}</code><span>Read progress or result</span></div><div><b>GET</b><code>/api/v1/ws/{`{job-id}`}</code><span>Upgrade to progress WebSocket</span></div></div>
        <Code title="Create an inline scan job">{`curl -X POST http://127.0.0.1:8080/api/v1/jobs \\\n  -H "content-type: application/json" \\\n  -d '{\n    "project": "my-program",\n    "source": {\n      "type": "inline",\n      "files": [{"path":"src/lib.rs","content":"..."}]\n    }\n  }'`}</Code>
      </DocSection>

      <DocSection id="websocket" eyebrow="LIVE PROGRESS" title="WebSocket scan events">
        <p>Connect after creating a job to receive the latest job snapshot as the scanner moves through queued, scanning, completed, or failed states. Each snapshot includes a stage label and numeric progress; completed jobs include the scan result.</p>
        <Code title="Browser client">{`const socket = new WebSocket(\n  "ws://127.0.0.1:8080/api/v1/ws/" + jobId\n);\n\nsocket.onmessage = (event) => {\n  const job = JSON.parse(event.data);\n  console.log(job.status, job.stage, job.progress);\n};`}</Code>
      </DocSection>

      <DocSection id="cli" eyebrow="AUTOMATION" title="Rust CLI">
        <p>The CLI uses the same analysis and reporting crates as the API. Run it at the repository root and point it at an Anchor workspace, native Solana program, or Rust crate.</p>
        <Code title="Audit and export">{`# Human-readable terminal result\ncargo run -p robox-cli -- scan ./path/to/program\n\n# Machine-readable and review formats\ncargo run -p robox-cli -- scan ./path/to/program --format json --output robox.json\ncargo run -p robox-cli -- scan ./path/to/program --format sarif --output robox.sarif\ncargo run -p robox-cli -- scan ./path/to/program --format markdown --output robox.md\ncargo run -p robox-cli -- scan ./path/to/program --format pdf --output robox.pdf`}</Code>
      </DocSection>

      <DocSection id="ci-cd" eyebrow="CONTINUOUS SECURITY" title="CI / CD integration">
        <p>Run Robox on pull requests and upload SARIF to your code-scanning platform. Pin the toolchain and Robox revision in production workflows, and choose a severity threshold that matches your release policy.</p>
        <Code title="GitHub Actions">{`- name: Build Robox\n  run: cargo build --release -p robox-cli\n\n- name: Audit Solana program\n  run: cargo run --release -p robox-cli -- scan . --format sarif --output robox.sarif\n\n- name: Upload SARIF\n  uses: github/codeql-action/upload-sarif@v3\n  with:\n    sarif_file: robox.sarif`}</Code>
      </DocSection>

      <DocSection id="architecture" eyebrow="SYSTEM DESIGN" title="How Robox is built">
        <p>Security-critical services are Rust crates with narrow responsibilities. The Next.js workspace is a client of the local API—it does not invent findings or perform a second, divergent scan.</p>
        <div className={styles.architecture}><article><code>robox-core</code><h3>Analysis engine</h3><p>Discovery, parsing, project profile, metrics, graph, rule registry, findings, and scan model.</p></article><article><code>robox-report</code><h3>Reporting engine</h3><p>Consistent JSON, SARIF, Markdown, and PDF generation from a completed scan.</p></article><article><code>robox-api</code><h3>Orchestration</h3><p>Axum REST routes, queued jobs, progress snapshots, WebSocket delivery, and source controls.</p></article><article><code>robox-cli</code><h3>Developer workflow</h3><p>Local project scanning and report export from scripts, terminals, and CI runners.</p></article><article><code>apps/web</code><h3>Review workspace</h3><p>Next.js interface for import, progress, findings, program relationships, and reports.</p></article></div>
      </DocSection>

      <DocSection id="custom-rules" eyebrow="EXTEND" title="Write a custom rule">
        <p>Rules implement a small Rust interface, declare stable metadata, inspect the shared analysis context, and return zero or more findings. Keep detection deterministic and attach evidence at the narrowest useful source location.</p>
        <Code title="Rule skeleton">{`pub struct MyRule;\n\nimpl Rule for MyRule {\n    fn metadata(&self) -> RuleMetadata {\n        RuleMetadata {\n            id: "RBX100".into(),\n            title: "Protocol-specific invariant".into(),\n            // severity, confidence, CWE, category ...\n        }\n    }\n\n    fn analyze(&self, context: &AnalysisContext) -> Vec<Finding> {\n        // Inspect parsed source and return evidence-backed findings.\n        Vec::new()\n    }\n}`}</Code>
        <ol className={styles.checklist}><li>Choose a permanent rule ID and a precise title.</li><li>Document the threat model, false-positive boundaries, and secure alternative.</li><li>Add vulnerable and safe fixtures, then test both outcomes.</li><li>Register the rule so the CLI, API, web catalog, and reports see it.</li></ol>
      </DocSection>

      <DocSection id="roadmap" eyebrow="FOUNDATION" title="Extension points, not inflated claims">
        <p>The current architecture leaves space for deeper analyzers without coupling them to transport or presentation:</p>
        <div className={styles.roadmap}><article><span>PLANNED SEAM</span><h3>Compiler-backed CFG / DFG</h3><p>Add rustc or rust-analyzer backed control and data-flow facts behind the shared analysis context.</p></article><article><span>PLANNED SEAM</span><h3>Symbolic reasoning</h3><p>Model selected instruction paths, arithmetic constraints, account states, and transaction composition.</p></article><article><span>PLANNED SEAM</span><h3>AI-assisted review</h3><p>Use opt-in semantic reasoning to prioritize or explain evidence—never to silently fabricate source facts.</p></article></div>
      </DocSection>

      <DocSection id="troubleshooting" eyebrow="SUPPORT" title="Troubleshooting">
        <div className={styles.faq}><details open><summary>The web workspace says it cannot start a scan.</summary><p>Confirm the Rust API is running at <code>127.0.0.1:8080</code>. If you changed the address, set <code>NEXT_PUBLIC_ROBOX_API</code> before starting the web workspace.</p></details><details><summary>A local folder shows no files.</summary><p>Select the project root that contains <code>.rs</code> or <code>.toml</code> files. Browser folder access may require choosing the folder again after a refresh.</p></details><details><summary>A GitHub import is rejected.</summary><p>Use a public HTTPS GitHub repository URL without credentials. Confirm the repository exists and the optional branch name is correct.</p></details><details><summary>A finding looks incorrect.</summary><p>Check its confidence, exact snippet, and root-cause explanation. Automated rules can produce false positives; record a reviewed exception only after verifying the relevant authorization and state invariants.</p></details><details><summary>Does a clean scan mean the program is safe?</summary><p>No. It means the active rules did not produce findings from the available source evidence. Continue with tests, simulation, manual threat modeling, dependency review, and an independent audit before high-value deployment.</p></details></div>
      </DocSection>

      <footer className={styles.footer}><div><Image src="/robox-logo-transparent.png" width={392} height={352} alt="" /><b>ROBOX</b></div><p>Rust-native security intelligence for programs built on Solana.</p><Link href="/">Return to auditor <span>↗</span></Link></footer>
    </main>

    <aside className={styles.onPage} aria-label="On this page"><strong>ON THIS PAGE</strong><a href="#introduction">What is Robox?</a><a href="#quick-start">First audit</a><a href="#coverage">Detection coverage</a><a href="#rest-api">REST API</a><a href="#architecture">Architecture</a><a href="#security-boundary">Security boundary</a><span>Was this useful?</span><div><button aria-label="Yes, this was useful">Yes</button><button aria-label="No, this was not useful">No</button></div></aside>
  </div>;
}
