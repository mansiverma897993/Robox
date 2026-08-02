"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";

type Severity = "critical" | "high" | "medium" | "low" | "informational";
type ProjectKind = "anchor" | "solana_program" | "rust_crate";
type Finding = {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  cvss: number;
  cwe: string;
  category: string;
  location: { file: string; line_start: number; line_end: number; snippet: string };
  summary: string;
  root_cause: string;
  attack_scenario: string;
  remediation: string;
  secure_example: string;
};
type ScanResult = {
  id: string;
  project: string;
  project_kind: ProjectKind;
  profile: {
    kind: ProjectKind;
    frameworks: string[];
    program_ids: string[];
    manifests: string[];
    has_anchor_workspace: boolean;
    has_solana_dependency: boolean;
  };
  engine_version: string;
  completed_at: string;
  security_score: number;
  findings: Finding[];
  metrics: {
    rust_files: number;
    parsed_files: number;
    lines_of_code: number;
    functions: number;
    instructions: number;
    programs: number;
    account_structs: number;
    signer_accounts: number;
    unchecked_accounts: number;
    token_accounts: number;
    sysvar_reads: number;
    pda_constraints: number;
    cpi_calls: number;
    dependencies: number;
  };
  graph: {
    nodes: { id: string; label: string; kind: string }[];
    edges: { source: string; target: string; relation: string }[];
    level: string;
  };
  limitations: string[];
};
type RuleMetadata = { id: string; title: string; severity: Severity; confidence: number; cvss: number; cwe: string; category: string };
type ScanJob = { id: string; status: "queued" | "scanning" | "completed" | "failed"; stage: string; progress: number; scan?: ScanResult; error?: string };

const API = process.env.NEXT_PUBLIC_ROBOX_API ?? "http://127.0.0.1:8080";
const tabs = ["Overview", "Findings", "Program graph", "Reports"] as const;
type WorkspaceTab = (typeof tabs)[number];
type View = WorkspaceTab | "CI / CD" | "Custom rules";
const directoryInputProps = { webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement>;

export default function Home() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [view, setView] = useState<View>("Overview");
  const [selectedFinding, setSelectedFinding] = useState(0);
  const [sourceMode, setSourceMode] = useState<"files" | "github">("files");
  const [files, setFiles] = useState<File[]>([]);
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState("Import a project to begin a live audit");
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [rules, setRules] = useState<RuleMetadata[]>([]);
  const folderInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetch(`${API}/api/v1/rules`).then((response) => response.ok ? response.json() : []).then(setRules).catch(() => undefined);
  }, []);

  const counts = useMemo(() => {
    const findings = scan?.findings ?? [];
    return {
      critical: findings.filter((item) => item.severity === "critical").length,
      high: findings.filter((item) => item.severity === "high").length,
      medium: findings.filter((item) => item.severity === "medium").length,
      low: findings.filter((item) => item.severity === "low").length,
    };
  }, [scan]);
  const finding = scan?.findings[selectedFinding] ?? scan?.findings[0];

  function acceptFiles(input: FileList | null) {
    const selected = Array.from(input ?? []).filter((file) => file.name.endsWith(".rs") || file.name.endsWith(".toml"));
    setFiles(selected);
    setNotice(selected.length ? `${selected.length} Rust and manifest files ready` : "No .rs or .toml files found in that folder");
  }

  async function runInputScan() {
    setIsScanning(true); setProgress(5); setNotice("Preparing project input");
    try {
      let source: object;
      let project = "uploaded-solana-project";
      if (sourceMode === "files") {
        if (!files.length) throw new Error("Choose a project folder containing Rust or TOML files");
        const total = files.reduce((sum, file) => sum + file.size, 0);
        if (total > 12 * 1024 * 1024) throw new Error("Project upload is larger than 12 MB");
        source = { type: "inline", files: await Promise.all(files.map(async (file) => ({ path: file.webkitRelativePath || file.name, content: await file.text() }))) };
        project = files[0].webkitRelativePath.split("/")[0] || "uploaded-project";
      } else {
        if (!/^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(repo)) throw new Error("Enter a public GitHub owner/repository URL");
        source = { type: "github", url: repo.replace(/\/$/, ""), branch: branch.trim() || null };
        project = repo.replace(/\/$/, "").split("/").pop()?.replace(".git", "") || "github-project";
      }

      const response = await fetch(`${API}/api/v1/jobs`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project, source }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to start scan");
      const completed = await waitForJob(payload.id, (job) => { setProgress(job.progress); setNotice(job.stage); });
      if (!completed.scan) throw new Error(completed.error || "Scan finished without a result");
      setScan(completed.scan); setSelectedFinding(0); setReviewed(new Set()); setView("Overview"); setNotice(`${projectKindLabel(completed.scan.project_kind)} audit complete · ${completed.scan.findings.length} findings ready`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Scan failed");
    } finally { setIsScanning(false); }
  }

  async function waitForJob(id: string, onProgress: (job: ScanJob) => void) {
    for (let attempt = 0; attempt < 1200; attempt += 1) {
      const response = await fetch(`${API}/api/v1/jobs/${id}`, { cache: "no-store" });
      const job: ScanJob = await response.json();
      if (!response.ok) throw new Error(job.error || "Unable to read scan progress");
      onProgress(job);
      if (job.status === "completed") return job;
      if (job.status === "failed") throw new Error(job.error || "Scan failed");
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
    throw new Error("Scan timed out");
  }

  async function downloadReport(format: "pdf" | "json" | "sarif" | "markdown") {
    if (!scan) return;
    const apiFormat = format === "markdown" ? "md" : format;
    const extension = format === "markdown" ? "md" : format;
    try {
      const response = await fetch(`${API}/api/v1/scans/${scan.id}/report/${apiFormat}`);
      if (!response.ok) throw new Error();
      downloadBlob(await response.blob(), `robox-${scan.project}.${extension}`);
      setNotice(`${format.toUpperCase()} report generated by the Rust backend`);
    } catch {
      downloadBlob(new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" }), `robox-${scan.project}.json`);
      setNotice("Backend report unavailable · downloaded the current scan as JSON");
    }
  }

  function toggleReviewed(id: string) {
    setReviewed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const workspaceView = tabs.includes(view as WorkspaceTab);
  return <main className="app-shell" data-view={view}>
    <aside className="sidebar">
      <button className="brand" onClick={() => setView("Overview")} aria-label="Robox home"><Image className="brand-mark" src="/robox-logo-transparent.png" width={392} height={352} alt="" priority /><span>ROBOX</span></button>
      <nav className="side-nav" aria-label="Workspace navigation">
        <span className="nav-label">Workspace</span>
        <NavButton active={view === "Overview"} label="Overview" icon="⌂" onClick={() => setView("Overview")} />
        <NavButton active={view === "Findings"} label="Findings" icon="◇" count={scan?.findings.length ?? 0} disabled={!scan} onClick={() => setView("Findings")} />
        <NavButton active={view === "Program graph"} label="Program graph" icon="⌘" disabled={!scan} onClick={() => setView("Program graph")} />
        <NavButton active={view === "Reports"} label="Reports" icon="▤" disabled={!scan} onClick={() => setView("Reports")} />
        <span className="nav-label second">Automation</span>
        <NavButton active={view === "CI / CD"} label="CI / CD" icon="↗" onClick={() => setView("CI / CD")} />
        <NavButton active={view === "Custom rules"} label="Custom rules" icon="◫" onClick={() => setView("Custom rules")} />
      </nav>
      <div className="engine-card"><div className="engine-head"><span className="pulse-dot" /> Engine online</div><p>Rust core · v{scan?.engine_version ?? "0.1.0"}</p><div className="mini-meter"><i /></div><small>{rules.length || 11} rules loaded</small></div>
      <div className="profile"><span>MV</span><span><strong>Security workspace</strong><small>Local environment</small></span><b>•••</b></div>
    </aside>
    <section className="workspace">
      <header className="topbar"><div><span className="eyebrow">PROJECT</span><h1>{scan?.project ?? "No project imported"}<span>/</span><em>{scan ? projectKindLabel(scan.project_kind) : "Awaiting live audit"}</em></h1></div><div className="top-actions"><Link className="docs-link" href="/docs">Docs</Link>{scan ? <><span className="network"><i /> {scan.profile.frameworks[0] || "Rust"}</span><button className="ghost-button" onClick={() => setView("Reports")}>Export report</button><button className="primary-button compact" onClick={() => { setScan(null); setFiles([]); setView("Overview"); setNotice("Import a project to begin a live audit"); }}>New audit</button></> : <span className="awaiting-pill"><i /> No scan data</span>}</div></header>
      <div className="content">
        {workspaceView && <>
          <section className="scan-hero">
            <div className="hero-copy"><span className="section-kicker"><i /> SOLANA SECURITY INTELLIGENCE</span><h2>Audit Solana.<br />Built in <em>Rust.</em></h2><p>Import an Anchor or native Solana program. Robox maps instructions, accounts, PDAs, CPIs, token surfaces, and explainable security risks.</p><div className="trust-row"><span><b>AST</b> parsed</span><i /><span><b>Anchor</b> aware</span><i /><span><b>SARIF</b> ready</span></div></div>
            <div className="core-scene" aria-hidden="true"><div className="halo h1" /><div className="halo h2" /><div className="halo h3" /><div className="orb"><span>R</span><i /></div><div className="orbit o1"><i /></div><div className="orbit o2"><i /></div><span className="scene-label l1">AST</span><span className="scene-label l2">PDA</span><span className="scene-label l3">CPI</span></div>
            <div className="import-card"><div className="mode-switch"><button className={sourceMode === "files" ? "active" : ""} onClick={() => setSourceMode("files")}>Project folder</button><button className={sourceMode === "github" ? "active" : ""} onClick={() => setSourceMode("github")}>GitHub</button></div>
              {sourceMode === "files" ? <label className="drop-zone"><input {...directoryInputProps} ref={folderInput} type="file" multiple onChange={(event) => acceptFiles(event.target.files)} /><span className="upload-icon">+</span><strong>{files.length ? `${files.length} project files selected` : "Choose an Anchor or Rust project"}</strong><small>{files.length ? files.slice(0, 3).map((file) => file.name).join(" · ") : "Folder import reads .rs, Cargo.toml, and Anchor.toml"}</small></label> : <div className="repo-fields"><div className="repo-input"><label htmlFor="repo">Repository URL</label><div><span>⌘</span><input id="repo" value={repo} onChange={(event) => setRepo(event.target.value)} /><button aria-label="Repository source">↗</button></div></div><label className="branch-input">Branch (optional)<input value={branch} placeholder="main" onChange={(event) => setBranch(event.target.value)} /></label></div>}
              <button className="primary-button scan-button" onClick={runInputScan} disabled={isScanning}><span>{isScanning ? "◌" : "◆"}</span>{isScanning ? `${progress}% · ${notice}` : "Start security audit"}</button>
              <div className="scan-notice"><i className={isScanning ? "loading" : ""} /><span>{notice}</span></div>{isScanning && <div className="job-progress"><i style={{ width: `${progress}%` }} /></div>}
            </div>
          </section>
          {scan ? <><div className="tabs" role="tablist">{tabs.map((tab) => <button key={tab} role="tab" aria-selected={view === tab} className={view === tab ? "active" : ""} onClick={() => setView(tab)}>{tab}{tab === "Findings" && <span>{scan.findings.length}</span>}</button>)}</div>
            {view === "Overview" && <Overview scan={scan} counts={counts} onFinding={() => setView("Findings")} onGraph={() => setView("Program graph")} />}
            {view === "Findings" && <Findings scan={scan} selected={selectedFinding} onSelect={setSelectedFinding} finding={finding} reviewed={reviewed} onReview={toggleReviewed} />}
            {view === "Program graph" && <ProgramGraph scan={scan} />}
            {view === "Reports" && <Reports scan={scan} download={downloadReport} />}</> : <EmptyAuditState ruleCount={rules.length || 11} />}
        </>}
        {view === "CI / CD" && <ContinuousSecurity />}
        {view === "Custom rules" && <CustomRuleWorkspace rules={rules} />}
      </div>
    </section>
  </main>;
}

function NavButton({ active, label, icon, count, disabled, onClick }: { active: boolean; label: string; icon: string; count?: number; disabled?: boolean; onClick: () => void }) {
  return <button className={active ? "active" : ""} disabled={disabled} onClick={onClick}><span>{icon}</span>{label}{count !== undefined && <b>{count}</b>}</button>;
}

function EmptyAuditState({ ruleCount }: { ruleCount: number }) {
  return <section className="empty-audit panel"><div><span className="section-kicker"><i /> LIVE DATA ONLY</span><h2>No security result yet</h2><p>Robox will not show example findings or a fabricated score. Import a real Anchor, native Solana, or Rust project above to produce evidence from its source code.</p></div><div className="audit-steps"><article><b>01</b><strong>Import source</strong><span>Project folder or public GitHub repository</span></article><article><b>02</b><strong>Analyze program</strong><span>{ruleCount} rules inspect Rust, accounts, PDAs, CPIs, tokens, and manifests</span></article><article><b>03</b><strong>Fix verified findings</strong><span>Review exact locations, attack paths, secure examples, and downloadable reports</span></article></div><p className="coverage-disclosure"><strong>Security boundary:</strong> automated analysis can reduce risk but cannot prove that every business-logic or runtime vulnerability has been found. Robox exposes its scope and limitations in every report.</p></section>;
}

function Overview({ scan, counts, onFinding, onGraph }: { scan: ScanResult; counts: Record<string, number>; onFinding: () => void; onGraph: () => void }) {
  return <div className="dashboard-grid">
    <section className="panel score-panel"><div className="panel-heading"><div><span className="eyebrow">SECURITY POSTURE</span><h3>Project risk score</h3></div><span className="live-pill"><i /> Complete</span></div><div className="score-content"><div className="score-ring" style={{ "--score": `${scan.security_score * 3.6}deg` } as React.CSSProperties}><div><strong>{scan.security_score}</strong><span>/100</span><small>{scan.security_score >= 80 ? "Healthy" : scan.security_score >= 50 ? "At risk" : "Critical risk"}</small></div></div><div className="risk-summary"><p>Deployment is <strong>{scan.security_score >= 70 ? "reviewable" : "not recommended"}</strong> until priority findings are resolved.</p><div className="severity-row"><span className="critical"><i />{counts.critical}<small>Critical</small></span><span className="high"><i />{counts.high}<small>High</small></span><span className="medium"><i />{counts.medium}<small>Medium</small></span><span className="low"><i />{counts.low}<small>Low</small></span></div><button onClick={onFinding}>Review priority findings <span>→</span></button></div></div></section>
    <section className="panel metrics-panel"><div className="panel-heading"><div><span className="eyebrow">SOLANA COVERAGE</span><h3>Program surface</h3></div><span className="mono-tag">{projectKindLabel(scan.project_kind)}</span></div><div className="metric-grid"><Metric value={scan.metrics.instructions} label="Instructions" trend="mapped" /><Metric value={scan.metrics.account_structs} label="Accounts" trend="validated" /><Metric value={scan.metrics.pda_constraints} label="PDAs" trend="derived" /><Metric value={scan.metrics.cpi_calls} label="CPI calls" trend="traced" /></div><div className="profile-badges">{scan.profile.frameworks.map((item) => <span key={item}>{item}</span>)}{scan.profile.program_ids.slice(0, 1).map((id) => <code key={id}>{id}</code>)}</div><div className="coverage"><div><span>Parse coverage</span><strong>{Math.round((scan.metrics.parsed_files / Math.max(scan.metrics.rust_files, 1)) * 100)}%</strong></div><div className="coverage-bar"><i /></div><small>{scan.metrics.lines_of_code} source lines across {scan.metrics.rust_files} Rust files</small></div></section>
    <section className="panel priority-panel"><div className="panel-heading"><div><span className="eyebrow">PRIORITY QUEUE</span><h3>Findings that need attention</h3></div><button onClick={onFinding}>View all →</button></div><div className="finding-preview">{scan.findings.slice(0, 3).map((item, index) => <button key={item.id} onClick={onFinding}><span className={`severity-icon ${item.severity}`}>{index + 1}</span><span><strong>{item.title}</strong><small>{item.location.file}:{item.location.line_start}</small></span><em className={item.severity}>{item.severity}</em><b>{Math.round(item.confidence * 100)}%</b></button>)}{!scan.findings.length && <div className="empty-state">No rule-based findings detected.</div>}</div></section>
    <section className="panel graph-preview"><div className="panel-heading"><div><span className="eyebrow">PROGRAM MODEL</span><h3>Live project relationships</h3></div><button onClick={onGraph}>Expand ↗</button></div><DynamicGraph scan={scan} compact /></section>
  </div>;
}

function Metric({ value, label, trend }: { value: number; label: string; trend: string }) { return <div className="metric"><span>{label}</span><strong>{value.toString().padStart(2, "0")}</strong><small><i /> {trend}</small></div>; }

function Findings({ scan, selected, onSelect, finding, reviewed, onReview }: { scan: ScanResult; selected: number; onSelect: (index: number) => void; finding?: Finding; reviewed: Set<string>; onReview: (id: string) => void }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const visible = filter === "all" ? scan.findings : scan.findings.filter((item) => item.severity === filter);
  return <div className="findings-layout"><section className="panel findings-list"><div className="panel-heading"><div><span className="eyebrow">{visible.length} VISIBLE FINDINGS</span><h3>Review queue</h3></div><select className="filter-button" value={filter} onChange={(event) => setFilter(event.target.value as Severity | "all")}><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>{visible.map((item) => { const index = scan.findings.findIndex((entry) => entry.id === item.id); return <button key={item.id} className={selected === index ? "selected" : ""} onClick={() => onSelect(index)}><span className={`severity-icon ${item.severity}`}>{reviewed.has(item.id) ? "✓" : item.severity.slice(0, 1).toUpperCase()}</span><span><strong>{item.title}</strong><small>{item.rule_id} · {item.location.file}:{item.location.line_start}</small></span><em className={item.severity}>{item.severity}</em><b>→</b></button>; })}{!visible.length && <div className="empty-state">Nothing matches this filter.</div>}</section>{finding && <section className="panel finding-detail"><div className="detail-head"><div><span className={`severity-pill ${finding.severity}`}>{finding.severity}</span><span className="mono-tag">{finding.rule_id}</span></div><span>{Math.round(finding.confidence * 100)}% confidence · CVSS {finding.cvss}</span></div><h2>{finding.title}</h2><p>{finding.summary}</p><div className="code-location"><div><span>{finding.location.file}</span><b>Ln {finding.location.line_start}</b></div><pre><code><i>{finding.location.line_start}</i>{finding.location.snippet}</code></pre></div><div className="explanation-grid"><article><span className="eyebrow">ROOT CAUSE</span><p>{finding.root_cause}</p></article><article><span className="eyebrow">ATTACK PATH</span><p>{finding.attack_scenario}</p></article></div><div className="remediation"><span className="eyebrow">RECOMMENDED REMEDIATION</span><p>{finding.remediation}</p><pre><code>{finding.secure_example}</code></pre></div><div className="detail-footer"><span>{finding.cwe}</span><span>{finding.category}</span><button className={reviewed.has(finding.id) ? "reviewed" : ""} onClick={() => onReview(finding.id)}>{reviewed.has(finding.id) ? "Reviewed ✓" : "Mark reviewed"}</button></div></section>}</div>;
}

function DynamicGraph({ scan, compact = false }: { scan: ScanResult; compact?: boolean }) {
  const nodes = scan.graph.nodes.slice(0, compact ? 6 : 12);
  const positions = compact ? [[5, 44], [31, 15], [34, 67], [66, 17], [68, 68], [46, 42]] : [[4, 45], [24, 13], [25, 69], [47, 10], [48, 72], [70, 16], [72, 68], [43, 40], [83, 40], [12, 15], [12, 76], [61, 43]];
  return <div className={compact ? "mini-graph dynamic-graph" : "dynamic-graph graph-canvas"}>{nodes.map((node, index) => <span key={node.id} className={`graph-node ${graphClass(node.kind)}`} style={{ left: `${positions[index][0]}%`, top: `${positions[index][1]}%` }} title={node.kind}>{node.label}</span>)}{!compact && <div className="edge-ledger">{scan.graph.edges.slice(0, 8).map((edge, index) => <span key={`${edge.source}-${edge.target}-${index}`}><b>{labelFor(scan, edge.source)}</b><i>{edge.relation}</i><b>{labelFor(scan, edge.target)}</b></span>)}</div>}</div>;
}

function ProgramGraph({ scan }: { scan: ScanResult }) { return <section className="panel graph-panel"><div className="panel-heading"><div><span className="eyebrow">{scan.graph.level.toUpperCase()}</span><h3>Instruction, account, PDA, CPI, and token map</h3></div><div className="graph-legend"><span><i />Instruction</span><span><i className="account" />Account</span><span><i className="risk" />CPI / token</span></div></div><div className="large-graph"><div className="grid-floor" /><DynamicGraph scan={scan} /><div className="graph-note"><span>Honest model boundary</span><p>These relationships come from Rust syntax and Solana/Anchor patterns. CFG, DFG, symbolic execution, and runtime simulation are extension layers.</p></div></div><div className="graph-stats"><span><strong>{scan.graph.nodes.length}</strong> Nodes</span><span><strong>{scan.graph.edges.length}</strong> Relationships</span><span><strong>{scan.metrics.pda_constraints}</strong> PDAs</span><span><strong>{scan.metrics.cpi_calls}</strong> CPIs</span><span><strong>{scan.metrics.token_accounts}</strong> Token accounts</span></div></section>; }

function Reports({ scan, download }: { scan: ScanResult; download: (format: "pdf" | "json" | "sarif" | "markdown") => void }) { return <div className="reports-grid"><section className="panel report-summary"><span className="eyebrow">BACKEND-GENERATED ARTIFACT</span><h2>{scan.project}</h2><p>{projectKindLabel(scan.project_kind)} audit <code>{scan.id}</code> from Robox {scan.engine_version}. Every artifact below is generated from this completed scan.</p><div className="report-score"><span>Security score</span><strong>{scan.security_score}<small>/100</small></strong></div><div className="report-meta"><span><b>{scan.findings.length}</b> findings</span><span><b>{scan.metrics.instructions}</b> instructions</span><span><b>{scan.metrics.lines_of_code}</b> LOC</span></div></section><section className="report-options"><ReportCard title="Detailed PDF" description="A polished multi-page audit with scope, severity analysis, exact evidence, remediation guidance, and limitations." tag="AUDIT REPORT" onClick={() => download("pdf")} /><ReportCard title="SARIF 2.1.0" description="GitHub Code Scanning compatible output with fingerprints and source regions." tag="CI READY" onClick={() => download("sarif")} /><ReportCard title="JSON" description="Complete machine-readable result for integrations and archival." tag="API" onClick={() => download("json")} /><ReportCard title="Markdown" description="Human-readable technical report for reviewers and stakeholders." tag="REPORT" onClick={() => download("markdown")} /></section><section className="panel limitations"><span className="eyebrow">HONEST ANALYSIS BOUNDARY</span><h3>What this scan means</h3>{scan.limitations.map((item) => <p key={item}><i>✓</i>{item}</p>)}</section></div>; }

function ReportCard({ title, description, tag, onClick }: { title: string; description: string; tag: string; onClick: () => void }) { return <button className="panel report-card" onClick={onClick}><span className="document-icon"><i /><i /><i /></span><span><small>{tag}</small><strong>{title}</strong><p>{description}</p></span><b>↓</b></button>; }

const workflow = `name: Robox security audit\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - name: Install Robox\n        run: cargo install --git https://github.com/mansiverma897993/Robox robox-cli\n      - name: Audit Solana program\n        run: robox scan . --format sarif --output robox.sarif --fail-on-score-below 70\n      - uses: github/codeql-action/upload-sarif@v3\n        if: always()\n        with:\n          sarif_file: robox.sarif`;

function ContinuousSecurity() {
  const [copied, setCopied] = useState(false);
  async function copy() { await navigator.clipboard.writeText(workflow); setCopied(true); setTimeout(() => setCopied(false), 1500); }
  return <section className="product-view"><div className="view-hero"><span className="section-kicker"><i /> AUTOMATED ASSURANCE</span><h2>Continuous security</h2><p>Run the same Rust analysis engine on every pull request and publish findings directly into GitHub Code Scanning.</p></div><div className="ci-grid"><article className="panel setup-card"><span className="eyebrow">GITHUB ACTIONS</span><h3>Protect every Solana change</h3><ol><li>Commit the workflow below.</li><li>Set the minimum acceptable security score.</li><li>Review SARIF findings inline on pull requests.</li></ol><div className="action-row"><button className="primary-button compact" onClick={copy}>{copied ? "Copied ✓" : "Copy workflow"}</button><button className="ghost-button" onClick={() => downloadBlob(new Blob([workflow], { type: "text/yaml" }), "robox-security.yml")}>Download YAML</button></div></article><article className="panel workflow-card"><div><span>.github/workflows/robox-security.yml</span><button onClick={copy}>{copied ? "Copied" : "Copy"}</button></div><pre>{workflow}</pre></article></div><div className="integration-strip"><span><b>01</b> Checkout</span><i>→</i><span><b>02</b> Rust scanner</span><i>→</i><span><b>03</b> SARIF</span><i>→</i><span><b>04</b> Merge gate</span></div></section>;
}

function CustomRuleWorkspace({ rules }: { rules: RuleMetadata[] }) {
  const [query, setQuery] = useState("");
  const catalog = rules.filter((rule) => `${rule.id} ${rule.title} ${rule.category}`.toLowerCase().includes(query.toLowerCase()));
  const template = `use robox_core::{Finding, Rule, RuleContext, RuleMetadata, Severity};\n\npub struct MySolanaRule;\n\nimpl Rule for MySolanaRule {\n    fn metadata(&self) -> RuleMetadata {\n        RuleMetadata {\n            id: "CUSTOM001", title: "Describe the invariant",\n            severity: Severity::High, confidence: 0.80, cvss: 8.0,\n            cwe: "CWE-284", category: "Business logic",\n        }\n    }\n\n    fn analyze(&self, context: &RuleContext<'_>) -> Vec<Finding> {\n        // Inspect context.source and context.syntax, then return findings.\n        Vec::new()\n    }\n}`;
  return <section className="product-view"><div className="view-hero"><span className="section-kicker"><i /> EXTENSIBLE RUST ENGINE</span><h2>Custom rule workspace</h2><p>Explore the active Solana and Rust checks, then start a typed plugin rule for protocol-specific invariants.</p></div><div className="rules-toolbar"><input aria-label="Search rules" placeholder="Search by rule, category, or title" value={query} onChange={(event) => setQuery(event.target.value)} /><button className="primary-button compact" onClick={() => downloadBlob(new Blob([template], { type: "text/rust" }), "custom_rule.rs")}>Download Rust template</button></div><div className="rules-layout"><div className="rule-catalog">{catalog.map((rule) => <article className="panel rule-card" key={rule.id}><div><code>{rule.id}</code><span className={`severity-pill ${rule.severity}`}>{rule.severity}</span></div><h3>{rule.title}</h3><p>{rule.category} · {rule.cwe}</p><footer><span>{Math.round(rule.confidence * 100)}% confidence</span><span>CVSS {rule.cvss.toFixed(1)}</span></footer></article>)}{!catalog.length && <div className="panel empty-state">The API rule catalog is unavailable or no rules match.</div>}</div><article className="panel extension-card"><span className="eyebrow">PLUGIN CONTRACT</span><h3>Deep enough to grow</h3><p>Rules receive the source text and parsed Rust syntax. The registry owns execution and finding normalization, keeping API, CLI, reports, and CI behavior consistent.</p><pre>{template}</pre></article></div></section>;
}

function downloadBlob(blob: Blob, filename: string) { const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 0); }
function projectKindLabel(kind: ProjectKind) { return kind === "anchor" ? "Anchor program" : kind === "solana_program" ? "Native Solana program" : "Rust crate"; }
function graphClass(kind: string) { if (kind.includes("program") || kind === "file") return "program"; if (kind.includes("account")) return "account"; if (kind.includes("pda")) return "pda"; if (kind.includes("cpi") || kind.includes("token")) return "cpi"; return "instruction"; }
function labelFor(scan: ScanResult, id: string) { return scan.graph.nodes.find((node) => node.id === id)?.label || id; }
