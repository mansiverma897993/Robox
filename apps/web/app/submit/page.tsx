"use client";

import Image from "next/image";
import Link from "next/link";
import { FormEvent, KeyboardEvent, useState } from "react";
import styles from "./submit.module.css";

const API = process.env.NEXT_PUBLIC_ROBOX_API ?? "http://127.0.0.1:8080";
const stepCount = 8;

type Intake = {
  projectName: string;
  websiteUrl: string;
  repositoryUrl: string;
  chains: string[];
  priorReview: "" | "yes" | "no" | "not_sure";
  scope: string;
  email: string;
  telegram: string;
  consent: boolean;
  companyFax: string;
};

type Receipt = { id: string; received_at: string };

const emptyIntake: Intake = {
  projectName: "", websiteUrl: "", repositoryUrl: "", chains: [], priorReview: "",
  scope: "", email: "", telegram: "", consent: false, companyFax: "",
};

const chainOptions = [
  ["solana", "Solana", "Mainnet, devnet, or testnet"],
  ["eclipse_svm", "Eclipse / SVM", "A Solana Virtual Machine deployment"],
  ["other_svm", "Other SVM", "Tell us the environment in your scope"],
  ["not_sure", "Not sure", "We will help classify the project"],
] as const;

function webUrl(value: string, optional = false) {
  if (!value.trim()) return optional;
  try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
}

export default function SubmitProjectPage() {
  const [step, setStep] = useState(0);
  const [intake, setIntake] = useState<Intake>(emptyIntake);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  function update<K extends keyof Intake>(key: K, value: Intake[K]) {
    setIntake((current) => ({ ...current, [key]: value }));
    setError("");
  }

  function toggleChain(value: string) {
    update("chains", intake.chains.includes(value)
      ? intake.chains.filter((chain) => chain !== value)
      : [...intake.chains, value]);
  }

  function validate(index = step) {
    if (index === 0 && intake.projectName.trim().length < 2) return "Enter the project or protocol name.";
    if (index === 1 && !webUrl(intake.websiteUrl, true)) return "Enter a complete website URL, or skip this step.";
    if (index === 2 && !webUrl(intake.repositoryUrl)) return "Enter a complete repository URL beginning with http:// or https://.";
    if (index === 3 && !intake.chains.length) return "Choose at least one deployment environment.";
    if (index === 4 && !intake.priorReview) return "Choose the previous review status.";
    if (index === 5 && intake.scope.trim().length < 20) return "Describe the audit scope in at least 20 characters.";
    if (index === 6 && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(intake.email.trim())) return "Enter a valid contact email.";
    if (index === 7 && !intake.consent) return "Confirm that Robox may contact you about this request.";
    return "";
  }

  function next() {
    const message = validate();
    if (message) return setError(message);
    setStep((current) => Math.min(stepCount - 1, current + 1));
    setError("");
  }

  function previous() {
    setStep((current) => Math.max(0, current - 1));
    setError("");
  }

  function keyDown(event: KeyboardEvent<HTMLFormElement>) {
    if (event.key !== "Enter" || event.shiftKey || (event.target as HTMLElement).tagName === "TEXTAREA") return;
    event.preventDefault();
    if (step < stepCount - 1) next();
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const message = validate(stepCount - 1);
    if (message) return setError(message);
    setSubmitting(true);
    try {
      const response = await fetch(`${API}/api/v1/audit-requests`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          project_name: intake.projectName, website_url: intake.websiteUrl || null,
          repository_url: intake.repositoryUrl, chains: intake.chains,
          prior_review: intake.priorReview, scope: intake.scope, email: intake.email,
          telegram: intake.telegram || null, contact_consent: intake.consent,
          company_fax: intake.companyFax || null,
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to submit this project right now.");
      setReceipt(payload);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to submit this project right now.");
    } finally { setSubmitting(false); }
  }

  if (receipt) return <main className={styles.shell}><Header /><section className={styles.success}>
    <div className={styles.successMark}><span>✓</span></div><span className={styles.kicker}>REQUEST RECEIVED</span>
    <h1>Your project is in<br />the review queue.</h1>
    <p>Robox saved your submission securely. We’ll review the repository and contact <strong>{intake.email}</strong> about access, scope, timing, and next steps.</p>
    <div className={styles.receipt}><span>Request reference</span><code>{receipt.id}</code><small>{new Date(receipt.received_at).toLocaleString()}</small></div>
    <div className={styles.successActions}><Link href="/">Return to Robox</Link><button onClick={() => { setReceipt(null); setIntake(emptyIntake); setStep(0); }}>Submit another</button></div>
  </section></main>;

  return <main className={styles.shell}><Header />
    <div className={styles.progress}><i style={{ width: `${((step + 1) / stepCount) * 100}%` }} /></div>
    <div className={styles.meta}><span>SECURE AUDIT INTAKE</span><strong>{String(step + 1).padStart(2, "0")} / {String(stepCount).padStart(2, "0")}</strong></div>
    <form className={styles.stage} onSubmit={submit} onKeyDown={keyDown} noValidate>
      <input className={styles.honeypot} tabIndex={-1} autoComplete="off" aria-hidden="true" value={intake.companyFax} onChange={(event) => update("companyFax", event.target.value)} />
      <section className={styles.question} key={step}>
        <div className={styles.number}>{step + 1}<span>→</span></div>
        {step === 0 && <><Title required>What’s your company or protocol’s name?</Title><Help>This becomes the project name in your private request.</Help><TextInput value={intake.projectName} onChange={(value) => update("projectName", value)} placeholder="Type your answer here…" autoComplete="organization" /><Continue onClick={next} /></>}
        {step === 1 && <><Title>What’s your website URL?</Title><Help>Optional. This helps us understand the product around the program.</Help><TextInput value={intake.websiteUrl} onChange={(value) => update("websiteUrl", value)} placeholder="https://" type="url" /><Continue onClick={next} label={intake.websiteUrl ? "OK" : "Skip"} /></>}
        {step === 2 && <><Title required>Where can we review the source?</Title><Help>Paste a GitHub, GitLab, or other repository URL. We’ll arrange private access by email when needed.</Help><TextInput value={intake.repositoryUrl} onChange={(value) => update("repositoryUrl", value)} placeholder="https://github.com/owner/project" type="url" /><Continue onClick={next} /></>}
        {step === 3 && <><Title required>Where are you planning to deploy?</Title><Help>Select one or more environments.</Help><div className={styles.choices}>{chainOptions.map(([value, label, description], index) => <Choice key={value} index={index} label={label} description={description} selected={intake.chains.includes(value)} onClick={() => toggleChain(value)} multi />)}</div><Continue onClick={next} /></>}
        {step === 4 && <><Title required>Has the project had a security review before?</Title><Help>Select the closest answer.</Help><div className={styles.choices}>{[["yes", "Yes", "A professional or internal review was completed"], ["no", "No", "This is the first formal security review"], ["not_sure", "I’m not sure", "We’ll clarify what has already been covered"]].map(([value, label, description], index) => <Choice key={value} index={index} label={label} description={description} selected={intake.priorReview === value} onClick={() => update("priorReview", value as Intake["priorReview"])} />)}</div><Continue onClick={next} /></>}
        {step === 5 && <><Title required>What should the audit cover?</Title><Help>Mention programs in scope, concerns, target dates, or anything the reviewer should know.</Help><textarea autoFocus className={styles.area} value={intake.scope} onChange={(event) => update("scope", event.target.value)} placeholder="Review the treasury and staking programs, especially PDA authorities and token CPIs…" maxLength={4000} /><div className={styles.count}>{intake.scope.length} / 4,000</div><Continue onClick={next} /></>}
        {step === 6 && <><Title required>What’s your best email?</Title><Help>Audit access, scoping questions, and follow-up will be sent here.</Help><TextInput value={intake.email} onChange={(value) => update("email", value)} placeholder="name@company.com" type="email" autoComplete="email" /><Continue onClick={next} /></>}
        {step === 7 && <><Title>How else can we reach you?</Title><Help>Telegram is optional. Confirm permission to submit the request.</Help><label className={styles.telegram}>Telegram handle<TextInput value={intake.telegram} onChange={(value) => update("telegram", value)} placeholder="@username" /></label><label className={styles.consent}><input type="checkbox" checked={intake.consent} onChange={(event) => update("consent", event.target.checked)} /><span>✓</span><strong>I agree that Robox may contact me about this audit request.<small>Your details are stored privately and never used as demo scan data.</small></strong></label><button className={styles.submit} type="submit" disabled={submitting}>{submitting ? "Saving request…" : "Submit project"}<span>{submitting ? "◌" : "↗"}</span></button></>}
        {error && <div className={styles.error} role="alert"><b>!</b>{error}</div>}
      </section>
    </form>
    <footer className={styles.footer}><span><i /> Private project intake</span><div><button onClick={previous} disabled={step === 0} aria-label="Previous question">↑</button><button onClick={next} disabled={step === stepCount - 1} aria-label="Next question">↓</button></div></footer>
  </main>;
}

function Header() { return <header className={styles.header}><Link className={styles.brand} href="/"><Image src="/robox-logo-transparent.png" width={392} height={352} alt="" priority /><strong>ROBOX</strong><span>Audit intake</span></Link><div className={styles.private}><i /> Private submission</div><Link className={styles.close} href="/" aria-label="Close">×</Link></header>; }
function Title({ children, required = false }: { children: React.ReactNode; required?: boolean }) { return <h1>{children}{required && <sup>*</sup>}</h1>; }
function Help({ children }: { children: React.ReactNode }) { return <p className={styles.help}>{children}</p>; }
function TextInput({ value, onChange, placeholder, type = "text", autoComplete = "off" }: { value: string; onChange: (value: string) => void; placeholder: string; type?: string; autoComplete?: string }) { return <input autoFocus className={styles.input} type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} maxLength={500} autoComplete={autoComplete} />; }
function Continue({ onClick, label = "OK" }: { onClick: () => void; label?: string }) { return <div className={styles.continue}><button type="button" onClick={onClick}>{label}<span>✓</span></button><small>press <kbd>Enter ↵</kbd></small></div>; }
function Choice({ index, label, description, selected, onClick, multi = false }: { index: number; label: string; description: string; selected: boolean; onClick: () => void; multi?: boolean }) { return <button type="button" role={multi ? "option" : "radio"} aria-selected={multi ? selected : undefined} aria-checked={multi ? undefined : selected} className={selected ? styles.selected : ""} onClick={onClick}><kbd>{String.fromCharCode(65 + index)}</kbd><span><strong>{label}</strong><small>{description}</small></span><i>✓</i></button>; }
