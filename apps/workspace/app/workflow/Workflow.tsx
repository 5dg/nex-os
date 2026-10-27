"use client";
import { useEffect, useRef, useState } from "react";
import type { Profile } from "../../lib/profile.ts";
type Job = { id: string; state: string; phase: string; answer?: string; provider?: string; citation?: string; approval_id?: string; export_id?: string; error_code?: string };
type Approval = { export_preview?: string; requester_id?: string; document_id?: string; document_version?: string; id: string; job_id: string; request_digest: string; destination_id: string; expires_at: string; status: string };
type Event = { integrity_verified?: boolean; producer?: string; event_id: string; action: string; timestamp: string; detail: { outcome?: string; reason_code?: string } };
type Session = { authenticated: boolean; subject?: string; csrf_token?: string; can_request_review?: boolean; can_approve?: boolean; expires_at?: string };
type Document = { id: string; version: string; classification: string };
export default function Workflow({ profile }: { profile: Profile }) {
  const qualification = profile === "synthetic-qualification";
  const identity = useRef("");
  const [subject, setSubject] = useState("alice"), [document, setDocument] = useState("review-alice"), [question, setQuestion] = useState("What access review and export controls apply?");
  const [session, setSession] = useState<Session | null>(null), [documents, setDocuments] = useState<Document[]>([]);
  const [job, setJob] = useState<Job | null>(null), [jobId, setJobId] = useState(""), [approvals, setApprovals] = useState<Approval[]>([]), [events, setEvents] = useState<Event[]>([]), [message, setMessage] = useState(""), [busy, setBusy] = useState(false);
  const identityKey = qualification ? (session?.authenticated ? session.subject + "/" + session.csrf_token : "anonymous") : subject;
  identity.current = identityKey;
  async function request(operation: string, data: Record<string, unknown> = {}) {
    const selected = identity.current;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (qualification) headers["X-Nex-CSRF"] = session?.csrf_token || "";
    const response = await fetch("/api/workflow", { method: "POST", headers, body: JSON.stringify({ ...(qualification ? {} : { subject }), operation, ...data }) });
    const result = await response.json();
    if (qualification && response.status === 401 && identity.current === selected) setSession({ authenticated: false });
    if (!response.ok) throw new Error(result.message || result.code || "Request failed"); return result;
  }
  async function run(action: () => Promise<void>) { setBusy(true); setMessage(""); try { await action(); } catch (error) { setMessage(error instanceof Error ? error.message : "Request failed"); } finally { setBusy(false); } }
  async function refresh(id: string) { const selected = identity.current; const next = await request("job", { id }); const detail = await request("events", { id }); if (identity.current !== selected) return; setJob(next); setEvents(detail); }
  useEffect(() => {
    if (!qualification) return;
    let active = true;
    fetch("/api/session", { cache: "no-store" }).then(async response => { const result = await response.json(); if (active) { if (response.status === 503) throw new Error("Authentication is unavailable."); setSession(result); } }).catch(error => { if (active) setMessage(error.message); });
    return () => { active = false; };
  }, [qualification]);
  useEffect(() => { setJob(null); setJobId(""); setEvents([]); setApprovals([]); setDocuments([]); setMessage(""); }, [identityKey]);
  useEffect(() => {
    if (!qualification || !session?.authenticated) return;
    const selected = identity.current;
    request("documents").then((result: Document[]) => { if (identity.current === selected) { setDocuments(result); setDocument(result[0]?.id || ""); } }).catch(error => { if (identity.current === selected) setMessage(error.message); });
  }, [identityKey, qualification]);
  useEffect(() => {
    if (!job || !["queued", "running", "approval_required"].includes(job.state)) return;
    const timer = setInterval(() => { refresh(job.id).catch(error => setMessage(error.message)); }, 2000);
    return () => clearInterval(timer);
  }, [job?.id, job?.state, identityKey]);
  async function signOut() {
    const response = await fetch("/auth/logout", { method: "POST", headers: { "X-Nex-CSRF": session?.csrf_token || "" } });
    if (!response.ok) throw new Error("Sign-out could not be confirmed.");
    setSession({ authenticated: false });
  }
  const signedIn = !qualification || Boolean(session?.authenticated);
  return <div className="shell"><aside><a className="brand" href="/">nex<span>.os</span></a><p className="caption">GOVERNED AI WORKSPACE</p><nav>{!qualification && <a href="/laboratory">Guard laboratory</a>}<a className="selected" href="/workflow">Document review</a><a href="#approvals">Approvals</a><a href="#evidence">Execution evidence</a></nav><p className="aside-note">Synthetic data only<br/>{qualification ? "Authenticated qualification fixture" : "Development identity issuer"}</p></aside><main>
    <header><span>Authorized review · Independent approval · Recorded outcomes</span><span className="good">{qualification ? "Synthetic qualification" : "Local alpha workflow"}</span></header>
    <section className="intro"><p className="eyebrow">REVIEW / APPROVE / EXPORT</p><h1>One workflow. Accountable actions.</h1><p>Review a permitted synthetic record, then obtain an independent decision before exporting the answer.</p></section>
    <div className="notice">{qualification ? "This profile uses a test identity provider, verified encrypted connections and admitted synthetic records. It does not authorize real CUI or production use." : "Development model responses are deterministic. Live Bedrock and GovCloud deployment are deferred. No real CUI is permitted here."}</div>
    {qualification ? session?.authenticated ? <div><p>Signed in as <strong>{session.subject}</strong></p><button className="secondary" disabled={busy} onClick={() => run(signOut)}>Sign out</button></div> : <section className="card"><h2>{session === null ? "Checking sign-in…" : "Sign in to the synthetic workspace"}</h2><p>Your account determines permitted records and approval authority. This page cannot select another identity.</p><a className="brand" href="/auth/login">Sign in →</a></section> : <label>Development persona<select disabled={busy} value={subject} onChange={e => setSubject(e.target.value)}><option value="alice">Alice · Contractor A requester</option><option value="carol">Carol · Contractor A approver</option><option value="bob">Bob · Contractor B requester</option><option value="dave">Dave · Contractor B approver</option></select></label>}
    {message && <p role="alert" className="notice">{message}</p>}
    {signedIn && <><div className="grid"><section className="card"><p className="eyebrow">01 / DOCUMENT REVIEW</p><h2>Start a durable job</h2><label>Document<select value={document} onChange={e => setDocument(e.target.value)}>{qualification ? documents.map(record => <option key={record.id} value={record.id}>{record.id} · {record.classification}</option>) : <><option value="review-alice">Synthetic record · Contractor A</option><option value="review-bob">Synthetic record · Contractor B</option></>}</select></label>
      <label>Question{qualification ? <p>What access review and export controls apply?<br/><span className="help">Approved synthetic question catalogue · internal</span></p> : <textarea rows={3} maxLength={1000} value={question} onChange={e => setQuestion(e.target.value)} />}</label>
      <button disabled={busy || (qualification && (!session?.can_request_review || !document))} onClick={() => run(async () => { const result = await request("create", { document_id: document, ...(qualification ? { question_catalogue_id: "access-review-controls" } : { question }), idempotency_key: crypto.randomUUID() }); setJob(result); setJobId(result.id); })}>Start governed review →</button>
      {qualification && !session?.can_request_review && <p className="help">This account has no active review delegation. Assigned approvers can review requests below.</p>}
      <label>Resume an existing job<input value={jobId} onChange={e => setJobId(e.target.value)} placeholder="Job reference" /></label><button className="secondary" disabled={busy || !jobId} onClick={() => run(() => refresh(jobId))}>Load job and evidence</button>
      {job && <><h3>Job reference</h3><code>{job.id}</code><p className="effect">{job.state}</p>{job.answer && <p style={{ whiteSpace: "pre-wrap" }}>{job.answer}</p>}<p className="help">{job.provider} · {job.citation}</p>{job.error_code && <div role="status"><p>{job.error_code.endsWith("_PREPARATION_DENIED") || job.error_code === "AUTHORITY_REVOKED" ? "Current authorization or sealed content no longer permits this operation. Start a new governed review; historical results are retained." : job.error_code.endsWith("_NOT_STARTED") ? "Execution did not start. You can retry this same operation while its authorization remains valid." : job.error_code.endsWith("_IN_PROGRESS") ? "An executor is still handling this operation. Check its recorded outcome before taking another action." : "The outcome could not be confirmed. Check the recorded outcome; starting a replacement may duplicate an effect."}</p><code>{job.error_code}</code>{job.state === "failed" && !job.error_code.endsWith("_PREPARATION_DENIED") && job.error_code !== "AUTHORITY_REVOKED" && <><button className="secondary" disabled={busy} onClick={() => run(async () => { const result = await request("reconcile", { id: job.id }); setMessage(result.state === "completed" ? "Recovered the completed result." : `Recorded outcome: ${result.state}. No new execution was requested.`); await refresh(job.id); })}>Check recorded outcome</button>{job.error_code.endsWith("_NOT_STARTED") && <button disabled={busy} onClick={() => run(async () => { await request("retry", { id: job.id }); await refresh(job.id); })}>Retry the same operation</button>}</>}</div>}{job.state === "completed" && job.phase === "review" && <button disabled={busy} onClick={() => run(async () => { await request("export", { id: job.id }); await refresh(job.id); })}>Request export approval</button>}{job.export_id && <><h3>Controlled local export</h3><code>{job.export_id}</code></>}</>}
    </section><section className="card" id="approvals"><p className="eyebrow">02 / INDEPENDENT APPROVAL</p><h2>Review exact export requests</h2><p className="help">{qualification ? "An authorized independent approver must inspect the exact content and destination. Your account's current permissions are checked for every decision." : "Select Carol or Dave to act as the corresponding tenant’s approver. Requesters cannot approve their own export."}</p><button className="secondary" disabled={busy || (qualification && !session?.can_approve)} onClick={() => run(async () => setApprovals(await request("approvals")))}>Refresh approvals</button>
      {approvals.map(a => <div className="model" key={a.id}><h3>{a.status} · {a.destination_id}</h3><code>{a.job_id}</code><p className="help">Expires {new Date(a.expires_at).toLocaleString()}</p><h3>Requested by {a.requester_id} · {a.document_id}@{a.document_version}</h3><p style={{ whiteSpace: "pre-wrap" }}>{a.export_preview}</p><h3>Exact request digest</h3><code>{a.request_digest}</code>{a.status === "pending" && <><button disabled={busy} onClick={() => run(async () => { await request("decide", { id: a.id, request_digest: a.request_digest, approve: true }); setApprovals(await request("approvals")); })}>Approve this exact export</button><button className="secondary" disabled={busy} onClick={() => run(async () => { await request("decide", { id: a.id, request_digest: a.request_digest, approve: false }); setApprovals(await request("approvals")); })}>Reject</button></>}</div>)}
    </section></div>
    <section className="card" id="evidence" style={{ marginTop: 22 }}><p className="eyebrow">03 / EXECUTION EVIDENCE</p><h2>Decisions and outcomes</h2>{events.length ? events.map(event => <div key={event.event_id} style={{ borderTop: "1px solid var(--line)", padding: "10px 0" }}><strong>{event.action}</strong>{event.integrity_verified && <span className="good" style={{ fontSize: 11, marginLeft: 12 }}>Verified · {event.producer}</span>}<span style={{ float: "right", color: "var(--muted)", fontSize: 12 }}>{new Date(event.timestamp).toLocaleTimeString()}</span><p className="help">{event.detail.outcome || event.detail.reason_code}</p><code>{event.event_id}</code></div>) : <p>Load or start a job to inspect its recorded decisions and outcomes.</p>}</section></>}
    <footer>Only admitted synthetic data is supported. Customer identity, approved cryptography, independent custody and assessment remain deployment requirements.</footer>
  </main></div>;
}
