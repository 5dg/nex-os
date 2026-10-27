"use client";
import { useEffect, useState } from "react";

type Result = { effect?: string; reason_code?: string; policy_digest?: string; decision_id?: string; provider?: string; text?: string; code?: string; message?: string };
export default function Workspace() {
  const [ready, setReady] = useState(false);
  const [subject, setSubject] = useState("alice");
  const [resource, setResource] = useState("document-alice");
  const [action, setAction] = useState("document.read");
  const [result, setResult] = useState<Result | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => { fetch("/api/status").then(r => setReady(r.ok)).catch(() => setReady(false)); }, []);
  async function run(mode: "authorize" | "model") {
    setPending(true); setResult(null);
    try {
      const response = await fetch("/api/demo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subject, resource_id: resource, action, mode }) });
      setResult(await response.json());
    } catch { setResult({ code: "CONNECTION_FAILED", message: "The control service could not be reached." }); }
    finally { setPending(false); }
  }
  return <div className="shell">
    <aside><a className="brand" href="/">nex<span>.os</span></a><p className="caption">GOVERNED AI WORKSPACE</p><nav><a className="selected" href="#guard">Guard laboratory</a><a href="/workflow">Document review</a><span>Approvals · upcoming</span><span>Evidence explorer · upcoming</span></nav><p className="aside-note">Alpha foundation<br/>Synthetic data only</p></aside>
    <main><header><span>Development environment</span><span className={ready ? "status good" : "status"}>{ready ? "Control dependencies ready" : "Checking / unavailable"}</span></header>
      <section className="intro"><p className="eyebrow">NEX.GUARD / FIRST ENFORCEMENT PATH</p><h1>Authority before action.</h1><p>Exercise tenant boundaries and delegated permissions against the live policy service. Every completed decision is recorded in PostgreSQL.</p></section>
      <div className="notice">Local synthetic identities · Development model adapter · No Bedrock inference · No compliance certification</div>
      <div className="grid"><section className="card" id="guard"><p className="eyebrow">01 / PROPOSE AN ACTION</p><h2>Authorization laboratory</h2>
        <label>Synthetic identity<select value={subject} onChange={e => setSubject(e.target.value)}><option value="alice">Alice · Contractor A</option><option value="bob">Bob · Contractor B</option></select></label>
        <label>Resource<select value={resource} onChange={e => setResource(e.target.value)}><option value="document-alice">Internal document · Contractor A</option><option value="document-bob">Internal document · Contractor B</option><option value="restricted-alice">Restricted document · Contractor A</option></select></label>
        <label>Proposed action<select value={action} onChange={e => setAction(e.target.value)}><option value="document.read">Read document</option><option value="document.export">Export document</option><option value="shell.execute">Unregistered shell action</option></select></label>
        <button disabled={pending} onClick={() => run("authorize")}>{pending ? "Evaluating…" : "Evaluate authorization →"}</button>
        <p className="help">Try Alice reading Contractor B’s document. Export decisions require approval; no export is executed in this milestone.</p>
      </section><section className="card result"><p className="eyebrow">02 / INSPECT THE DECISION</p><h2>Independent enforcement</h2>
        {result ? <><div role="status" className={`effect ${result.effect === "allow" ? "good" : ""}`}>{result.effect || result.provider || result.code}</div><p>{result.reason_code || result.text || result.message}</p>{result.decision_id && <><h3>Decision reference</h3><code>{result.decision_id}</code></>}{result.policy_digest && <><h3>Policy source digest</h3><code>{result.policy_digest}</code></>}</> : <div className="empty"><div className="symbol">◇</div><p>Choose an identity, resource, and action.<br/>The gateway resolves trusted facts independently.</p></div>}
        <div className="model"><h3>Development model route</h3><p>Runs a fixed synthetic response through the same authorization path.</p><button className="secondary" disabled={pending} onClick={() => run("model")}>Test governed development model</button></div>
      </section></div>
      <footer>Current scope: authenticated permit/deny, approval-required decisions, and development inference. Durable jobs, document bodies, export execution, and GovCloud deployment follow.</footer>
    </main>
  </div>;
}
