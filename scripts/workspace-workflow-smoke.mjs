import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
const base = "http://127.0.0.1:3000";
const page = await fetch(`${base}/workflow`);
assert.equal(page.status, 200);assert.match(await page.text(), /Accountable actions/);
async function call(subject, operation, data = {}, status = 200) {
  const response = await fetch(`${base}/api/workflow`, { method: "POST", headers: { "Content-Type": "application/json", Origin: base }, body: JSON.stringify({ subject, operation, ...data }) });
  const result = await response.json();assert.equal(response.status, status, JSON.stringify(result));return result;
}
const documents = await call("alice", "documents");assert(documents.some(x => x.id === "review-alice"));assert(!documents.some(x => x.id === "review-bob"));
const created = await call("alice", "create", { document_id: "review-alice", question: "Summarize the synthetic access review requirements.", idempotency_key: randomUUID() }, 202);
async function wait() {
  for (let i = 0; i < 80; i++) {
    const result = await call("alice", "job", { id: created.id });
    assert.notEqual(result.state, "failed", JSON.stringify(result));
    if (result.state === "completed") return result;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error("Job did not complete");
}
const review = await wait();assert.equal(review.provider, "development");
await call("bob", "job", { id: created.id }, 403);
const approval = await call("alice", "export", { id: created.id }, 201);
const approvals = await call("carol", "approvals");const pending = approvals.find(x => x.id === approval.id);
assert(pending);assert.match(pending.export_preview, /SYNTHETIC DEVELOPMENT REVIEW/);assert.equal(pending.requester_id, "alice");assert.equal(pending.document_id, "review-alice");
await call("alice", "decide", { id: approval.id, request_digest: approval.request_digest, approve: true }, 403);
await call("carol", "decide", { id: approval.id, request_digest: approval.request_digest, approve: true });
const delivered = await wait();assert(delivered.export_id);
const events = await call("alice", "events", { id: created.id });
assert(events.length > 0);assert(events.every(x => x.integrity_verified), "New workflow contains unsigned or invalid evidence");
assert(events.some(x => x.producer === "kernel" && x.action === "export.authorized" && x.detail.approval_digest === approval.request_digest));
const rejected = await fetch(`${base}/api/workflow`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://untrusted.invalid" }, body: "{}" });assert.equal(rejected.status, 403);
console.log("Workspace workflow passed: rendered UI, scoped document list, durable review, exact export preview, independent approval, controlled export, signed producer-bound evidence and cross-origin rejection.");
