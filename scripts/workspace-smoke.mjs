import assert from "node:assert/strict";
const base = "http://127.0.0.1:3000";
const page = await fetch(base);
assert.equal(page.status, 200);
assert.match(await page.text(), /Authority before action/);
assert.equal((await fetch(`${base}/api/status`)).status, 200);
for (const [subject, resource_id, action, status, effect] of [
  ["alice", "document-alice", "document.read", 200, "allow"],
  ["alice", "document-bob", "document.read", 403, "deny"],
  ["alice", "document-alice", "document.export", 200, "require_approval"],
]) {
  const r = await fetch(`${base}/api/demo`, { method: "POST", headers: { "Content-Type": "application/json", Origin: base }, body: JSON.stringify({ subject, resource_id, action, mode: "authorize" }) });
  assert.equal(r.status, status);assert.equal((await r.json()).effect, effect);
}
const foreign = await fetch(`${base}/api/demo`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://untrusted.invalid" }, body: "{}" });
assert.equal(foreign.status, 403);
const malformed = await fetch(`${base}/api/demo`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "malformed" }, body: "{}" });
assert.equal(malformed.status, 403);
console.log("Workspace smoke: rendered page, dependency readiness, permitted/denied/approval decisions, and origin rejection passed.");
