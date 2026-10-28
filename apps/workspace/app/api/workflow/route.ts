import { profile } from "../../../lib/profile.ts";
import { qualificationWorkflow } from "../../../lib/workflow.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try { if (profile() === "synthetic-qualification") return await qualificationWorkflow(request); } catch { return Response.json({ code: "PROFILE_UNAVAILABLE" }, { status: 503 }); }
  if (process.env.APP_ENV !== "development") return Response.json({ code: "DEVELOPMENT_ONLY" }, { status: 403 });
  try {
    const origin = request.headers.get("origin");
    if (!origin || new URL(origin).host !== request.headers.get("host")) return Response.json({ code: "ORIGIN_DENIED" }, { status: 403 });
    const reader = request.body?.getReader(); if (!reader) throw new Error("Missing body");
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 8192) { await reader.cancel(); return Response.json({ code: "PAYLOAD_TOO_LARGE" }, { status: 413 }); } chunks.push(value); }
    const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!["alice", "bob", "carol", "dave"].includes(input.subject)) return Response.json({ code: "INVALID_IDENTITY" }, { status: 400 });
    const id = typeof input.id === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(input.id) ? input.id : "";
    if (input.operation === "event_page" && (Object.keys(input).some(key => !["subject", "operation", "id", "cursor"].includes(key)) || (input.cursor !== undefined && (typeof input.cursor !== "string" || (input.cursor.length > 4096 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input.cursor)))))) return Response.json({ code: "INVALID_REQUEST" }, { status: 400 });
    const operations: Record<string, { method: string; path: string; body?: unknown }> = {
      documents: { method: "GET", path: "/v1/documents" },
      approvals: { method: "GET", path: "/v1/approvals" },
      job: { method: "GET", path: `/v1/jobs/${id}` },
      events: { method: "GET", path: `/v1/jobs/${id}/events` },
      event_page: { method: "GET", path: `/v1/jobs/${id}/events?page=1${input.cursor ? "&cursor=" + encodeURIComponent(input.cursor) : ""}` },
      create: { method: "POST", path: "/v1/jobs", body: { delegation_id: `delegation-${input.subject}`, document_id: input.document_id, question: input.question, idempotency_key: input.idempotency_key } },
      reconcile: { method: "POST", path: `/v1/jobs/${id}/reconcile` },
      retry: { method: "POST", path: `/v1/jobs/${id}/retry` },
      export: { method: "POST", path: `/v1/jobs/${id}/export`, body: { destination_id: "local-evidence" } },
      decide: { method: "POST", path: `/v1/approvals/${id}/decision`, body: { approve: input.approve, request_digest: input.request_digest } },
    };
    const operation = operations[input.operation];
    if (!operation || (["job", "events", "event_page", "export", "decide", "reconcile", "retry"].includes(input.operation) && !id)) return Response.json({ code: "INVALID_OPERATION" }, { status: 400 });
    const issuer = process.env.DEV_ISSUER_URL, control = process.env.CONTROL_URL;
    if (!issuer || !control) throw new Error("Missing configuration");
    const token = await fetch(`${issuer}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ subject: input.subject }), cache: "no-store", signal: AbortSignal.timeout(3000) });
    if (!token.ok) throw new Error("Issuer unavailable");
    const { access_token } = await token.json();
    const result = await fetch(control + operation.path, { method: operation.method, headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` }, body: operation.body === undefined ? undefined : JSON.stringify(operation.body), cache: "no-store", signal: AbortSignal.timeout(15000) });
    return Response.json(await result.json(), { status: result.status, headers: { "Cache-Control": "no-store" } });
  } catch { return Response.json({ code: "REQUEST_FAILED", message: "The local workflow request could not be completed." }, { status: 503 }); }
}
