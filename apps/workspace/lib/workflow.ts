import { noStore, requireSession } from "./auth.ts";
import { controlJSON } from "./trust.ts";
import { sessions } from "./sessions.ts";

async function boundedJSON(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("content-type") !== "application/json") throw new Error("JSON required");
  const reader = request.body?.getReader(); if (!reader) throw new Error("Body required");
  const parts: Uint8Array[] = []; let length = 0;
  const deadline = Date.now() + 5000;
  try {
    for (;;) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const result = await Promise.race([reader.read(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Body timeout")), Math.max(0, deadline - Date.now())); })]).finally(() => clearTimeout(timer));
      if (result.done) break;
      length += result.value.length; if (length > 8192) throw new Error("Body exceeds limit"); parts.push(result.value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  const value: unknown = JSON.parse(Buffer.concat(parts).toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Object required");
  return value as Record<string, unknown>;
}
export async function qualificationWorkflow(request: Request): Promise<Response> {
  let session;
  try { session = requireSession(request, true); } catch (error) {
    return noStore({ code: error instanceof Error && error.message === "Session required" ? "UNAUTHENTICATED" : "SESSION_OR_CSRF_DENIED" }, error instanceof Error && error.message === "Session required" ? 401 : 403);
  }
  let input: Record<string, unknown>;
  try { input = await boundedJSON(request); } catch { return noStore({ code: "INVALID_REQUEST" }, 400); }
  const operation = input.operation;
  const keys: Record<string, string[]> = {
    documents: [], approvals: [], job: ["id"], events: ["id"],
    create: ["document_id", "idempotency_key", "question_catalogue_id"],
    export: ["id"], reconcile: ["id"], retry: ["id"], decide: ["id", "approve", "request_digest"],
  };
  if (typeof operation !== "string" || !Object.hasOwn(keys, operation) || Object.keys(input).some(key => key !== "operation" && !keys[operation].includes(key))) return noStore({ code: "INVALID_REQUEST" }, 400);
  const id = typeof input.id === "string" && /^[A-Za-z0-9_-]{8,100}$/.test(input.id) ? input.id : "";
  if (["job", "events", "export", "reconcile", "retry", "decide"].includes(operation) && !id) return noStore({ code: "INVALID_REQUEST" }, 400);
  if (operation === "create" && (!session.actor.delegation_id || typeof input.document_id !== "string" || !/^[A-Za-z0-9_-]{1,100}$/.test(input.document_id) || typeof input.idempotency_key !== "string" || !/^[A-Za-z0-9_-]{8,100}$/.test(input.idempotency_key) || input.question_catalogue_id !== "access-review-controls")) return noStore({ code: "INVALID_REQUEST" }, 400);
  if (operation === "decide" && (typeof input.approve !== "boolean" || typeof input.request_digest !== "string" || !/^[a-f0-9]{64}$/.test(input.request_digest))) return noStore({ code: "INVALID_REQUEST" }, 400);
  const operations: Record<string, { method: string; path: string; body?: unknown }> = {
    documents: { method: "GET", path: "/v1/documents" }, approvals: { method: "GET", path: "/v1/approvals" },
    job: { method: "GET", path: `/v1/jobs/${id}` }, events: { method: "GET", path: `/v1/jobs/${id}/events` },
    create: { method: "POST", path: "/v1/jobs", body: { delegation_id: session.actor.delegation_id, document_id: input.document_id, question_catalogue_id: "access-review-controls", idempotency_key: input.idempotency_key } },
    export: { method: "POST", path: `/v1/jobs/${id}/export`, body: { destination_id: "local-evidence" } },
    reconcile: { method: "POST", path: `/v1/jobs/${id}/reconcile` }, retry: { method: "POST", path: `/v1/jobs/${id}/retry` },
    decide: { method: "POST", path: `/v1/approvals/${id}/decision`, body: { approve: input.approve, request_digest: input.request_digest } },
  };
  const selected = operations[operation];
  if (selected.method === "POST") sessions().get(session.id, true);
  try {
    const { response, value } = await controlJSON(selected.path, session.accessToken, selected.method, selected.body);
    if (response.status === 401) sessions().close(session.id);
    return noStore(value, response.status);
  } catch { return noStore({ code: "DEPENDENCY_UNAVAILABLE", message: "The authenticated workflow service is unavailable." }, 503); }
}
