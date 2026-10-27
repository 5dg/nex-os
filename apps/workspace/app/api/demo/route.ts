import { profile } from "../../../lib/profile.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try { if (profile() !== "development") return Response.json({ code: "NOT_AVAILABLE" }, { status: 404 }); } catch { return Response.json({ code: "PROFILE_UNAVAILABLE" }, { status: 503 }); }
  if (process.env.APP_ENV !== "development") return Response.json({ code: "DEVELOPMENT_ONLY" }, { status: 403 });
  const origin = request.headers.get("origin");
  try {
    if (!origin || new URL(origin).host !== request.headers.get("host")) return Response.json({ code: "ORIGIN_DENIED" }, { status: 403 });
  } catch { return Response.json({ code: "ORIGIN_DENIED" }, { status: 403 }); }
  if (request.headers.get("content-type") !== "application/json") return Response.json({ code: "INVALID_REQUEST" }, { status: 415 });
  try {
    const text = await request.text();
    if (text.length > 2048) return Response.json({ code: "INVALID_REQUEST" }, { status: 413 });
    const input = JSON.parse(text);
    if (!["alice", "bob"].includes(input.subject) || !["authorize", "model"].includes(input.mode)) return Response.json({ code: "INVALID_REQUEST" }, { status: 400 });
    const issuer = process.env.DEV_ISSUER_URL, base = process.env.CONTROL_URL;
    if (!issuer || !base) throw new Error("Missing configuration");
    const tokenResponse = await fetch(`${issuer}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ subject: input.subject }), cache: "no-store", signal: AbortSignal.timeout(4000) });
    if (!tokenResponse.ok) throw new Error("Issuer unavailable");
    const { access_token } = await tokenResponse.json();
    const body = input.mode === "model" ? { delegation_id: `delegation-${input.subject}`, resource_id: "dev-model", prompt: "Synthetic connectivity check", max_output_tokens: 64 } : { delegation_id: `delegation-${input.subject}`, resource_id: input.resource_id, action: input.action };
    const result = await fetch(`${base}/v1/${input.mode === "model" ? "models/invoke" : "actions/authorize"}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` }, body: JSON.stringify(body), cache: "no-store", signal: AbortSignal.timeout(10000) });
    return Response.json(await result.json(), { status: result.status, headers: { "Cache-Control": "no-store" } });
  } catch { return Response.json({ code: "REQUEST_FAILED", message: "The development request could not be completed." }, { status: 503 }); }
}
