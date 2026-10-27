import { profile } from "../../../lib/profile.ts";
import { controlJSON } from "../../../lib/trust.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function GET() {
  try {
    if (profile() === "synthetic-qualification") {
      const ready = await controlJSON("/readyz");
      if (!ready.response.ok) throw new Error("Dependency unavailable");
      const status = await controlJSON("/v1/status");
      if (!status.response.ok) throw new Error("Status unavailable");
      return Response.json(status.value, { headers: { "Cache-Control": "no-store" } });
    }
    const base = process.env.CONTROL_URL;
    if (!base || process.env.APP_ENV !== "development") throw new Error("Development configuration required");
    const response = await fetch(`${base}/readyz`, { cache: "no-store", signal: AbortSignal.timeout(4000) });
    if (!response.ok) throw new Error("Dependency unavailable");
    const status = await fetch(`${base}/v1/status`, { cache: "no-store", signal: AbortSignal.timeout(4000) });
    if (!status.ok) throw new Error("Status unavailable");
    return Response.json(await status.json(), { headers: { "Cache-Control": "no-store" } });
  } catch { return Response.json({ code: "UNAVAILABLE" }, { status: 503 }); }
}
