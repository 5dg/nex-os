import { noStore, sessionView } from "../../../lib/auth.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function GET(request: Request) { try { return await sessionView(request); } catch { return noStore({ code: "AUTHENTICATION_UNAVAILABLE" }, 503); } }
