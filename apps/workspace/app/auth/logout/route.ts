import { logout, noStore } from "../../../lib/auth.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function POST(request: Request) { try { return await logout(request); } catch { return noStore({ code: "SESSION_OR_CSRF_DENIED" }, 403); } }
