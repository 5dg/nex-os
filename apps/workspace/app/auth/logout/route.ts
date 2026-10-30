import { logout, noStore } from "../../../lib/auth.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try { return await logout(request); }
  catch (error) {
    if (error instanceof Error && (error.message === "Session store unavailable" || error.message.startsWith("Session configuration"))) return noStore({ code: "AUTHENTICATION_UNAVAILABLE" }, 503);
    return noStore({ code: "SESSION_OR_CSRF_DENIED" }, 403);
  }
}
