import { finishLogin, loginFailure } from "../../../lib/auth.ts";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function GET(request: Request) { try { return await finishLogin(request); } catch { return loginFailure(); } }
