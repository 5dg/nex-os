import { randomBytes, timingSafeEqual } from "node:crypto";
import { profile } from "./profile.ts";
import { createPostgresSessionStore } from "./postgres-session-config.ts";
import type { PostgresSessionStore } from "./postgres-sessions.ts";

export const SESSION_COOKIE = "__Host-nex_session";
export const LOGIN_COOKIE = "__Host-nex_login";
export const CSRF_HEADER = "X-Nex-CSRF";
export const IDLE_MILLISECONDS = 5 * 60_000;
export const TOTAL_MILLISECONDS = 15 * 60_000;
const TRANSACTION_MILLISECONDS = 5 * 60_000;
const MAX_RECORDS = 1000;

export type Actor = { issuer: string; subject: string; user_id: string; tenant_id: string; delegation_id: string; permissions: string[] };
export type Session = { id: string; actor: Actor; accessToken: string; csrf: string; expires: number; idleExpires: number };
export type Login = { id: string; state: string; nonce: string; verifier: string; expires: number };
function id(): string { return randomBytes(32).toString("base64url"); }
export function equalSecret(left: string, right: string): boolean {
  if (left.length > 256 || right.length > 256) return false;
  const a = Buffer.from(left), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
export function cookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie") || "";
  if (header.length > 8192) throw new Error("Cookie header exceeds limit");
  const matches = header.split(";").map(part => part.trim()).filter(part => part.startsWith(name + "="));
  if (matches.length > 1) throw new Error("Ambiguous session cookie");
  if (!matches.length) return undefined;
  const value = matches[0].slice(name.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}
export function cookieHeader(name: string, value: string, seconds: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(seconds))}`;
}

// Single-instance synthetic store. Nothing is persisted or sent to the browser
// except an opaque handle and CSRF token. Restart deliberately logs everyone out.
export class SessionStore {
  private sessions = new Map<string, Session>();
  private logins = new Map<string, Login>();
  private now: () => number;
  constructor(now: () => number = Date.now) { this.now = now; }
  private clean(): void {
    const now = this.now();
    for (const [key, value] of this.sessions) if (value.expires <= now || value.idleExpires <= now) this.sessions.delete(key);
    for (const [key, value] of this.logins) if (value.expires <= now) this.logins.delete(key);
  }
  begin(state: string, nonce: string, verifier: string): Login {
    this.clean(); if (this.logins.size >= MAX_RECORDS) throw new Error("Login capacity unavailable");
    const value = { id: id(), state, nonce, verifier, expires: this.now() + TRANSACTION_MILLISECONDS };
    this.logins.set(value.id, value); return value;
  }
  consume(transaction: string, state: string): Login {
    this.clean(); const found = this.logins.get(transaction);
    // Consume before any awaited exchange, including failed state validation.
    this.logins.delete(transaction);
    if (!found || !equalSecret(found.state, state)) throw new Error("Login transaction denied"); return found;
  }
  open(actor: Actor, accessToken: string, accessExpiry: number, assertionExpiry: number): Session {
    this.clean(); if (this.sessions.size >= MAX_RECORDS) throw new Error("Session capacity unavailable");
    const now = this.now(), expires = Math.min(now + TOTAL_MILLISECONDS, accessExpiry, assertionExpiry);
    if (!Number.isFinite(expires) || expires <= now || accessToken.length > 8192) throw new Error("Expired login credential");
    const value = { id: id(), actor, accessToken, csrf: id(), expires, idleExpires: Math.min(expires, now + IDLE_MILLISECONDS) };
    this.sessions.set(value.id, value); return value;
  }
  get(value: string | undefined, touch = false): Session | undefined {
    this.clean(); if (!value) return undefined;
    const found = this.sessions.get(value);
    if (found && touch) found.idleExpires = Math.min(found.expires, this.now() + IDLE_MILLISECONDS);
    return found;
  }
  close(value: string | undefined): void { if (value) { this.sessions.delete(value); this.logins.delete(value); } }
}
const globalStore = globalThis as typeof globalThis & { __nexQualificationSessions?: SessionStore | PostgresSessionStore };
export function sessions(): SessionStore | PostgresSessionStore {
  const backend = process.env.NEX_SESSION_BACKEND || "memory";
  if (backend !== "memory" && backend !== "postgres") throw new Error("Session configuration invalid");
  if (backend === "postgres" && profile() !== "synthetic-qualification") throw new Error("Session configuration invalid");
  if (!globalStore.__nexQualificationSessions) globalStore.__nexQualificationSessions = backend === "postgres" ? createPostgresSessionStore() : new SessionStore();
  const store = globalStore.__nexQualificationSessions;
  if ((backend === "postgres") !== ("readiness" in store)) throw new Error("Session configuration changed after startup");
  return store;
}
