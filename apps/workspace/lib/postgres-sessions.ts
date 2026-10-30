import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { equalSecret, IDLE_MILLISECONDS, TOTAL_MILLISECONDS, type Actor, type Login, type Session, type SessionAssurance } from "./sessions.ts";

const LOGIN_MILLISECONDS = 5 * 60_000;
const MAX_RECORDS = 1000;
const MAX_PAYLOAD_BYTES = 32 * 1024;
type Kind = "login" | "session";
type State = Omit<Login, "id" | "expires"> | Omit<Session, "id" | "expires" | "idleExpires">;
type Row = { sealed: Buffer; hard_expires_ms: string; idle_expires_ms: string };
const DB_NOW = "floor(extract(epoch from clock_timestamp()) * 1000)::bigint";
function handle(): string { return randomBytes(32).toString("base64url"); }
function hashHandle(id: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(id)) throw new Error("Session handle invalid");
  return createHash("sha256").update(id, "ascii").digest("hex");
}
function expiry(value: string): number {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result <= 0) throw new Error("Session record invalid");
  return result;
}
function aad(kind: Kind, hash: string, hard: number, idle: number): Buffer {
  return Buffer.from(`nex-workspace-session-v1\n${kind}\n${hash}\n${hard}\n${idle}`, "utf8");
}

// The pool must use a dedicated least-privilege workspace role, authenticated
// TLS and bounded timeouts. The separately generated key is never stored in DB.
// Production profile selection remains closed until its startup checks and
// deployment integration are independently qualified.
export class PostgresSessionStore {
  private readonly key: Buffer;
  private readonly pool: Pool;
  constructor(pool: Pool, key: Uint8Array) {
    if (key.length !== 32 || key.every(value => value === 0)) throw new Error("Session encryption key invalid");
    this.pool = pool;
    this.key = Buffer.from(key);
  }
  async readiness(): Promise<void> {
    try {
      const result = await this.pool.query<{ allowed: boolean }>(`SELECT
        current_user = session_user AND current_setting('search_path') = 'pg_catalog' AND t.relkind = 'r' AND r.rolcanlogin AND NOT r.rolsuper AND
        NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls AND
        NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid) AND
        NOT has_database_privilege(current_user, current_database(), 'CREATE') AND
        CASE WHEN pg_catalog.to_regnamespace('public') IS NULL THEN true ELSE NOT has_schema_privilege(current_user, 'public', 'CREATE') END AND
        has_schema_privilege(current_user, 'nex_workspace_auth', 'USAGE') AND
        NOT has_schema_privilege(current_user, 'nex_workspace_auth', 'USAGE WITH GRANT OPTION') AND
        NOT has_schema_privilege(current_user, 'nex_workspace_auth', 'CREATE') AND
        pg_catalog.pg_get_userbyid(n.nspowner) <> current_user AND
        pg_catalog.pg_get_userbyid(t.relowner) <> current_user AND
        has_table_privilege(current_user, t.oid, 'SELECT') AND
        has_table_privilege(current_user, t.oid, 'INSERT') AND
        has_table_privilege(current_user, t.oid, 'UPDATE') AND
        has_table_privilege(current_user, t.oid, 'DELETE') AND
        NOT has_table_privilege(current_user, t.oid, 'TRUNCATE,REFERENCES,TRIGGER') AND
        NOT has_table_privilege(current_user, t.oid, 'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION') AND
        NOT has_any_column_privilege(current_user, t.oid, 'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION') AND
        NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace s WHERE pg_catalog.left(s.nspname, 3) <> 'pg_' AND s.nspname <> 'information_schema' AND has_schema_privilege(current_user, s.oid, 'CREATE')) AND
        NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
          WHERE c.oid <> t.oid AND pg_catalog.left(s.nspname, 3) <> 'pg_' AND s.nspname <> 'information_schema'
            AND c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))) AND
        NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
          WHERE pg_catalog.left(s.nspname, 3) <> 'pg_' AND s.nspname <> 'information_schema' AND c.relkind = 'S'
            AND has_sequence_privilege(current_user, c.oid, 'USAGE,SELECT,UPDATE')) AND
        NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid = p.pronamespace
          WHERE pg_catalog.left(s.nspname, 3) <> 'pg_' AND s.nspname <> 'information_schema' AND has_function_privilege(current_user, p.oid, 'EXECUTE')) AS allowed
        FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_namespace n ON n.nspname = 'nex_workspace_auth'
        JOIN pg_catalog.pg_class t ON t.relnamespace = n.oid AND t.relname = 'workspace_session_state'
        WHERE r.rolname = current_user`);
      if (result.rows[0]?.allowed !== true) throw new Error("insufficient permission");
    }
    catch { throw new Error("Session store unavailable"); }
  }
  private seal(kind: Kind, hash: string, hard: number, idle: number, state: State): Buffer {
    const plaintext = Buffer.from(JSON.stringify(state), "utf8");
    if (plaintext.length > MAX_PAYLOAD_BYTES) throw new Error("Session payload exceeds limit");
    const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(aad(kind, hash, hard, idle));
    return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  }
  private unseal(kind: Kind, hash: string, hard: number, idle: number, sealed: Buffer): State {
    if (!Buffer.isBuffer(sealed) || sealed.length < 28 || sealed.length > MAX_PAYLOAD_BYTES + 28) throw new Error("Session record invalid");
    const decipher = createDecipheriv("aes-256-gcm", this.key, sealed.subarray(0, 12));
    decipher.setAAD(aad(kind, hash, hard, idle));
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    const data: unknown = JSON.parse(Buffer.concat([decipher.update(sealed.subarray(12, -16)), decipher.final()]).toString("utf8"));
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Session record invalid");
    return data as State;
  }
  private async transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    let client: PoolClient | undefined;
    let broken = false;
    try {
      client = await this.pool.connect();
      await client.query("BEGIN");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch {
      if (client) await client.query("ROLLBACK").catch(() => { broken = true; });
      throw new Error("Session store unavailable");
    } finally { client?.release(broken ? new Error("Session connection unavailable") : undefined); }
  }
  private async insert(kind: Kind, state: State, hardLimit?: number): Promise<{ id: string; hard: number; idle: number }> {
    return this.transaction(async client => {
      // Serialize count and cleanup across replicas; never exceed the bound.
      await client.query("SELECT pg_advisory_xact_lock(7247958301541)");
      const clock = await client.query<{ now_ms: string }>(`SELECT ${DB_NOW} AS now_ms`);
      const cleanupAt = expiry(clock.rows[0]?.now_ms);
      await client.query("DELETE FROM nex_workspace_auth.workspace_session_state WHERE kind=$1 AND (hard_expires_ms <= $2 OR idle_expires_ms <= $2)", [kind, cleanupAt]);
      const count = await client.query<{ count: string }>("SELECT count(*)::text AS count FROM nex_workspace_auth.workspace_session_state WHERE kind=$1", [kind]);
      const total = Number(count.rows[0]?.count);
      if (!Number.isSafeInteger(total) || total < 0 || total >= MAX_RECORDS) throw new Error("Session capacity unavailable");
      const currentClock = await client.query<{ now_ms: string }>(`SELECT ${DB_NOW}::text AS now_ms`);
      const now = expiry(currentClock.rows[0]?.now_ms);
      const hard = kind === "login" ? now + LOGIN_MILLISECONDS : Math.min(now + TOTAL_MILLISECONDS, hardLimit ?? 0);
      if (!Number.isSafeInteger(hard) || hard <= now) throw new Error("Expired login credential");
      const idle = kind === "login" ? hard : Math.min(hard, now + IDLE_MILLISECONDS);
      const id = handle(), hash = hashHandle(id);
      const sealed = this.seal(kind, hash, hard, idle, state);
      await client.query("INSERT INTO nex_workspace_auth.workspace_session_state(kind,handle_hash,hard_expires_ms,idle_expires_ms,sealed) VALUES($1,$2,$3,$4,$5)", [kind, hash, hard, idle, sealed]);
      return { id, hard, idle };
    });
  }
  async begin(state: string, nonce: string, verifier: string): Promise<Login> {
    if (![state, nonce, verifier].every(value => typeof value === "string" && value.length > 0 && value.length <= 256)) throw new Error("Login transaction denied");
    const record = await this.insert("login", { state, nonce, verifier });
    return { id: record.id, state, nonce, verifier, expires: record.hard };
  }
  async consume(id: string, state: string): Promise<Login> {
    let hash: string;
    try { hash = hashHandle(id); } catch { throw new Error("Login transaction denied"); }
    let row: Row | undefined;
    try {
      // Autocommit deletion precedes state comparison and token exchange.
      const result = await this.pool.query<Row>("DELETE FROM nex_workspace_auth.workspace_session_state WHERE kind='login' AND handle_hash=$1 RETURNING sealed,hard_expires_ms::text,idle_expires_ms::text", [hash]);
      row = result.rows[0];
    } catch { throw new Error("Session store unavailable"); }
    if (!row) throw new Error("Login transaction denied");
    let now: number;
    try {
      const clock = await this.pool.query<{ now_ms: string }>(`SELECT ${DB_NOW}::text AS now_ms`);
      now = expiry(clock.rows[0]?.now_ms);
    } catch { throw new Error("Session store unavailable"); }
    try {
      const hard = expiry(row.hard_expires_ms), idle = expiry(row.idle_expires_ms);
      const data = this.unseal("login", hash, hard, idle, row.sealed) as Omit<Login, "id" | "expires">;
      if (hard <= now || idle <= now || typeof data.state !== "string" || typeof data.nonce !== "string" || typeof data.verifier !== "string" || !equalSecret(data.state, state)) throw new Error("denied");
      return { id, state: data.state, nonce: data.nonce, verifier: data.verifier, expires: hard };
    } catch { throw new Error("Login transaction denied"); }
  }
  async open(actor: Actor, accessToken: string, accessExpiry: number, assertionExpiry: number, assurance?: SessionAssurance): Promise<Session> {
    if (!Number.isSafeInteger(accessExpiry) || !Number.isSafeInteger(assertionExpiry) || typeof accessToken !== "string" || !accessToken || accessToken.length > 8192) throw new Error("Expired login credential");
    const csrf = handle();
    const record = await this.insert("session", { actor, accessToken, csrf, ...(assurance ? { assurance } : {}) }, Math.min(accessExpiry, assertionExpiry));
    return { id: record.id, actor, accessToken, csrf, expires: record.hard, idleExpires: record.idle, ...(assurance ? { assurance } : {}) };
  }
  async get(id: string | undefined, touch = false): Promise<Session | undefined> {
    if (!id) return undefined;
    let hash: string;
    try { hash = hashHandle(id); } catch { return undefined; }
    return this.transaction(async client => {
      const result = await client.query<Row>("SELECT sealed,hard_expires_ms::text,idle_expires_ms::text FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1 FOR UPDATE", [hash]);
      const row = result.rows[0];
      if (!row) return undefined;
      // The row lock may have waited; sample the authoritative database clock
      // only after it has been acquired, before accepting or extending expiry.
      const clock = await client.query<{ now_ms: string }>(`SELECT ${DB_NOW}::text AS now_ms`);
      const hard = expiry(row.hard_expires_ms), idle = expiry(row.idle_expires_ms), now = expiry(clock.rows[0]?.now_ms);
      if (hard <= now || idle <= now) { await client.query("DELETE FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1", [hash]); return undefined; }
      const data = this.unseal("session", hash, hard, idle, row.sealed) as Omit<Session, "id" | "expires" | "idleExpires">;
      const actor = data.actor;
      if (Object.hasOwn(data, "id") || !actor || typeof actor.issuer !== "string" || typeof actor.subject !== "string" || typeof actor.user_id !== "string" || typeof actor.tenant_id !== "string" || typeof actor.delegation_id !== "string" || !Array.isArray(actor.permissions) || !actor.permissions.every(value => typeof value === "string") || typeof data.accessToken !== "string" || !data.accessToken || data.accessToken.length > 8192 || typeof data.csrf !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf)) throw new Error("Session record invalid");
      const nextIdle = touch ? Math.min(hard, now + IDLE_MILLISECONDS) : idle;
      if (touch) {
        const sealed = this.seal("session", hash, hard, nextIdle, data);
        await client.query("UPDATE nex_workspace_auth.workspace_session_state SET idle_expires_ms=$1,sealed=$2 WHERE kind='session' AND handle_hash=$3", [nextIdle, sealed, hash]);
      }
      return { id, ...data, expires: hard, idleExpires: nextIdle };
    });
  }
  async close(id: string | undefined): Promise<void> {
    if (!id) return;
    let hash: string;
    try { hash = hashHandle(id); } catch { return; }
    try { await this.pool.query("DELETE FROM nex_workspace_auth.workspace_session_state WHERE handle_hash=$1", [hash]); }
    catch { throw new Error("Session store unavailable"); }
  }
}
