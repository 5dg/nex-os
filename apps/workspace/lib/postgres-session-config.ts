import { constants, closeSync, fstatSync, openSync, readSync } from "node:fs";
import tls from "node:tls";
import pg from "pg";
import { PostgresSessionStore } from "./postgres-sessions.ts";

function privateFile(variable: string, limit: number): Buffer {
  const path = process.env[variable];
  if (!path) throw new Error("Session configuration invalid");
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.geteuid?.() || (info.mode & 0o400) === 0 || (info.mode & 0o7177) !== 0 || info.size < 1 || info.size > limit) throw new Error("invalid");
    const bounded = Buffer.alloc(limit + 1);
    try {
      let used = 0;
      while (used < bounded.length) {
        const count = readSync(fd, bounded, used, bounded.length - used, null);
        if (!count) break;
        used += count;
      }
      if (used < 1 || used > limit) throw new Error("invalid");
      return Buffer.from(bounded.subarray(0, used));
    } finally { bounded.fill(0); }
  } catch { throw new Error("Session configuration invalid"); }
  finally { if (fd !== undefined) closeSync(fd); }
}

function publicCA(path: string): Buffer {
  const limit = 512 * 1024;
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const info = fstatSync(fd);
    if (!info.isFile() || info.size < 1 || info.size > limit) throw new Error("invalid");
    const bytes = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (!count) break;
      used += count;
    }
    if (!used || used > limit) throw new Error("invalid");
    return bytes.subarray(0, used);
  } catch { throw new Error("Session configuration invalid"); }
  finally { if (fd !== undefined) closeSync(fd); }
}

export function createPostgresSessionStore(): PostgresSessionStore {
  try {
    const rawURL = privateFile("NEX_SESSION_DB_URL_FILE", 4096);
    let target: URL;
    try { target = new URL(rawURL.toString("utf8").trim()); } finally { rawURL.fill(0); }
    const keys = [...target.searchParams.keys()];
    if (!['postgres:', 'postgresql:'].includes(target.protocol) || !target.hostname || target.hostname !== process.env.NEX_SESSION_DB_HOST || !target.username || !target.password || target.hash || keys.length !== 1 || keys[0] !== 'sslmode' || target.searchParams.get('sslmode') !== 'verify-full') throw new Error("invalid");
    const database = decodeURIComponent(target.pathname.slice(1));
    if (!database || database.length > 63 || /[\/\x00-\x1f]/.test(database)) throw new Error("invalid");
    const user = decodeURIComponent(target.username), password = decodeURIComponent(target.password);
    if (!user || user.length > 63 || !password || password.length > 1024 || /[\x00-\x1f]/.test(user + password)) throw new Error("invalid");
    const caPath = process.env.NEX_SESSION_DB_CA_FILE;
    if (!caPath) throw new Error("invalid");
    const ca = publicCA(caPath);
    tls.createSecureContext({ ca, minVersion: "TLSv1.2" });
    const key = privateFile("NEX_SESSION_ENCRYPTION_KEY_FILE", 32);
    try {
      if (key.length !== 32 || key.every(value => value === 0)) throw new Error("invalid");
      const pool = new pg.Pool({ host: target.hostname, port: target.port ? Number(target.port) : 5432, database, user, password,
        ssl: { ca, servername: target.hostname, rejectUnauthorized: true, minVersion: "TLSv1.2" },
        options: "-c search_path=pg_catalog",
        max: 4, connectionTimeoutMillis: 3000, idleTimeoutMillis: 30_000,
        statement_timeout: 3000, lock_timeout: 2000, idle_in_transaction_session_timeout: 10_000 });
      return new PostgresSessionStore(pool, key);
    } finally { key.fill(0); }
  } catch { throw new Error("Session configuration invalid"); }
}
