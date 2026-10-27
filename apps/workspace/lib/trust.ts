import "reflect-metadata";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";
import https from "node:https";
import tls from "node:tls";
import { SubjectAlternativeNameExtension, X509Certificate as ParsedCertificate } from "@peculiar/x509";
import { profile } from "./profile.ts";

const URI_PREFIX = "spiffe://nex.local/service/";
export type Role = "workspace" | "control" | "oidc";
export function certificateRole(raw: Uint8Array): string {
  // Parse the DER extension. Human-readable subjectAltName text can contain
  // quoted DNS values that look like URI entries and is never an identity API.
  const der = new Uint8Array(raw.byteLength); der.set(raw);
  const certificate = new ParsedCertificate(der.buffer);
  if (certificate.extensions.filter(extension => extension.type === "2.5.29.17").length !== 1) throw new Error("One unambiguous SAN extension required");
  const names = certificate.getExtension(SubjectAlternativeNameExtension)?.names.items || [];
  const identities = names.filter(name => name.type === "url").map(name => name.value);
  if (identities.length !== 1 || !/^spiffe:\/\/nex\.local\/service\/[a-z]+$/.test(identities[0])) throw new Error("One exact workload URI required");
  return identities[0];
}
export function assertPeerIdentity(raw: Uint8Array, peer: Role, hostname: string): X509Certificate {
  const certificate = new X509Certificate(Buffer.from(raw));
  assertCertificateTime(certificate);
  if (certificateRole(certificate.raw) !== URI_PREFIX + peer || !certificate.checkHost(hostname, { subject: "never", wildcards: false })) throw new Error("Exact service URI and DNS identity required");
  return certificate;
}
export function assertCertificateTime(certificate: X509Certificate, now = Date.now()): void {
  const start = Date.parse(certificate.validFrom), end = Date.parse(certificate.validTo);
  if (!Number.isFinite(start) || !Number.isFinite(end) || now < start || now >= end) throw new Error("Workload certificate is outside its validity period");
}
function pemCertificates(bytes: Buffer): X509Certificate[] {
  if (bytes.length > 128 * 1024) throw new Error("Certificate input exceeds limit");
  const text = bytes.toString("utf8"), blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  if (!blocks.length || blocks.length > 8 || text.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g, "").trim()) throw new Error("Invalid certificate chain");
  return blocks.map(block => new X509Certificate(block));
}
function verifyOwnChain(leaf: X509Certificate, intermediates: X509Certificate[], roots: X509Certificate[]): void {
  const visit = (current: X509Certificate, seen: Set<string>): boolean => {
    assertCertificateTime(current);
    if (seen.has(current.fingerprint256)) return false;
    if (roots.some(root => root.fingerprint256 === current.fingerprint256)) return current.ca;
    if (seen.size > 8) return false;
    const next = new Set(seen); next.add(current.fingerprint256);
    return [...intermediates, ...roots].some(issuer => issuer.ca && current.checkIssued(issuer) && current.verify(issuer.publicKey) && visit(issuer, next));
  };
  if (!visit(leaf, new Set())) throw new Error("Workspace certificate is not issued by the configured trust");
}
export type WorkspaceConfig = {
  origin: URL; issuer: URL; issuerText: string; redirectURI: string;
  clientID: string; audience: string; scope: string; secret: string;
  control: URL; ca: Buffer; cert: Buffer; key: Buffer; own: X509Certificate;
};
let configuration: WorkspaceConfig | undefined;
function file(name: string, limit = 128 * 1024): Buffer {
  const path = process.env[name]; if (!path) throw new Error("Required workspace trust file missing");
  const bytes = readFileSync(path); if (!bytes.length || bytes.length > limit) throw new Error("Invalid workspace trust file"); return bytes;
}
function url(name: string, hosts: string[]): URL {
  const value = process.env[name]; if (!value) throw new Error("Required workspace endpoint missing");
  const result = new URL(value);
  if (result.protocol !== "https:" || !hosts.includes(result.hostname) || result.username || result.password || result.search || result.hash || result.pathname !== "/") throw new Error("Endpoint is outside the synthetic trust profile");
  return result;
}
export function workspaceConfig(): WorkspaceConfig {
  if (profile() !== "synthetic-qualification") throw new Error("Authenticated workspace profile required");
  if (configuration) return configuration;
  try {
    const origin = url("WORKSPACE_ORIGIN", ["workspace.nex.test"]);
    const issuer = url("OIDC_ISSUER", ["issuer.nex.test"]);
    const control = url("CONTROL_URL", ["control", "control.nex.test"]);
    const clientID = process.env.OIDC_CLIENT_ID, audience = process.env.OIDC_AUDIENCE;
    const scope = process.env.OIDC_REQUIRED_SCOPE;
    if (clientID !== "nex-workspace" || audience !== "nex-api" || scope !== "nex:access") throw new Error("Explicit fixture token profile required");
    const redirectURI = origin.origin + "/auth/callback";
    if (process.env.OIDC_REDIRECT_URI !== redirectURI) throw new Error("Exact registered callback required");
    const ca = file("NEX_TLS_CA_FILE"), cert = file("NEX_TLS_CERT_FILE"), key = file("NEX_TLS_KEY_FILE", 64 * 1024);
    const chain = pemCertificates(cert), roots = pemCertificates(ca), own = chain[0];
    if (own.ca || certificateRole(own.raw) !== URI_PREFIX + "workspace") throw new Error("Workspace identity required");
    verifyOwnChain(own, chain.slice(1), roots);
    const actual = createPublicKey(createPrivateKey(key)).export({ type: "spki", format: "der" });
    if (!actual.equals(own.publicKey.export({ type: "spki", format: "der" }))) throw new Error("Workspace key does not match certificate");
    tls.createSecureContext({ ca, cert, key, minVersion: "TLSv1.3" });
    const secret = file("OIDC_CLIENT_SECRET_FILE", 4096).toString("utf8").trim();
    if (secret.length < 16 || /[\r\n\0]/.test(secret)) throw new Error("Confidential fixture client secret required");
    configuration = { origin, issuer, issuerText: process.env.OIDC_ISSUER!, redirectURI, clientID, audience, scope, secret, control, ca, cert, key, own };
    return configuration;
  } catch { throw new Error("Workspace trust configuration is invalid"); }
}
export function assertStartup(): void { if (profile() === "synthetic-qualification") workspaceConfig(); }
export function requireCanonicalHost(request: Request): void {
  if (request.headers.get("host")?.toLowerCase() !== workspaceConfig().origin.host) throw new Error("Canonical workspace host required");
}
export function requireOrigin(request: Request): void {
  requireCanonicalHost(request);
  if (request.headers.get("origin") !== workspaceConfig().origin.origin) throw new Error("Same-origin request required");
}

type VerifiedRequestInit = { method?: string; headers?: HeadersInit; signal?: AbortSignal | null; body?: unknown };
export async function verifiedRequest(target: URL, peer: "control" | "oidc", init: VerifiedRequestInit = {}, limit = 128 * 1024): Promise<Response> {
  const config = workspaceConfig();
  const expected = peer === "control" ? config.control.origin : config.issuer.origin;
  if (target.origin !== expected || target.username || target.password || target.protocol !== "https:" || target.hash) throw new Error("Unexpected service destination");
  assertCertificateTime(config.own);
  let body: Buffer | undefined;
  if (init.body instanceof URLSearchParams) body = Buffer.from(init.body.toString());
  else if (typeof init.body === "string" || init.body instanceof Uint8Array) body = Buffer.from(init.body);
  else if (init.body != null) throw new Error("Unsupported service request body");
  if (body && body.length > 128 * 1024) throw new Error("Service request exceeds limit");
  const headers = new Headers(init.headers);
  if (init.body instanceof URLSearchParams && !headers.has("Content-Type")) headers.set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
  if (body) headers.set("Content-Length", String(body.length));
  return new Promise<Response>((resolve, reject) => {
    let peerCertificate: X509Certificate | undefined;
    const request = https.request(target, {
      method: init.method || "GET", headers: Object.fromEntries(headers.entries()),
      ca: config.ca, ...(peer === "control" ? { cert: config.cert, key: config.key } : {}),
      agent: false, minVersion: "TLSv1.3", timeout: 10_000, signal: init.signal ?? undefined,
      checkServerIdentity(host, certificate) {
        const error = tls.checkServerIdentity(host, certificate); if (error) return error;
        try {
          peerCertificate = assertPeerIdentity(certificate.raw, peer, host);
          return undefined;
        } catch { return new Error("Service workload identity denied"); }
      },
    }, response => {
      const chunks: Buffer[] = []; let size = 0;
      response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > limit) { response.destroy(new Error("Service response exceeds limit")); return; } chunks.push(chunk); });
      response.on("error", reject);
      response.on("end", () => {
        try {
          assertCertificateTime(config.own);
          if (!peerCertificate) throw new Error("Missing verified peer identity");
          assertCertificateTime(peerCertificate);
          const out = new Headers();
          for (const [name, value] of Object.entries(response.headers)) if (value !== undefined) out.set(name, Array.isArray(value) ? value.join(", ") : value);
          const status = response.statusCode || 502;
          resolve(new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), { status, headers: out }));
        } catch (error) { reject(error); }
      });
    });
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("Service request timed out")));
    if (body) request.write(body);
    request.end();
  });
}
export async function controlJSON(path: string, accessToken?: string, method = "GET", body?: unknown): Promise<{ response: Response; value: unknown }> {
  const target = new URL(path, workspaceConfig().control);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (accessToken) headers.Authorization = "Bearer " + accessToken;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await verifiedRequest(target, "control", { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
  const value: unknown = await response.json(); return { response, value };
}
