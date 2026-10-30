import { constants, closeSync, fstatSync, openSync, readSync } from "node:fs";
import type { WorkspaceConfig } from "./trust.ts";
import { createProductionOidcPolicy, type OidcProductionInputs, type OidcProductionPolicy } from "./production-oidc-policy.ts";

type State = { path: string | undefined; policy: OidcProductionPolicy | undefined };
let state: State | undefined;

// Config is snapshotted once per process; replacing its contents requires a
// coordinated restart. Changing the configured path while running is rejected.
// Never silently drop or reload assurance after a session has been created.
export function configuredProductionOidcPolicy(config: WorkspaceConfig): OidcProductionPolicy | undefined {
  const path = process.env.NEX_OIDC_ASSURANCE_POLICY_FILE;
  if (state) {
    if (state.path !== path) throw new Error("Identity policy configuration changed");
    return state.policy;
  }
  if (path === undefined) { state = { path: undefined, policy: undefined }; return undefined; }
  let fd: number | undefined;
  try {
    if (!path) throw new Error("invalid");
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.geteuid?.() || ![0o400, 0o600].includes(info.mode & 0o777) || (info.mode & 0o7000) !== 0 || info.size < 1 || info.size > 16 * 1024) throw new Error("invalid");
    const bytes = Buffer.alloc(16 * 1024 + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (!count) break;
      used += count;
    }
    if (!used || used > 16 * 1024) throw new Error("invalid");
    const input: unknown = JSON.parse(bytes.subarray(0, used).toString("utf8"));
    const policy = createProductionOidcPolicy(input as OidcProductionInputs);
    if (policy.issuer !== config.issuerText || policy.clientId !== config.clientID || policy.audience !== process.env.OIDC_AUDIENCE || policy.requiredAccessScope !== process.env.OIDC_REQUIRED_SCOPE || new URL(policy.workspaceOrigin).origin !== config.origin.origin || policy.redirectURI !== config.redirectURI) throw new Error("invalid");
    // Current synthetic transport authorizes only the pinned issuer origin and
    // workload identity. Split-origin providers need a separately reviewed
    // transport and may not be enabled by the policy file alone.
    for (const endpoint of [policy.authorizationEndpoint, policy.tokenEndpoint, policy.jwksURI]) {
      if (new URL(endpoint).origin !== config.issuer.origin) throw new Error("invalid");
    }
    state = { path, policy };
    return policy;
  } catch { throw new Error("Identity policy configuration invalid"); }
  finally { if (fd !== undefined) closeSync(fd); }
}
