// This policy validates explicit configuration and already-verified OIDC
// assertions. It does not perform discovery, fetch keys or enable a production
// profile. The caller must cryptographically verify the ID token and nonce.
// Allowed ACR values and AMR meanings must be approved against the selected
// issuer's documented MFA semantics; their names alone cannot prove assurance.
export type OidcProductionInputs = {
  issuer: string; clientId: string; audience: string; requiredAccessScope: string;
  authorizationScopes: readonly string[]; workspaceOrigin: string; redirectURI: string;
  authorizationEndpoint: string; tokenEndpoint: string; jwksURI: string;
  allowedAcr: readonly string[]; requiredAmr: readonly string[]; maxAuthAgeSeconds: number;
};
export type OidcProductionPolicy = Readonly<OidcProductionInputs>;
export type OidcActor = { issuer: unknown; subject: unknown; user_id: unknown; tenant_id: unknown; delegation_id: unknown; permissions: unknown };
function identifier(value: unknown, maximum = 256): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && /^[\x21-\x7e]+$/.test(value);
}
function scopeWord(value: unknown): value is string {
  return identifier(value) && !/["\\]/.test(value);
}
function httpsURL(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2048 || value.trim() !== value) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !!parsed.hostname && !parsed.username && !parsed.password && !parsed.hash && !parsed.search;
  } catch { return false; }
}
function distinctList(values: unknown, validate: (value: unknown) => boolean, limit = 32): values is string[] {
  return Array.isArray(values) && values.length <= limit && values.every(value => validate(value)) && new Set(values).size === values.length;
}
function multifactorAmr(values: readonly string[]): boolean {
  if (values.includes("mfa")) return true;
  const groups = [
    ["pwd", "pin"],
    ["otp", "sms", "hwk", "swk", "fido"],
    ["fpt", "face", "iris", "eye", "vbm"],
  ];
  return groups.filter(group => group.some(value => values.includes(value))).length >= 2;
}
export function createProductionOidcPolicy(input: OidcProductionInputs): OidcProductionPolicy {
  const names = ["issuer", "clientId", "audience", "requiredAccessScope", "authorizationScopes", "workspaceOrigin", "redirectURI", "authorizationEndpoint", "tokenEndpoint", "jwksURI", "allowedAcr", "requiredAmr", "maxAuthAgeSeconds"];
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).length !== names.length || !Object.keys(input).every(name => names.includes(name)) || !httpsURL(input.issuer) || !httpsURL(input.workspaceOrigin) || !httpsURL(input.redirectURI) ||
      !httpsURL(input.authorizationEndpoint) || !httpsURL(input.tokenEndpoint) || !httpsURL(input.jwksURI) ||
      !identifier(input.clientId) || !identifier(input.audience) || !scopeWord(input.requiredAccessScope) ||
      !distinctList(input.authorizationScopes, scopeWord) || input.authorizationScopes.join(" ").length > 1024 || !input.authorizationScopes.includes("openid") || !input.authorizationScopes.includes(input.requiredAccessScope) ||
      !distinctList(input.allowedAcr, identifier) || !distinctList(input.requiredAmr, identifier) ||
      input.allowedAcr.join(" ").length > 1024 ||
      (!input.allowedAcr.length && !multifactorAmr(input.requiredAmr)) ||
      !Number.isSafeInteger(input.maxAuthAgeSeconds) || input.maxAuthAgeSeconds < 1 || input.maxAuthAgeSeconds > 86400) throw new Error("Production identity policy invalid");
  const origin = new URL(input.workspaceOrigin);
  if (origin.pathname !== "/" || new URL(input.redirectURI).href !== new URL("/auth/callback", origin).href) throw new Error("Production identity policy invalid");
  return Object.freeze({ ...input, authorizationScopes: Object.freeze([...input.authorizationScopes]), allowedAcr: Object.freeze([...input.allowedAcr]), requiredAmr: Object.freeze([...input.requiredAmr]) });
}
export function productionAuthorizationRequirements(policy: OidcProductionPolicy): { scope: string; max_age: string; acr_values?: string } {
  return { scope: policy.authorizationScopes.join(" "), max_age: String(policy.maxAuthAgeSeconds), ...(policy.allowedAcr.length ? { acr_values: policy.allowedAcr.join(" ") } : {}) };
}
export function validateProductionDiscovery(policy: OidcProductionPolicy, metadata: Record<string, unknown>): void {
  const includes = (value: unknown, required: string): boolean => Array.isArray(value) && value.length <= 32 && value.every(item => typeof item === "string") && value.includes(required);
  if (!metadata || metadata.issuer !== policy.issuer || metadata.authorization_endpoint !== policy.authorizationEndpoint || metadata.token_endpoint !== policy.tokenEndpoint || metadata.jwks_uri !== policy.jwksURI ||
      !includes(metadata.response_types_supported, "code") || !includes(metadata.code_challenge_methods_supported, "S256") ||
      !includes(metadata.id_token_signing_alg_values_supported, "RS256") || !includes(metadata.token_endpoint_auth_methods_supported, "client_secret_basic")) throw new Error("Production issuer metadata denied");
}
export function validateVerifiedProductionClaims(policy: OidcProductionPolicy, claims: Record<string, unknown>, nowSeconds: number): void {
  // Identity claims must come from a previously signature-, issuer-, audience-,
  // expiry- and nonce-verified ID token. Reject insufficient assurance before
  // performing any authoritative identity lookup.
  if (!claims || !Number.isSafeInteger(nowSeconds) || claims.iss !== policy.issuer || !identifier(claims.sub, 255) ||
      !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.auth_time)) throw new Error("Production identity denied");
  const exp = claims.exp as number, iat = claims.iat as number, authTime = claims.auth_time as number;
  if (exp <= nowSeconds || iat <= 0 || exp <= iat || iat > nowSeconds + 30 || authTime <= 0 || authTime > nowSeconds + 30 || authTime > iat + 30 || nowSeconds - authTime > policy.maxAuthAgeSeconds) throw new Error("Production identity denied");
  if (policy.allowedAcr.length && (typeof claims.acr !== "string" || !policy.allowedAcr.includes(claims.acr))) throw new Error("Production identity denied");
  if (policy.requiredAmr.length && (!distinctList(claims.amr, identifier) || !policy.requiredAmr.every(value => (claims.amr as string[]).includes(value)))) throw new Error("Production identity denied");
}
export function validateVerifiedProductionIdentity(policy: OidcProductionPolicy, claims: Record<string, unknown>, actor: OidcActor, nowSeconds: number): void {
  // Actor must come from /v1/me after control independently verified this
  // exact access token; no identity or authority comes from browser input.
  validateVerifiedProductionClaims(policy, claims, nowSeconds);
  if (!actor || actor.issuer !== claims.iss || actor.subject !== claims.sub || !identifier(actor.user_id) || !identifier(actor.tenant_id) ||
      (actor.delegation_id !== "" && !identifier(actor.delegation_id)) || !distinctList(actor.permissions, identifier, 128)) throw new Error("Production identity denied");
}
