import * as oidc from "openid-client";
import { profile } from "./profile.ts";
import { controlJSON, requireCanonicalHost, requireOrigin, verifiedRequest, workspaceConfig } from "./trust.ts";
import { configuredProductionOidcPolicy } from "./production-oidc-config.ts";
import { productionAuthorizationRequirements, validateProductionDiscovery, validateVerifiedProductionClaims, validateVerifiedProductionIdentity } from "./production-oidc-policy.ts";
import { cookie, cookieHeader, CSRF_HEADER, equalSecret, LOGIN_COOKIE, SESSION_COOKIE, sessions, type Actor, type Session, type SessionAssurance } from "./sessions.ts";

let issuerConfiguration: Promise<oidc.Configuration> | undefined;
async function issuer(): Promise<oidc.Configuration> {
  const config = workspaceConfig();
  // Validate the trusted issuer policy before any discovery or token request,
  // including when the issuer configuration is already cached.
  const policy = configuredProductionOidcPolicy(config);
  if (!issuerConfiguration) {
    issuerConfiguration = oidc.discovery(config.issuer, config.clientID, {
      redirect_uris: [config.redirectURI], response_types: ["code"], id_token_signed_response_alg: "RS256",
    }, oidc.ClientSecretBasic(config.secret), {
      timeout: 5,
      [oidc.customFetch]: (target, options) => verifiedRequest(new URL(target.toString()), "oidc", options, 128 * 1024),
      execute: [oidc.enableNonRepudiationChecks],
    }).then(result => {
      const metadata = result.serverMetadata();
      for (const name of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
        const value = metadata[name];
        if (!value || new URL(value).origin !== config.issuer.origin) throw new Error("Unexpected issuer endpoint");
      }
      if (policy) validateProductionDiscovery(policy, metadata as unknown as Record<string, unknown>);
      return result;
    }).catch(error => { issuerConfiguration = undefined; throw error; });
  }
  return issuerConfiguration;
}
export function noStore(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  const result = new Headers(headers); result.set("Cache-Control", "no-store"); result.set("Vary", "Cookie"); result.set("X-Content-Type-Options", "nosniff"); result.set("Referrer-Policy", "no-referrer");
  return Response.json(value, { status, headers: result });
}
function redirect(location: string, cookies: string[]): Response {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store", "Vary": "Cookie", "Referrer-Policy": "no-referrer" });
  for (const value of cookies) headers.append("Set-Cookie", value);
  return new Response(null, { status: 303, headers });
}
async function authorizedSession(request: Request, mutate: boolean, enforceAssurance: boolean): Promise<Session> {
  requireCanonicalHost(request);
  if (mutate) requireOrigin(request);
  const value = await sessions().get(cookie(request, SESSION_COOKIE));
  if (!value) throw new Error("Session required");
  if (mutate && !equalSecret(request.headers.get(CSRF_HEADER) || "", value.csrf)) throw new Error("CSRF denied");
  if (enforceAssurance) {
    const policy = configuredProductionOidcPolicy(workspaceConfig());
    if (policy) {
      if (!value.assurance) throw new Error("Production identity denied");
      validateVerifiedProductionIdentity(policy, value.assurance as Record<string, unknown>, value.actor, Math.floor(Date.now() / 1000));
    }
  }
  return value;
}
export async function requireSession(request: Request, mutate: boolean): Promise<Session> {
  return authorizedSession(request, mutate, true);
}
export function beginLogin(request: Request): Promise<Response> {
  return (async () => {
    if (profile() !== "synthetic-qualification") return noStore({ code: "NOT_AVAILABLE" }, 404);
    requireCanonicalHost(request);
    if (new URL(request.url).search) return noStore({ code: "INVALID_LOGIN_REQUEST" }, 400);
    const config = await issuer();
    const state = oidc.randomState(), nonce = oidc.randomNonce(), verifier = oidc.randomPKCECodeVerifier();
    const transaction = await sessions().begin(state, nonce, verifier);
    const policy = configuredProductionOidcPolicy(workspaceConfig());
    const requirements = policy ? productionAuthorizationRequirements(policy) : { scope: "openid nex:access" };
    const destination = oidc.buildAuthorizationUrl(config, {
      redirect_uri: workspaceConfig().redirectURI, ...requirements, response_type: "code",
      state, nonce, code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256",
    });
    return redirect(destination.href, [cookieHeader(LOGIN_COOKIE, transaction.id, 300)]);
  })();
}
export async function finishLogin(request: Request): Promise<Response> {
  if (profile() !== "synthetic-qualification") return noStore({ code: "NOT_AVAILABLE" }, 404);
  requireCanonicalHost(request);
  const params = new URL(request.url).searchParams;
  const transactionID = cookie(request, LOGIN_COOKIE);
  const state = params.get("state");
  if (!transactionID || !state || state.length > 256 || params.getAll("state").length !== 1) throw new Error("Login state denied");
  const transaction = await sessions().consume(transactionID, state);
  if (params.getAll("code").length !== 1 || !params.get("code") || params.get("code")!.length > 2048 || params.has("error")) throw new Error("Authorization response denied");
  const callback = new URL(workspaceConfig().redirectURI); callback.search = params.toString();
  const tokens = await oidc.authorizationCodeGrant(await issuer(), callback, { pkceCodeVerifier: transaction.verifier, expectedState: transaction.state, expectedNonce: transaction.nonce, idTokenExpected: true });
  const assertion = tokens.claims();
  if (!assertion || assertion.iss !== workspaceConfig().issuerText || !assertion.sub || typeof assertion.exp !== "number" || tokens.access_token.length > 8192) throw new Error("Login assertion denied");
  const policy = configuredProductionOidcPolicy(workspaceConfig());
  let assurance: SessionAssurance | undefined;
  if (policy) {
    const verified = assertion as unknown as Record<string, unknown>;
    assurance = { iss: verified.iss, sub: verified.sub, iat: verified.iat, exp: verified.exp, auth_time: verified.auth_time, acr: verified.acr, amr: Array.isArray(verified.amr) ? [...verified.amr] : verified.amr };
    validateVerifiedProductionClaims(policy, assurance as Record<string, unknown>, Math.floor(Date.now() / 1000));
  }
  // The resource server validates the access JWT's purpose, signature and
  // current membership. Do not substitute the browser's ID token for it.
  const me = await controlJSON("/v1/me", tokens.access_token);
  if (!me.response.ok) throw new Error("Current membership denied");
  const actor = me.value as Actor;
  if (!actor || actor.issuer !== assertion.iss || actor.subject !== assertion.sub || typeof actor.user_id !== "string" || typeof actor.tenant_id !== "string" || typeof actor.delegation_id !== "string" || !Array.isArray(actor.permissions)) throw new Error("Access and login identity differ");
  // This claim is used only after /me authenticated this exact access JWT.
  const accessClaims = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url").toString("utf8"));
  if (!Number.isSafeInteger(accessClaims.exp) || accessClaims.sub !== actor.subject || accessClaims.iss !== actor.issuer) throw new Error("Access-token session binding denied");
  if (policy && assurance) validateVerifiedProductionIdentity(policy, assurance as Record<string, unknown>, actor, Math.floor(Date.now() / 1000));
  const previous = cookie(request, SESSION_COOKIE); await sessions().close(previous);
  const session = await sessions().open(actor, tokens.access_token, accessClaims.exp * 1000, assertion.exp * 1000, assurance);
  return redirect("/workflow", [cookieHeader(LOGIN_COOKIE, "", 0), cookieHeader(SESSION_COOKIE, session.id, (session.expires - Date.now()) / 1000)]);
}
export async function logout(request: Request): Promise<Response> {
  if (profile() !== "synthetic-qualification") return noStore({ code: "NOT_AVAILABLE" }, 404);
  const value = await authorizedSession(request, true, false);
  await sessions().close(value.id); await sessions().close(cookie(request, LOGIN_COOKIE));
  const headers = new Headers(); headers.append("Set-Cookie", cookieHeader(SESSION_COOKIE, "", 0)); headers.append("Set-Cookie", cookieHeader(LOGIN_COOKIE, "", 0));
  return noStore({ authenticated: false }, 200, headers);
}
export async function sessionView(request: Request): Promise<Response> {
  if (profile() === "development") return noStore({ profile: "development", authenticated: false });
  try {
    const value = await requireSession(request, false);
    return noStore({ profile: "synthetic-qualification", authenticated: true, subject: value.actor.subject, user_id: value.actor.user_id, can_request_review: Boolean(value.actor.delegation_id), can_approve: value.actor.permissions.includes("approval.decide"), csrf_token: value.csrf, expires_at: new Date(value.expires).toISOString() });
  } catch (error) {
    if (error instanceof Error && (error.message === "Session store unavailable" || error.message.startsWith("Session configuration") || error.message.startsWith("Identity policy configuration"))) return noStore({ code: "AUTHENTICATION_UNAVAILABLE" }, 503);
    return noStore({ profile: "synthetic-qualification", authenticated: false }, 401);
  }
}
export function loginFailure(): Response { return noStore({ code: "AUTHENTICATION_FAILED", message: "Sign-in could not be completed. Start a new sign-in attempt." }, 401, { "Set-Cookie": cookieHeader(LOGIN_COOKIE, "", 0) }); }
