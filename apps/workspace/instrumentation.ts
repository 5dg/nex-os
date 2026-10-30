export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { assertStartup } = await import("./lib/trust.ts");
    assertStartup();
    const { profile } = await import("./lib/profile.ts");
    if (profile() === "synthetic-qualification") {
      const { workspaceConfig } = await import("./lib/trust.ts");
      const { configuredProductionOidcPolicy } = await import("./lib/production-oidc-config.ts");
      configuredProductionOidcPolicy(workspaceConfig());
    } else if (process.env.NEX_OIDC_ASSURANCE_POLICY_FILE !== undefined) {
      throw new Error("Identity policy configuration invalid");
    }
    if (process.env.NEX_SESSION_BACKEND === "postgres") {
      const { sessions } = await import("./lib/sessions.ts");
      const store = sessions();
      if (!("readiness" in store)) throw new Error("Session configuration invalid");
      await store.readiness();
    }
  }
}
