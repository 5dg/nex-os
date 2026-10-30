export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { assertStartup } = await import("./lib/trust.ts");
    assertStartup();
    if (process.env.NEX_SESSION_BACKEND === "postgres") {
      const { sessions } = await import("./lib/sessions.ts");
      const store = sessions();
      if (!("readiness" in store)) throw new Error("Session configuration invalid");
      await store.readiness();
    }
  }
}
