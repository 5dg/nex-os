export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { assertStartup } = await import("./lib/trust.ts");
    assertStartup();
  }
}
