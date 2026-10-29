import type { NextConfig } from "next";
const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // Match the admitted compiler quota instead of serializing host CPU count.
  experimental: { cpus: 2 },
  async generateBuildId() {
    // Canonical builders provide the verified compiler-input identity. This is
    // build metadata only; it never conveys user or workload authority.
    const source = process.env.NEX_SOURCE_INPUT_SHA256;
    if (source === undefined) return null;
    if (!/^[a-f0-9]{64}$/.test(source)) throw new Error("Invalid build source input identity");
    return source;
  },
  async headers() {
    return [{ source: "/:path*", headers: [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Frame-Options", value: "DENY" },
    ] }];
  },
};
export default config;
