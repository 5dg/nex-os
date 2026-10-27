export type Profile = "development" | "synthetic-qualification";
export function profile(): Profile {
  const value = process.env.NEX_PROFILE || "development";
  if (value !== "development" && value !== "synthetic-qualification") throw new Error("Unsupported workspace profile");
  if (process.env.APP_ENV && process.env.APP_ENV !== "development") throw new Error("Only synthetic workspace profiles are supported");
  if (value === "synthetic-qualification" && process.env.APP_ENV !== "development") throw new Error("Explicit synthetic environment required");
  return value;
}
