import type { Metadata } from "next";
import "./style.css";
export const metadata: Metadata = { title: "Nex.os · Governance workspace", description: "Synthetic-data governance foundation" };
export default function Layout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
