import { notFound } from "next/navigation";
import { profile } from "../../lib/profile.ts";
import Laboratory from "./Laboratory";
export const dynamic = "force-dynamic";
export default function LaboratoryPage() { if (profile() !== "development") notFound(); return <Laboratory />; }
