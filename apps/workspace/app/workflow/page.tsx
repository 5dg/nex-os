import { profile } from "../../lib/profile.ts";
import Workflow from "./Workflow";
export const dynamic = "force-dynamic";
export default function WorkflowPage() { return <Workflow profile={profile()} />; }
