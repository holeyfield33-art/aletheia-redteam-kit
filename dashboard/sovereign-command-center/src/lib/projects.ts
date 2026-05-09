import path from "path";
import { ProjectId } from "@/lib/types";

export interface ProjectConfig {
  id: ProjectId;
  name: string;
  repoPath: string;
  runtimeEndpoint: string;
}

const workspaceRoot = path.resolve(process.cwd(), "../..");

export const PROJECTS: ProjectConfig[] = [
  {
    id: "aletheia-core",
    name: "Aletheia-Core",
    repoPath: workspaceRoot,
    runtimeEndpoint: "http://localhost:8080/runtime",
  },
  {
    id: "unitarity-lab",
    name: "Unitarity-Lab",
    repoPath: "/workspaces/unitarity-lab",
    runtimeEndpoint: "http://localhost:8090/runtime",
  },
  {
    id: "revenueforge",
    name: "RevenueForge",
    repoPath: "/workspaces/revenueforge",
    runtimeEndpoint: "http://localhost:8100/runtime",
  },
];

export function getProjectConfig(projectId: ProjectId): ProjectConfig {
  const cfg = PROJECTS.find((project) => project.id === projectId);
  if (!cfg) {
    return PROJECTS[0];
  }
  return cfg;
}
