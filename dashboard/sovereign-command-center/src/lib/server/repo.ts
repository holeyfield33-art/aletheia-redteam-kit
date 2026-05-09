import fs from "fs";
import path from "path";
import { getProjectConfig } from "@/lib/projects";
import { ProjectId } from "@/lib/types";

export function resolveProjectRoot(projectId: ProjectId): string {
  const cfg = getProjectConfig(projectId);
  return cfg.repoPath;
}

export function fileExists(rootPath: string, relPath: string): boolean {
  const abs = path.resolve(rootPath, relPath);
  return fs.existsSync(abs);
}

export function readTextIfPresent(absPath: string): string {
  if (!fs.existsSync(absPath)) {
    return "";
  }
  return fs.readFileSync(absPath, "utf8");
}

export function listFilesRecursive(rootPath: string, maxFiles = 1600): string[] {
  const results: string[] = [];
  const skipDirs = new Set([
    ".git",
    "node_modules",
    ".next",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "runs",
    "__pycache__",
  ]);

  function walk(current: string): void {
    if (results.length >= maxFiles) {
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) {
        return;
      }
      if (entry.name.startsWith(".")) {
        if (entry.name !== ".github") {
          continue;
        }
      }
      const absolute = path.join(current, entry.name);
      const rel = path.relative(rootPath, absolute);
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) {
          continue;
        }
        walk(absolute);
      } else if (entry.isFile()) {
        results.push(rel);
      }
    }
  }

  walk(rootPath);
  return results;
}
