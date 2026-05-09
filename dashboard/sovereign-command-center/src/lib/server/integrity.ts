import fs from "fs";
import path from "path";
import { IntegrityResult, RemediationCard } from "@/lib/types";
import { readTextIfPresent } from "@/lib/server/repo";

const REQUIRED_FILES = ["README.md", "pyproject.toml", "audit.py", "attacks", "engine", "kit"];

export function runIntegrityAudit(projectRoot: string): IntegrityResult {
  const missingArtifacts = REQUIRED_FILES.filter((item) => !fs.existsSync(path.join(projectRoot, item)));

  const runsIndex = readTextIfPresent(path.join(projectRoot, "runs", "index.json"));
  const report = readTextIfPresent(path.join(projectRoot, "report.md"));

  const structuralScore = Math.max(0, 100 - missingArtifacts.length * 12);
  const cards: RemediationCard[] = [];

  if (missingArtifacts.length > 0) {
    cards.push({
      id: "integrity-missing-artifacts",
      title: "Missing Structural Artifacts",
      severity: "HIGH",
      summary: `Repository is missing ${missingArtifacts.join(", ")}.`,
      suggestedFix: `# Add missing files/folders\nmkdir -p ${missingArtifacts.filter((item) => !item.includes(".")).join(" ") || "<dir>"}\n`,
      source: "integrity",
    });
  }

  if (!runsIndex) {
    cards.push({
      id: "integrity-scout-log",
      title: "Scout Log Unavailable",
      severity: "MEDIUM",
      summary: "No runs/index.json found; Scout lineage cannot be reconstructed.",
      suggestedFix: `# Generate run index\npython audit.py --mode repo --export-index runs/index.json\n`,
      source: "integrity",
    });
  }

  if (!report) {
    cards.push({
      id: "integrity-judge-log",
      title: "Judge Log Unavailable",
      severity: "LOW",
      summary: "No report.md found; human-readable Judge assessment is missing.",
      suggestedFix: `# Regenerate report\npython audit.py --mode combined --report report.md\n`,
      source: "integrity",
    });
  }

  return {
    structuralScore,
    missingArtifacts,
    scoutLogSummary: runsIndex ? "runs/index.json detected and parseable." : "Scout index missing.",
    judgeLogSummary: report ? "report.md available for parity checks." : "Judge report missing.",
    cards,
  };
}
