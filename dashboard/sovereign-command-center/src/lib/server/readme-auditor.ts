import fs from "fs";
import path from "path";
import { NarrativeFinding, NarrativeResult, RemediationCard } from "@/lib/types";

const PATH_TOKEN = /(?:\.?\/?[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_.-]+)+)/g;

function normalizeSeverity(value: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (value >= 4) return "HIGH";
  if (value >= 2) return "MEDIUM";
  return "LOW";
}

export function runNarrativeAudit(projectRoot: string): NarrativeResult {
  const readmePath = path.join(projectRoot, "README.md");
  if (!fs.existsSync(readmePath)) {
    const finding: NarrativeFinding = {
      id: "narrative-readme-missing",
      severity: "HIGH",
      title: "README Missing",
      detail: "README.md is missing, so documentation parity cannot be evaluated.",
      suggestedFix: "Create README.md with setup, runbook, and verification commands.",
    };
    return {
      parityScore: 0,
      findings: [finding],
      cards: [
        {
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          summary: finding.detail,
          suggestedFix: "# README bootstrap\ncat > README.md <<'EOF'\n# Project\nEOF\n",
          source: "narrative",
        },
      ],
    };
  }

  const readme = fs.readFileSync(readmePath, "utf8");
  const tokens = Array.from(new Set(readme.match(PATH_TOKEN) ?? []));

  const findings: NarrativeFinding[] = [];

  for (const token of tokens) {
    if (token.startsWith("http://") || token.startsWith("https://")) {
      continue;
    }
    const normalized = token.replace(/^\.\//, "").replace(/[:.,;!?]+$/, "");
    const absolute = path.resolve(projectRoot, normalized);
    if (!fs.existsSync(absolute)) {
      findings.push({
        id: `ghost-${normalized}`,
        severity: "MEDIUM",
        title: "Ghost Command/Path",
        detail: `README references '${normalized}' but the path does not exist.`,
        ghostCommand: normalized,
        suggestedFix: `Update README path or create '${normalized}'.`,
      });
    }
  }

  const commandMentions = (readme.match(/\b(npm|python|pytest|uv|pip)\b/g) ?? []).length;
  const parityPenalty = Math.min(70, findings.length * 10);
  const parityScore = Math.max(20, 100 - parityPenalty - (commandMentions === 0 ? 20 : 0));

  const cards: RemediationCard[] = findings.map((finding) => ({
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    summary: finding.detail,
    suggestedFix: `# README parity fix\n# Replace or remove stale reference: ${finding.ghostCommand ?? "<ghost-path>"}\n`,
    source: "narrative",
  }));

  if (commandMentions === 0) {
    const severity = normalizeSeverity(findings.length);
    findings.push({
      id: "narrative-no-command-context",
      severity,
      title: "README Lacks Execution Narrative",
      detail: "No executable command context found in README; operator onboarding risk is high.",
      suggestedFix: "Add install, run, and verification commands with explicit expected outputs.",
    });
    cards.push({
      id: "narrative-no-command-context",
      title: "README Execution Narrative Missing",
      severity,
      summary: "README should include reproducible run commands.",
      suggestedFix: "```bash\npython audit.py --mode combined\npytest -q\n```",
      source: "narrative",
    });
  }

  return {
    parityScore,
    findings,
    cards,
  };
}
