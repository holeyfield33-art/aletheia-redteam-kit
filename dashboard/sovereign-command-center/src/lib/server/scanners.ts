import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { RemediationCard, Severity, SupplyChainFinding, SupplyChainResult } from "@/lib/types";
import { listFilesRecursive } from "@/lib/server/repo";

interface SemgrepIssue {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
  };
}

interface SemgrepResponse {
  results?: SemgrepIssue[];
}

function toSeverity(value: string): Severity {
  const normalized = value.toUpperCase();
  if (normalized.includes("CRIT")) return "CRITICAL";
  if (normalized.includes("HIGH")) return "HIGH";
  if (normalized.includes("MED")) return "MEDIUM";
  return "LOW";
}

function runSemgrep(projectRoot: string): { status: "available" | "missing" | "error"; findings: SupplyChainFinding[] } {
  const check = spawnSync("semgrep", ["--version"], { encoding: "utf8" });
  if (check.status !== 0) {
    return { status: "missing", findings: [] };
  }

  const command = spawnSync(
    "semgrep",
    ["--config", "auto", "--json", projectRoot],
    { encoding: "utf8", maxBuffer: 6 * 1024 * 1024, timeout: 120000 },
  );

  if (command.status !== 0 && !command.stdout) {
    return { status: "error", findings: [] };
  }

  try {
    const parsed = JSON.parse(command.stdout || "{}") as SemgrepResponse;
    const results = Array.isArray(parsed.results) ? parsed.results.slice(0, 40) : [];
    const findings: SupplyChainFinding[] = results.map((result) => ({
      id: `semgrep-${result.check_id}-${result.start?.line ?? 0}`,
      title: result.extra?.message || result.check_id || "Semgrep finding",
      severity: toSeverity(result.extra?.severity || "MEDIUM"),
      file: result.path || "unknown",
      line: result.start?.line,
      engine: "semgrep",
      evidence: result.extra?.lines || "Pattern matched by Semgrep auto rules.",
      remediation: "Refactor affected code path and enforce secure coding pattern in CI policy.",
    }));
    return { status: "available", findings };
  } catch {
    return { status: "error", findings: [] };
  }
}

function runTrufflehog(projectRoot: string): { status: "available" | "missing" | "error"; findings: SupplyChainFinding[] } {
  const check = spawnSync("trufflehog", ["--version"], { encoding: "utf8" });
  if (check.status !== 0) {
    return { status: "missing", findings: [] };
  }

  const command = spawnSync(
    "trufflehog",
    ["filesystem", "--json", projectRoot],
    { encoding: "utf8", maxBuffer: 6 * 1024 * 1024, timeout: 120000 },
  );

  if (command.status !== 0 && !command.stdout) {
    return { status: "error", findings: [] };
  }

  const findings: SupplyChainFinding[] = [];
  const lines = (command.stdout || "").split("\n").filter(Boolean).slice(0, 70);
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      const source = parsed.SourceMetadata?.Data?.Filesystem?.file || "unknown";
      findings.push({
        id: `trufflehog-${parsed.DetectorName}-${findings.length}`,
        title: parsed.DetectorName || "Potential secret",
        severity: "HIGH",
        file: source,
        engine: "trufflehog",
        evidence: String(parsed.Raw || "Potential secret disclosed."),
        remediation: "Move secret to runtime vault, rotate value, and remove literal from repository history.",
      });
    } catch {
      continue;
    }
  }

  return { status: "available", findings };
}

function fallbackEntropyScan(projectRoot: string): SupplyChainFinding[] {
  const files = listFilesRecursive(projectRoot, 1400).filter((item) => {
    return /\.(ts|tsx|js|jsx|py|json|yml|yaml|md|env|txt)$/i.test(item);
  });

  const findings: SupplyChainFinding[] = [];
  const entropyRegex = /(?:sk_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_\-]{32,})/g;

  for (const rel of files) {
    const abs = path.join(projectRoot, rel);
    let content: string;
    try {
      content = fs.readFileSync(abs, "utf8");
    } catch {
      continue;
    }

    const lines = content.split("\n");
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      const line = lines[lineIndex];
      if (line.includes("pragma: allowlist secret") || line.includes("noqa")) {
        continue;
      }
      const matches = line.match(entropyRegex);
      if (!matches) {
        continue;
      }
      for (const match of matches) {
        findings.push({
          id: `entropy-${rel}-${lineIndex + 1}-${match.slice(0, 8)}`,
          title: "Potential hardcoded secret",
          severity: "HIGH",
          file: rel,
          line: lineIndex + 1,
          engine: "fallback-entropy",
          evidence: line.trim().slice(0, 200),
          remediation: "Replace hardcoded token with environment variable and rotate any exposed value.",
        });
      }
      if (findings.length >= 60) {
        return findings;
      }
    }
  }

  return findings;
}

export function runSupplyChainAudit(projectRoot: string): SupplyChainResult {
  const semgrep = runSemgrep(projectRoot);
  const trufflehog = runTrufflehog(projectRoot);
  const fallback = fallbackEntropyScan(projectRoot);

  const findings = [...semgrep.findings, ...trufflehog.findings, ...fallback].slice(0, 120);

  const cards: RemediationCard[] = findings.map((finding) => ({
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    summary: `${finding.file}${finding.line ? `:${finding.line}` : ""} -> ${finding.evidence}`,
    suggestedFix: `# ${finding.engine} remediation\n# Move secret out of source and into secure runtime env\nexport SECRET_NAME=\"<vault-ref>\"\n`,
    source: "supply-chain",
  }));

  return {
    workerStatus: {
      semgrep: semgrep.status,
      trufflehog: trufflehog.status,
    },
    findings,
    cards,
  };
}
