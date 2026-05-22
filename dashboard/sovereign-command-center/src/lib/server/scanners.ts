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

function isIgnoredPath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, "/").toLowerCase();
  return normalized.includes("/node_modules/")
    || normalized.includes("/.next/")
    || normalized.includes("/dist/")
    || normalized.includes("/build/")
    || normalized.includes("/.git/")
    || normalized.startsWith("node_modules/")
    || normalized.startsWith(".next/")
    || normalized.startsWith("dist/")
    || normalized.startsWith("build/");
}

function isLowTrustSecretPath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, "/").toLowerCase();
  return normalized.endsWith(".md")
    || normalized.endsWith(".sample")
    || normalized.endsWith(".example")
    || normalized.endsWith(".env.example")
    || normalized.endsWith(".env.sample")
    || normalized.includes("/docs/")
    || normalized.includes("/examples/")
    || normalized.includes("/tests/")
    || normalized.includes("/test/")
    || normalized.includes("/fixtures/")
    || normalized.includes("/fixture/");
}

function isEnvReferenceLine(line: string): boolean {
  return /\bprocess\.env\b|\bos\.environ\b|\bos\.getenv\b|\bgetenv\b|\$\{[A-Za-z_][A-Za-z0-9_]*\}/.test(line);
}

function isPlaceholderSecret(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return false;
  if (normalized.startsWith("<") && normalized.endsWith(">")) return true;
  return /\byour_[a-z0-9_]*\b|\bchangeme\b|\bplaceholder\b|\bdummy\b|\btest_key\b|\bxxx+\b|\.\.\.|\{\{[^}]+\}\}/i.test(normalized);
}

function extractSecretCandidate(line: string): string {
  const stripped = line.split("#", 1)[0].trim();
  if (!stripped) return "";
  const value = stripped.includes("=") ? stripped.split("=", 2)[1] : stripped.includes(":") ? stripped.split(":", 2)[1] : stripped;
  const quoted = value.match(/['\"]([^'\"]{1,256})['\"]/);
  return (quoted?.[1] || value).trim().replace(/[\s,;]+$/g, "");
}

function secretSeverity(relPath: string, findingType: string, candidate: string): Severity | null {
  if (isPlaceholderSecret(candidate) || isEnvReferenceLine(candidate)) return null;
  if (findingType === "api_key_literal" || findingType === "password_literal") {
    return isLowTrustSecretPath(relPath) ? "LOW" : "HIGH";
  }
  if (findingType === "private_key_block") {
    return isLowTrustSecretPath(relPath) ? "LOW" : "CRITICAL";
  }
  if (isLowTrustSecretPath(relPath)) return "LOW";
  const mixed = /[A-Za-z]/.test(candidate) && /[0-9]/.test(candidate) && /[_\-+/=]/.test(candidate);
  const entropy = new Set(candidate).size;
  return mixed && entropy >= 12 ? "HIGH" : "LOW";
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
    const results = Array.isArray(parsed.results)
      ? parsed.results.filter((result) => !result.path || !isIgnoredPath(result.path)).slice(0, 40)
      : [];
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
    return /\.(ts|tsx|js|jsx|py|json|yml|yaml|md|env|txt)$/i.test(item) && !isIgnoredPath(item);
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
      if (isEnvReferenceLine(line)) {
        continue;
      }
      const matches = line.match(entropyRegex);
      if (!matches) {
        continue;
      }
      for (const match of matches) {
        if (isPlaceholderSecret(match)) {
          continue;
        }
        findings.push({
          id: `entropy-${rel}-${lineIndex + 1}-${match.slice(0, 8)}`,
          title: "Potential hardcoded secret",
          severity: isLowTrustSecretPath(rel) ? "LOW" : "HIGH",
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
