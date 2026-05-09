import fs from "fs";
import path from "path";
import { ProjectId, RuntimeMode, SovereignAuditReport } from "@/lib/types";
import { resolveProjectRoot } from "@/lib/server/repo";
import { runIntegrityAudit } from "@/lib/server/integrity";
import { runSupplyChainAudit } from "@/lib/server/scanners";
import { runNarrativeAudit } from "@/lib/server/readme-auditor";
import { runAdversarialSimulation } from "@/lib/server/adversary";
import { createAuditLog } from "@/lib/server/audit-log";

function calculateConfidence(
  integrityScore: number,
  supplyFindings: number,
  narrativeFindings: number,
  baselineVulnerabilities: number,
): number {
  const penalty = supplyFindings * 1.6 + narrativeFindings * 1.2 + baselineVulnerabilities * 2.4;
  return Math.max(1, Math.min(99, Math.round(integrityScore - penalty)));
}

function buildGueK1Series(runtimeMode: RuntimeMode, confidence: number): number[] {
  if (runtimeMode === "OFFLINE") {
    return [];
  }
  const seed = confidence;
  const values: number[] = [];
  for (let i = 0; i < 20; i += 1) {
    const wobble = Math.sin((seed + i) / 2.7) * 4 + Math.cos((seed + i) / 7.3) * 2;
    values.push(Math.max(10, Math.min(99, Math.round(confidence + wobble))));
  }
  return values;
}

export function runSovereignAudit(projectId: ProjectId, runtimeMode: RuntimeMode): SovereignAuditReport {
  const projectRoot = resolveProjectRoot(projectId);

  const logs = [
    createAuditLog(projectId, runtimeMode, "audit.init", "PASS", {
      projectRoot,
      runtimeMode,
      exists: fs.existsSync(projectRoot),
    }),
  ];

  if (!fs.existsSync(projectRoot)) {
    const emptyReport: SovereignAuditReport = {
      generatedAt: new Date().toISOString(),
      projectId,
      runtimeMode,
      integrity: {
        structuralScore: 0,
        missingArtifacts: ["Project root unreachable"],
        scoutLogSummary: "Unavailable",
        judgeLogSummary: "Unavailable",
        cards: [
          {
            id: "project-root-missing",
            title: "Project Root Missing",
            severity: "CRITICAL",
            summary: `Configured path '${projectRoot}' is not mounted.`,
            suggestedFix: "Update project switcher mapping to a valid mounted repository path.",
            source: "integrity",
          },
        ],
      },
      supplyChain: {
        workerStatus: { semgrep: "missing", trufflehog: "missing" },
        findings: [],
        cards: [],
      },
      narrative: {
        parityScore: 0,
        findings: [
          {
            id: "narrative-unavailable",
            severity: "HIGH",
            title: "Narrative Scan Unavailable",
            detail: "Project root unavailable.",
            suggestedFix: "Mount the target repository and rerun narrative scan.",
          },
        ],
        cards: [],
      },
      adversarial: {
        outcomes: [],
        baselineVulnerabilities: [],
        cards: [],
      },
      gueK1Series: [],
      confidenceScore: 1,
      logs: logs.concat(
        createAuditLog(projectId, runtimeMode, "audit.project.unreachable", "FAIL", { projectRoot }),
      ),
    };
    return emptyReport;
  }

  const integrity = runIntegrityAudit(projectRoot);
  logs.push(
    createAuditLog(projectId, runtimeMode, "audit.integrity", integrity.structuralScore >= 85 ? "PASS" : "WARN", {
      structuralScore: integrity.structuralScore,
      missingArtifacts: integrity.missingArtifacts,
    }),
  );

  const supplyChain = runSupplyChainAudit(projectRoot);
  logs.push(
    createAuditLog(projectId, runtimeMode, "audit.supply_chain", supplyChain.findings.length ? "WARN" : "PASS", {
      findingCount: supplyChain.findings.length,
      workerStatus: supplyChain.workerStatus,
    }),
  );

  const narrative = runNarrativeAudit(projectRoot);
  logs.push(
    createAuditLog(projectId, runtimeMode, "audit.narrative", narrative.findings.length ? "WARN" : "PASS", {
      parityScore: narrative.parityScore,
      findingCount: narrative.findings.length,
    }),
  );

  const adversarial = runAdversarialSimulation(runtimeMode);
  const baselineVulnerabilities = adversarial.baselineVulnerabilities.length;
  logs.push(
    createAuditLog(projectId, runtimeMode, "audit.adversarial.pre_connection", baselineVulnerabilities ? "FAIL" : "PASS", {
      outcomes: adversarial.outcomes.length,
      baselineVulnerabilities,
    }),
  );

  for (const outcome of adversarial.outcomes.slice(0, 40)) {
    logs.push(
      createAuditLog(
        projectId,
        runtimeMode,
        "audit.adversarial.payload",
        outcome.protectedDecision === "DENIED" ? "PASS" : "FAIL",
        {
          payloadId: outcome.payloadId,
          category: outcome.category,
          expected: outcome.expected,
          unprotectedDecision: outcome.unprotectedDecision,
          protectedDecision: outcome.protectedDecision,
          baselineVulnerability: outcome.baselineVulnerability,
        },
      ),
    );
  }

  const confidenceScore = calculateConfidence(
    integrity.structuralScore,
    supplyChain.findings.length,
    narrative.findings.length,
    baselineVulnerabilities,
  );

  const report: SovereignAuditReport = {
    generatedAt: new Date().toISOString(),
    projectId,
    runtimeMode,
    integrity,
    supplyChain,
    narrative,
    adversarial,
    gueK1Series: buildGueK1Series(runtimeMode, confidenceScore),
    confidenceScore,
    logs,
  };

  const outputDir = path.join(projectRoot, "runs", "sovereign-command-center");
  fs.mkdirSync(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, `audit-${Date.now()}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf8");

  return report;
}
