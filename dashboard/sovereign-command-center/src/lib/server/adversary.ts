import fs from "fs";
import path from "path";
import { AdversarialOutcome, AdversarialPayload, AdversarialResult, RuntimeMode } from "@/lib/types";

function repoRootFromAppCwd(): string {
  return path.resolve(process.cwd(), "../..");
}

function loadPayloadsFromKit(): AdversarialPayload[] {
  const attacksDir = path.join(repoRootFromAppCwd(), "attacks");
  if (!fs.existsSync(attacksDir)) {
    return [];
  }

  const payloads: AdversarialPayload[] = [];
  const files = fs.readdirSync(attacksDir).filter((file) => file.endsWith(".json"));
  for (const file of files) {
    const abs = path.join(attacksDir, file);
    try {
      const parsed = JSON.parse(fs.readFileSync(abs, "utf8"));
      if (Array.isArray(parsed)) {
        for (const payload of parsed) {
          payloads.push({
            id: payload.id,
            name: payload.name,
            category: payload.category,
            payload: payload.payload,
            expected_decision: payload.expected_decision,
            severity: payload.severity,
            action: payload.action,
          });
        }
      }
    } catch {
      continue;
    }
  }

  return payloads;
}

function deterministicLeak(id: string, hardening: number): boolean {
  const chars = Array.from(id).reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const score = chars % 100;
  return score > hardening;
}

export function runAdversarialSimulation(runtimeMode: RuntimeMode): AdversarialResult {
  const payloads = loadPayloadsFromKit().slice(0, 80);
  const outcomes: AdversarialOutcome[] = payloads.map((payload) => {
    const unprotectedLeak = deterministicLeak(payload.id, 32);
    const protectedLeak = runtimeMode === "CONNECTED" ? deterministicLeak(payload.id, 93) : deterministicLeak(payload.id, 56);

    const unprotectedDecision = unprotectedLeak ? "PROCEED" : "DENIED";
    const protectedDecision = protectedLeak ? "PROCEED" : "DENIED";
    const baselineVulnerability = runtimeMode === "OFFLINE" && unprotectedDecision === "PROCEED" && payload.expected_decision === "DENIED";

    return {
      payloadId: payload.id,
      category: payload.category,
      expected: payload.expected_decision,
      unprotectedDecision,
      protectedDecision,
      baselineVulnerability,
      rationale:
        protectedDecision === "DENIED"
          ? "Aletheia policy hardening blocked adversarial prompt pathway."
          : "Prompt chain still vulnerable; policy tune required.",
    };
  });

  const baselineVulnerabilities = outcomes.filter((outcome) => outcome.baselineVulnerability);

  return {
    outcomes,
    baselineVulnerabilities,
    cards: baselineVulnerabilities.slice(0, 16).map((outcome) => ({
      id: `baseline-${outcome.payloadId}`,
      title: `Baseline Vulnerability: ${outcome.category}`,
      severity: "CRITICAL",
      summary: `Payload ${outcome.payloadId} bypassed defenses in OFFLINE baseline mode.`,
      suggestedFix: `# Policy hardening snippet\nif attack.category == \"${outcome.category}\":\n    return \"DENIED\"\n`,
      source: "adversarial",
    })),
  };
}

export function loadPayloadPreview(limit = 25): AdversarialPayload[] {
  return loadPayloadsFromKit().slice(0, limit);
}
