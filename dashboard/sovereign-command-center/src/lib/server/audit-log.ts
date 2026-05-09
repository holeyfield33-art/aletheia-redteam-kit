import crypto from "crypto";
import { AuditLog, ProjectId, RuntimeMode } from "@/lib/types";

function hashPayload(payload: Record<string, unknown>): string {
  return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

export function createAuditLog(
  projectId: ProjectId,
  runtimeMode: RuntimeMode,
  event: string,
  outcome: "PASS" | "FAIL" | "WARN",
  payload: Record<string, unknown>,
): AuditLog {
  return {
    id: crypto.randomUUID(),
    generatedAt: new Date().toISOString(),
    projectId,
    runtimeMode,
    event,
    outcome,
    payload,
    signing: {
      status: "pending",
      algorithm: "ed25519",
      canonicalPayloadHash: hashPayload(payload),
      vaultTarget: "mneme",
    },
  };
}
