export type ProjectId = "aletheia-core" | "unitarity-lab" | "revenueforge";

export type RuntimeMode = "CONNECTED" | "OFFLINE";

export type AuditMode = "api" | "website" | "repo";

export type WorkspaceTab = "Integrity" | "Supply Chain" | "Narrative" | "Adversarial";

export type SidebarView = "Command" | "Inspector" | "Adversary" | "ApiTesting" | "Mneme";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type AdversarialDecision = "DENIED" | "PROCEED";

export interface RemediationCard {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  suggestedFix: string;
  source: string;
}

export interface IntegrityResult {
  structuralScore: number;
  missingArtifacts: string[];
  scoutLogSummary: string;
  judgeLogSummary: string;
  cards: RemediationCard[];
}

export interface SupplyChainFinding {
  id: string;
  title: string;
  severity: Severity;
  file: string;
  line?: number;
  engine: "semgrep" | "trufflehog" | "fallback-entropy";
  evidence: string;
  remediation: string;
}

export interface SupplyChainResult {
  workerStatus: {
    semgrep: "available" | "missing" | "error";
    trufflehog: "available" | "missing" | "error";
  };
  findings: SupplyChainFinding[];
  cards: RemediationCard[];
}

export interface NarrativeFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  ghostCommand?: string;
  suggestedFix: string;
}

export interface NarrativeResult {
  parityScore: number;
  findings: NarrativeFinding[];
  cards: RemediationCard[];
}

export interface AdversarialPayload {
  id: string;
  name: string;
  category: string;
  payload: string;
  expected_decision: string;
  severity: Severity;
  action: string;
}

export interface AdversarialOutcome {
  payloadId: string;
  category: string;
  expected: string;
  unprotectedDecision: AdversarialDecision;
  protectedDecision: AdversarialDecision;
  baselineVulnerability: boolean;
  rationale: string;
}

export interface AdversarialResult {
  outcomes: AdversarialOutcome[];
  baselineVulnerabilities: AdversarialOutcome[];
  cards: RemediationCard[];
}

export interface SigningEnvelope {
  status: "pending";
  algorithm: "ed25519";
  canonicalPayloadHash: string;
  vaultTarget: "mneme";
}

export interface AuditLog {
  id: string;
  generatedAt: string;
  projectId: ProjectId;
  runtimeMode: RuntimeMode;
  event: string;
  outcome: "PASS" | "FAIL" | "WARN";
  payload: Record<string, unknown>;
  signing: SigningEnvelope;
}

export interface SovereignAuditReport {
  generatedAt: string;
  projectId: ProjectId;
  runtimeMode: RuntimeMode;
  integrity: IntegrityResult;
  supplyChain: SupplyChainResult;
  narrative: NarrativeResult;
  adversarial: AdversarialResult;
  gueK1Series: number[];
  confidenceScore: number;
  logs: AuditLog[];
}

export interface AuditModeSelection {
  api: boolean;
  website: boolean;
  repo: boolean;
}

export interface ApiTestTarget {
  url: string;
  method?: string;
}

export interface ApiTestRequest {
  singleTarget?: ApiTestTarget;
  batchTargets?: ApiTestTarget[];
  jsonTargets?: ApiTestTarget[];
  enableMethodFuzzing: boolean;
  enableParameterInjection: boolean;
  payloadCategoryFilter?: string[];
}

export interface ApiTestResult {
  id: string;
  targetUrl: string;
  method: string;
  injectionMode: "raw" | "query" | "header" | "body";
  statusCode: number;
  ok: boolean;
  durationMs: number;
  severity: Severity;
  signal: string;
  payloadId: string;
}
