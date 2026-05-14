# Sovereign Command Center Data Shapes

This document captures the current dashboard-facing contracts so the redesign can stay fully backward compatible.

## File-Based Inputs

- `summary.json` - canonical run summary for API/combined audits.
- `website_summary.json` - canonical website audit summary.
- `runs/index.json` - run catalog used by the static dashboard and hosted dashboard history views.
- `runs/**/summary.json` - archived run summaries copied by the runner.
- `runs/**/command_center.json` - normalized command-center payload written alongside each run.
- `runs/**/command_center.sqlite` - SQLite database backing drilldown and summary views.

## HTTP API Responses

### `GET /api/health`

Response:

- `ok: boolean`
- `authEnabled: boolean`
- `authMode: "disabled" | "basic" | "api-key" | "proxy"`

### `POST /api/auth/login`

Returns a redirect or JSON error depending on the host page flow. Successful login sets the session cookie.

### `POST /api/auth/logout`

Returns a redirect and clears the session cookie.

### `GET /api/payloads`

Response:

- `payloads: AdversarialPayload[]`
- `total: number`

### `POST /api/test-endpoint`

Request body:

- `singleTarget?: { url: string; method?: string }`
- `batchTargets?: { url: string; method?: string }[]`
- `jsonTargets?: { url: string; method?: string }[]`
- `enableMethodFuzzing: boolean`
- `enableParameterInjection: boolean`
- `payloadCategoryFilter?: string[]`

Response:

- `total: number`
- `results: ApiTestResult[]`

### `POST /api/engine`

Request body:

- `projectId?: ProjectId`
- `runtimeMode?: RuntimeMode`
- `modeSelection?: AuditModeSelection`

Response:

- `SovereignAuditReport`

## Core Type Shapes

### `SovereignAuditReport`

- `generatedAt: string`
- `projectId: ProjectId`
- `runtimeMode: RuntimeMode`
- `integrity: IntegrityResult`
- `supplyChain: SupplyChainResult`
- `narrative: NarrativeResult`
- `adversarial: AdversarialResult`
- `gueK1Series: number[]`
- `confidenceScore: number`
- `logs: AuditLog[]`

### `IntegrityResult`

- `structuralScore: number`
- `missingArtifacts: string[]`
- `scoutLogSummary: string`
- `judgeLogSummary: string`
- `cards: RemediationCard[]`

### `SupplyChainResult`

- `workerStatus.semgrep: "available" | "missing" | "error"`
- `workerStatus.trufflehog: "available" | "missing" | "error"`
- `findings: SupplyChainFinding[]`
- `cards: RemediationCard[]`

### `NarrativeResult`

- `parityScore: number`
- `findings: NarrativeFinding[]`
- `cards: RemediationCard[]`

### `AdversarialResult`

- `outcomes: AdversarialOutcome[]`
- `baselineVulnerabilities: AdversarialOutcome[]`
- `cards: RemediationCard[]`

### `ApiTestResult`

- `id: string`
- `targetUrl: string`
- `method: string`
- `injectionMode: "raw" | "query" | "header" | "body"`
- `statusCode: number`
- `ok: boolean`
- `durationMs: number`
- `severity: Severity`
- `signal: string`
- `payloadId: string`

## Design Notes

- The dashboards should keep consuming the existing file and API contracts as-is.
- New presentation layers may rename labels for operators, but the underlying JSON keys should remain unchanged.
- Any future data model expansion should be additive so historical runs remain readable.