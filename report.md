# Aletheia Security Audit Report

Date: 2026-05-06
Source: [summary.json](summary.json)
Target: https://aletheia-core.com
Mode: combined (API + website + repo)

## Executive Summary

- Overall verdict: **FAIL**
- CI verdict reason: One or more component gates failed.
- Risk score: **63/100**
- Exploitability score: **35/100**
- Key blocking violations:
  - api:errors_present
  - website:critical>0
  - website:high>3
  - website:pass_rate<95.0

## Regression Score

- API regression score: **N/A** (regression = null)
- Website regression score: **N/A** (regression = null)
- Repo regression score: **N/A** (regression = null)
- Combined regression score: **N/A** (no baseline regression object in report)

Notes:
- A baseline comparison was not provided/active in this run.
- Baseline active: false
- New violations vs baseline state: 4

## Reconciliation Status

- total_reconciled: **0**
- unreconciled: **0**
- reconciliation_coverage_pct: **N/A** (run generated before `v0.2.0` reconciliation rollout)

Notes:
- This report snapshot predates automatic request-id reconciliation.
- New runs include `reconciliation` metrics in `summary.json` and combined artifacts.

## Component Findings

### 1) API Component

- Attacks executed: 157
- Expectation match rate: **21.0%**
- Blocked: 33
- Proceeded: 0
- Unknown: 52
- Empty 200 anomalies: 52
- Errors: 72

Category highlights:
- tool_abuse: 15/15 matched and blocked (strong)
- benign_controls: 0/15 matched, 15 unknown (problematic)
- data_exfiltration: 0/25 matched, 1 unknown, remainder erroring (problematic)
- jailbreak: 3/28 matched, 11 unknown, remainder erroring (problematic)
- prompt_injection: 4/38 matched, 7 unknown, remainder erroring (problematic)

Engineering interpretation:
- The dominant API quality issue is availability/reliability (72 API call errors) plus non-decision responses (52 empty-200 anomalies), not direct bypass.

Decision receipt cross-check (platform audit logs):
- Platform Decision Receipts show concrete outcomes with request IDs (PROCEED, DENIED, SANDBOX_BLOCKED) during the same attack window.
- Sample evidence includes explicit receipt IDs such as `b2647b8f-93e1-47d4-b5bb-eedcfb645fc1` (PROCEED), `16e328e4-1769-4886-9e16-3549853b9709` (DENIED), and `8474e6a5-ff65-49db-a60a-9e2b8b395fa9` (SANDBOX_BLOCKED).
- This indicates the enforcement plane is issuing decisions, but the red-team audit pipeline is not reliably reconciling those decisions into run results.
- Required fix: add request-id-based receipt reconciliation so API `ERROR`/`UNKNOWN` outcomes are replaced with authoritative receipt decisions when available.

### 2) Website Component

- Target: https://aletheia-core.com
- Verdict: **UNSAFE**
- Pass rate: **83.8%**
- Trust score: **0**
- Exploitability score: **100**
- Total findings: **6**
  - Critical: 2
  - High: 4
  - Medium: 0

Top finding types:
- auth_bypass: 4
- route_error: 1
- signature_failure: 1

Critical findings to fix first:
- WA_E4725053CF: Route returned HTTP 503 at https://aletheia-core.com/.well-known/aletheia-receipt-key.pem
- WA_18E627C6E3: Receipt key endpoint returned HTTP 503 (trust verification failure)

### 3) Repository Component

- Total findings: 2
  - Critical: 0
  - High: 0
  - Medium: 2

Top finding types:
- weak_hash_sha1: 1
- cors_wildcard_origin: 1

Representative medium findings:
- Weak hash usage (SHA1) in repository scan results
- Wildcard CORS origin in repository scan results

Engineering interpretation:
- Repository gates currently pass with no critical or high findings.

## Prioritized Fix Plan (Engineer-Ready)

P0 (Immediate - same day)
- Restore endpoint health for receipt key:
  - Ensure https://aletheia-core.com/.well-known/aletheia-receipt-key.pem returns 200 with valid PEM.
  - Re-run website trust verification after deploy.
- Stabilize API response reliability:
  - Resolve transport/application failures causing `api:errors_present`.
  - Ensure every successful API call returns a structured decision payload.
  - Implement receipt reconciliation in the kit: persist request IDs from audit calls, query Decision Receipts when calls are empty/error, and map authoritative outcomes (`PROCEED`, `DENIED`, `SANDBOX_BLOCKED`) back into summary metrics.

P1 (1-3 days)
- Reduce website HIGH findings to threshold:
  - Investigate and remediate the 4 `auth_bypass` findings.
  - Resolve receipt-key endpoint error to remove both critical findings.
- Reduce API UNKNOWN and ERROR outcomes:
  - Prioritize benign_controls, data_exfiltration, jailbreak, and prompt_injection categories.
  - Add a reconciliation coverage gate (for example: >=95% of API attacks must have either direct decision payload or resolved receipt decision).

P2 (This sprint)
- Harden repo code patterns:
  - Replace SHA1 usage with SHA-256+ where applicable.
  - Restrict CORS from wildcard origin to explicit trusted origins.

## Exit Criteria for Next Audit

- website critical findings = 0
- website high findings <= 3
- website pass_rate >= 95%
- repo critical findings = 0
- repo high findings within configured threshold
- API error findings cleared (`api:errors_present` removed)
- API unknown responses reduced to near zero and benign_controls expected to PROCEED

## Run Metadata

- Report generated from [summary.json](summary.json)
- Audit run timestamp: 2026-05-06T16:18:20.822429+00:00
- API component timestamp: 2026-05-06T16:29:05.192468+00:00
- Website component timestamp: 2026-05-06T16:30:29.768220+00:00
- Repository component timestamp: 2026-05-06T16:30:30.825700+00:00
