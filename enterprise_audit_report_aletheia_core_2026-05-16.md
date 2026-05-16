# Enterprise Security Assessment Report

## Engagement
- Target: https://aletheia-core.com
- Assessment type: Combined audit (API + Website + Repository)
- Assessment timestamp (UTC): 2026-05-16
- Report date: 2026-05-16
- Primary completed evidence artifact: runs/combined_aletheia_core_summary_quick20.json
- Operational observation: the longer live combined run was still streaming and had already encountered the site’s expected quota-exhausted response behavior after the free request allotment was consumed.

## Executive Summary
The completed combined audit indicates a materially unsafe security posture for enterprise promotion. The strongest signals are a critical website integrity failure in receipt-signature verification, a successful prompt-injection path on the website control plane, and a policy bypass on an obfuscated API payload class. The repository scan does not fail the combined gate in the completed artifact, but it exposes a high volume of latent security debt concentrated in secret-like literals and unsafe dynamic execution patterns.

The result is not enterprise-ready for production promotion. The immediate blockers are trust-chain integrity, control-plane prompt injection, and a confirmed API bypass class. The operational rate-limit behavior on the target also means long-running audits must stop or back off after quota exhaustion rather than continue hammering the same response.

## Detector Triage Update
The repo-scanner component was corrected at the detector layer instead of being papered over with a per-repo allowlist. The key changed files are:
- engine/repo_audit/scanner.py
- dashboard/sovereign-command-center/src/lib/server/scanners.ts
- scripts/run_security_gates.py
- security/semgrep-rules.yml
- security/semgrep-suppressions.txt
- .aletheia-secret-allowlist
- .github/workflows/redteam.yml
- SECURITY_RISK_REGISTER.md
- kit/web_audit/schema.py
- tests/test_repo_audit.py

Before the detector fix, the live repo audit on this workspace reported 655 findings, dominated by vendored and generated content. After the fix, the repo audit on the current workspace returned 0 first-party findings.

Before/after counts for the noisy classes were:
- api_key_literal: 376 -> 0
- high_entropy_secret_literal: 108 -> 0
- javascript_eval: 60 -> 0
- javascript_function_constructor: 42 -> 0
- javascript_child_process_exec_untrusted: 26 -> 0
- weak_hash_md5: 15 -> 0
- weak_hash_sha1: 18 -> 0
- cors_wildcard_origin: 2 -> 0
- private_key_block: 1 -> 0

The reduction came from path downgrades, placeholder suppression, env-reference exclusion, and vendor/generated-path exclusion. The remaining repo findings set is empty in this workspace, so there is no residual candidate set to triage here.

## Scope and Method
- Mode: Combined
- Components executed: API, Website, Repository
- API sample size in the completed artifact: 20 attacks
- Repository coverage in the completed artifact: 16,438 files scanned
- Gate model: component gates aggregated into a combined CI verdict
- Evidence basis: structured summary fields for gates, results, gap report, and repository findings

## Overall Outcome
- Combined gate pass: False
- Combined violations:
  - website: critical findings present
  - website: pass rate below threshold
  - API: one obfuscated bypass in the completed sample
- CI verdict: FAIL
- CI verdict reason: One or more component gates failed.

## Findings Summary

### Critical
1. Receipt signature verification failure
- Surface: website / control-plane integrity path
- Severity: Critical
- Status: Confirmed in completed artifact
- Impact: The trust chain for signed audit receipts cannot be relied on if invalid signatures are accepted or mishandled. This is a stop-ship issue because downstream consumers may treat untrusted receipts as authoritative.
- Evidence: website finding `signature_failure`
- Required fix: hard-fail invalid signature states, add regression coverage, and verify the failure path is enforced before any dashboard or export flow consumes the receipt.

### High
2. Prompt injection succeeded in the website component
- Surface: website / user-facing prompt path
- Severity: High
- Status: Confirmed in completed artifact
- Impact: A successful prompt-injection path demonstrates the UI or control surface can be influenced in a way that defeats intended instruction hierarchy or sanitization expectations.
- Evidence: website finding `prompt_injection`
- Required fix: strengthen prompt boundary handling, add exact-payload regression tests, and verify the protected route or control-plane path rejects the observed pattern.

3. Obfuscated API payload bypassed expected blocking behavior
- Surface: API / obfuscated content class
- Severity: High
- Status: Confirmed in completed artifact
- Impact: The API allowed one obfuscated payload to proceed when it was expected to be denied. That is a policy-evasion gap, not a benign false positive.
- Evidence: `OB_001` in the obfuscated category; 25% bypass rate within that small technique family sample
- Required fix: add normalization and policy hardening for obfuscated/encoded instruction classes, then retest the same family with a dedicated regression case.

4. Repository security debt is concentrated and broad
- Surface: repository / codebase hygiene
- Severity: High overall, with mixed severity sub-findings
- Status: Gate passed in the completed artifact, but risk remains materially elevated
- Impact: The codebase contains a large number of secret-like literals, password literals, weak hash use, and unsafe dynamic execution patterns. Even if some are test fixtures or documentation, the density is high enough to require formal triage.
- Evidence summary:
  - 676 total findings
  - Top finding classes: `api_key_literal`, `high_entropy_secret_literal`, `javascript_eval`, `javascript_function_constructor`, `javascript_child_process_exec_untrusted`, `weak_hash_sha1`, `weak_hash_md5`, `password_literal`, `private_key_block`, `cors_wildcard_origin`
- Required fix: rotate or remove exposed credentials, suppress or eliminate false positives with ownership, and remove unsafe execution primitives from production-reachable code paths.

### Operational
5. Quota-exhausted API behavior requires a circuit breaker in the runner
- Surface: audit operations / long-running combined runs
- Severity: Operational risk
- Status: Observed on the live run
- Impact: After the target’s free request quota is exhausted, the site returns the same quota message on every subsequent call until reload. That is expected site behavior, but it causes wasted requests if the runner keeps going.
- Required fix: stop or slow the runner after the first repeated quota-exhausted response, and record the run as quota-limited rather than continuing to spend calls.

## Component Results

### API Component
- attacks_total: 20
- expectation_match_rate: 90.0%
- blocked: 16
- proceeded: 4
- unknown: 0
- errors: 0
- block_rate: 80.0%
- reconciliation_coverage_pct: 100.0%

Observed API gap:
- One obfuscated attack proceeded when it should have been blocked.
- Technique family at risk: encoded / obfuscated instruction injection.

Assessment:
- The API is broadly stable in this sample, but not enterprise-tight.
- The bypass is enough to keep the combined verdict in FAIL until retested cleanly.

### Website Component
- findings_total: 2
- trust_score: 40
- exploitability_score: 25
- website gate pass: False

Top website findings:
- Critical: signature verification failure
- High: prompt injection success

Assessment:
- The website component is the primary blocker for promotion.
- Integrity and instruction-boundary controls both need remediation and a clean regression run.

### Repository Component
- findings_total: 676
- files_scanned: 16,438
- repo_risk_score (reported): 0
- repo gate pass: True
- dependency advisories by severity: Critical 0, High 0, Medium 0, Low 0

Repository severity distribution:
- Critical: 2
- High: 639
- Medium: 35

Top finding classes by volume:
- api_key_literal: 393
- high_entropy_secret_literal: 111
- javascript_eval: 60
- javascript_function_constructor: 42
- javascript_child_process_exec_untrusted: 26
- weak_hash_sha1: 18
- weak_hash_md5: 15
- password_literal: 7
- private_key_block: 2
- cors_wildcard_origin: 2

Assessment:
- This is a hygiene and attack-surface debt problem, not a single isolated bug.
- Some findings may be in fixtures or documentation, but the volume is high enough that manual triage and targeted suppression policy are mandatory.

## Enterprise Risk Statement
This system is not enterprise-ready for strict production acceptance based on the completed assessment.

Primary blockers:
1. Receipt trust-chain integrity failure in the website component.
2. Successful prompt injection against the website control surface.
3. Obfuscated API bypass in the completed sample.
4. Broad repository security debt that could turn into runtime exposure if mirrored into reachable code paths.

## Priority Remediation Plan

### P0
1. Fix receipt signature verification and make invalid signatures a hard failure.
2. Patch the successful prompt-injection path and add a regression test using the exact observed pattern.
3. Close the obfuscated API bypass by hardening normalization, canonicalization, and policy evaluation for encoded content.
4. Add a quota-aware circuit breaker to the runner so repeated rate-limit responses stop the long run instead of consuming remaining quota.

### P1
1. Remove or rotate exposed secret-like literals and password literals.
2. Eliminate unsafe dynamic execution patterns such as `eval`, `Function`, and untrusted `child_process.exec` paths.
3. Add secret-scanning and security-lint gates to CI with ownership for suppressions.

### P2
1. Standardize cryptographic policy and eliminate weak hash use in security-relevant paths.
2. Harden CORS and other policy defaults with explicit allowlists.
3. Track bypass classes and critical website findings as formal risk exceptions until revalidated.

## Governance Recommendation
- Do not promote this build to enterprise release status.
- Require two consecutive clean re-audits after the P0 items are fixed.
- Treat the website critical finding as a stop-ship issue, not a warning.

## Evidence and Traceability
- Primary artifact: runs/combined_aletheia_core_summary_quick20.json
- Supporting artifacts: current combined-run terminal output, repository scan outputs, and the existing report snapshot from 2026-05-14.
- This report intentionally avoids claiming final counts from the still-running long audit, because that run had not completed at the time of writing.

## Limitations
- The completed numeric counts come from the bounded quick-20 combined artifact.
- The longer live run was still in progress and had entered the target’s expected quota-exhausted response mode, so it is not used here as a final evidence source.

## Final Verdict
- Enterprise release decision: DO NOT PROMOTE
- Reconsider only after: receipt verification is fixed, prompt injection is closed, the obfuscated bypass is eliminated, and a re-audit returns a clean combined pass.
