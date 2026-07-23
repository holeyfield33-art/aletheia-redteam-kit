# Changelog

## Unreleased

### Attack corpus coverage expansion (data-only)

Adds HF-breach-modeled and aletheia-lite-sweep-derived test cases. No schema, code, or dependency changes; existing 277 tests unchanged.

- **New attack categories (40 records):**
  - `authority_claim_override` (10) — claimed-rank / waiver / exception framing with no attack verb present; the #1 gap found in a 118-payload sweep against aletheia-lite.
  - `roleplay_persona_bypass` (10) — persona / character framing without DAN-mode keywords; sweep gap #2.
  - `staged_compliance_escalation` (8) — Step1/Step2/Step3 and classify-then-comply chains; sweep gap #3.
  - `dataset_loader_rce` (6) — malicious dataset loader RCE + dataset-config template injection, modeled on the July 2026 Hugging Face breach's ingestion-pipeline entry point.
  - `supply_chain_sandbox_egress` (6) — package-proxy / postinstall-hook sandbox-egress vectors, modeled on the zero-day needed for outbound network access in the same incident.
- **`session_campaigns.json`:** +3 swarm/volumetric records (SC_002–SC_004) modeling the HF breach's "swarm of thousands of individually low-signal actions" and the SPRT swarm-detector wiring gap found in aletheia-lite. The `repeat_count` / `repeat_agent_fixed` fields are documentation for a future runner feature and are not yet wired into `kit/runner.py`.
- **`benign_controls.json`:** 15 → 515 records. ~475 domain-diverse benign requests (IT ops, HR, finance, dev, marketing, education, logistics, personal productivity, cooking, travel, data analysis, healthcare admin, legal-adjacent) plus 25 deliberately lexically-attack-adjacent-but-benign edge cases (password-reset FAQs, admin/root glossary entries, secure-deletion tutorials) as a false-positive stress test. All 500 new records verified unique against `dedupe_attacks_semantic(threshold=0.92)`.
- **Docs:** adds `docs/test-case-catalog-addendum-hf-breach.md`.

## v1.3.0 (Phase 3 — Private Repo & Expanded Scanning)

- **Private repo support**: `run_repo_audit` now accepts `repo_token` (PAT or fine-grained token with `Contents: read` scope). Token is passed via `GIT_ASKPASS` — it never appears in subprocess arguments, logs, or summary output. Also readable from `ALETHEIA_GITHUB_TOKEN` env var.
- **Scan profiles**: Added `--scan-profile` CLI flag with four levels: `light` (secrets + CI + language), `medium` (default, adds dep hygiene + advisories), `full` (medium + semgrep + bandit + trivy + npm-audit), `custom` (arbitrary scanner set from `--scan-profile-file`).
- **Semgrep integration**: `_scan_semgrep()` runs `semgrep --config auto --json` when available; findings normalised to `Finding` dataclass with severity mapping (ERROR→HIGH, WARNING→MEDIUM, INFO→LOW).
- **Bandit integration**: `_scan_bandit()` runs `bandit -r -f json`; severity from `issue_severity` field.
- **Trivy integration**: `_scan_trivy()` runs `trivy fs --format json`; severity from `Vulnerabilities[].Severity`.
- **npm audit integration**: `_scan_npm_audit()` runs `npm audit --json` on repos containing a `package.json`; severity from `vulnerabilities.{pkg}.severity`.
- All four new tool scanners follow the existing `_scan_dependency_advisories()` pattern: return `(list[Finding], dict)` and emit `{"status": "unavailable"}` when the binary is not on `PATH`.
- Added `enabled_scanners` and `scan_profile` fields to repo audit summary output.
- Added `extra_tools` dict to repo audit summary for per-tool execution metadata.
- Runner `_sanitize_legacy_args` now reads `ALETHEIA_GITHUB_TOKEN` into `args.repo_token` when not passed explicitly; token is never forwarded through batch child-process args.
- `_build_batch_target_legacy_args` forwards `--scan-profile` and `--scan-profile-file` to per-target runs.
- Simplified `_run_repo_audit_with_cli_options` — removed brittle `TypeError`-based feature-detection shim; function now has a clean single call site.
- Added 14 new tests covering scan profiles, tool-unavailable fallbacks, token masking, and CLI `--scan-profile` flag wiring.
- Added `dependencies.top_packages` to repo audit summaries so dashboards can surface top vulnerable packages with advisory counts and max severity.
- Updated the static dashboard repo mission board to prioritize vulnerable package remediation targets when dependency advisory data is present.
- Added `dependencies.signals` for explicit malware-suspect and tampering-risk dependency counts plus top suspicious packages.
- Updated command-center normalization and the static dashboard to surface suspicious dependency packages as supply-chain trust events.

## v1.2.0

- Aligned release metadata to v1.2.0 across packaging and launch documentation.
- Hardened hosted dashboard serving defaults to require authentication by default in `--serve` mode.
- Added hosted request throttling (default 30 requests/minute per principal or client IP).
- Improved dashboard safety messaging with explicit TLS and reverse-proxy recommendations.
- Strengthened dashboard input sanitization for user-provided repo URLs and artifact path traversal handling.
- Tightened repo clone safety for public GitHub audits with stricter URL normalization, timeout controls, and bounded clone resource limits.
- Added stricter CLI sanitization for user-supplied JSON configuration paths (rules, auth workflows, prompt tests, threat feeds, and conversation inputs).
- Cleaned checked-in operational artifacts from repository root and `runs/`, and moved reusable examples under `examples/`.
- Expanded README with ethical-use requirements, production launch checklist, and external-target usage guidance.
- Added test coverage for hosted rate limiting, default dashboard auth mode behavior, and stricter repo URL validation/clone timeout handling.
- **Phase 2**: Added `--targets-file` batch execution for `--mode combined`: run API, repo, and website targets in a single sweep with bounded parallel execution, per-target artifact trees, and a merged command-center SQLite.
- Fixed combined-mode SQLite `targets` table count: cleared the default single-target placeholder before appending batch target rows to prevent an off-by-one (N+1) count.
- Fixed `test_repo_audit_can_clone_public_github_repo`: monkeypatched `subprocess.run` now correctly distinguishes `git clone` calls from `pip-audit` calls to avoid `cmd[-1]` collision.
- Updated dashboard meta panel to surface batch progress fields (`batch_mode`, `targets_total`, `targets_completed`, `targets_failed`, `targets_file`) when a targets-file batch summary is loaded.
- Added "Multi-target batch mode" section to README with full examples, output shape description, and field reference.

## v1.1.0

- Sanitized the environment template defaults and cleaned checked-in run artifacts.
- Standardized the CLI on `--mode agentic` and added regression coverage for the removed `--agentic-mode` flag.
- Added `LICENSE-COMMERCIAL.md`, sample threat-feed ingestion, and `sample_threat_feed.json`.
- Introduced recursive attack taxonomy directories across `attacks/` with visual and encoding payload examples.
- Added the CARTO certification blueprint under `docs/certification/`.
- Implemented an adaptive `AgenticRunner` with iterative requeueing, default `runs/agentic_results.json` output, payload cloaking, and hard-negative mining.
- Polished the launch README with demo video placeholder, sponsorship note, taxonomy links, and updated agentic quick-start guidance.