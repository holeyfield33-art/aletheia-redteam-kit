# Changelog

## Unreleased — Active Remediation Runtime

- **Real telemetry**: `engine/semantic_drift.py` computes drift as the maximum cosine distance between consecutive turns' term-frequency vectors; `engine/disagreement_metrics.py` computes token-level Jaccard dissimilarity and the adjudication override rate. No stubbed zero-values.
- **Threshold calibration**: `engine/calibration.py` + `scripts/calibrate_thresholds.py` replay the ME/HE/APH suites and recommend a tuned `flag_drift_violations` threshold from observed bypass drift (per-suite P10 with must-catch override and false-positive guard).
- **Headless CI gate**: `engine/ci_gates.py` + `scripts/redteam_gate.py` (workflow `.github/workflows/redteam-gate.yml`) break the build on override-rate regressions or critical must-block leaks (e.g. `false_citation`, `tool_selection_override`).
- **NIST-2025-0035 telemetry export**: `engine/nist_export.py` + `scripts/export_nist_telemetry.py` emit a hash-stamped JSON/CSV/Markdown dataset correlating agentic bypasses with receipt signature state (signed vs. unsigned/missing).
- **Auto-remediation loop**: `engine/remediation.py` turns each failing technique into a deterministic, template-generated proposal (no LLM) bundling a system-prompt constraint, a `DENY` manifest rule, and a zero-trust policy entry. `kit/remediation_store.py` persists them idempotently under `<artifact-dir>/remediation/` as `system_prompt_patch.md`, `manifest_rules.json`, and `zero_trust_policy.json` (the last consumable by `run_security_gates.py`).
- **Dashboard approval**: `kit/dashboard_server.py` adds `GET /api/remediation/proposals` and `POST /api/remediation/approve`; the static dashboard gains a one-click **Approve & Apply** panel. Live HTTP flow covered by `tests/test_remediation_dashboard.py`.
- **Expanded suites**: `multi_encoding` now ME_001–006 (adds zero-width separator and homoglyph+base64 vectors).
- Documentation: added [docs/automated-remediation.md](docs/automated-remediation.md) and updated the README to reflect the active runtime.

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