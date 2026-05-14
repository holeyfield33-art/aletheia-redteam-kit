# Changelog

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