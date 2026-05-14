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

## v1.1.0

- Sanitized the environment template defaults and cleaned checked-in run artifacts.
- Standardized the CLI on `--mode agentic` and added regression coverage for the removed `--agentic-mode` flag.
- Added `LICENSE-COMMERCIAL.md`, sample threat-feed ingestion, and `sample_threat_feed.json`.
- Introduced recursive attack taxonomy directories across `attacks/` with visual and encoding payload examples.
- Added the CARTO certification blueprint under `docs/certification/`.
- Implemented an adaptive `AgenticRunner` with iterative requeueing, default `runs/agentic_results.json` output, payload cloaking, and hard-negative mining.
- Polished the launch README with demo video placeholder, sponsorship note, taxonomy links, and updated agentic quick-start guidance.