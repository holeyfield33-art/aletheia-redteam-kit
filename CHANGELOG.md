# Changelog

## v1.1.0

- Sanitized the environment template defaults and cleaned checked-in run artifacts.
- Standardized the CLI on `--mode agentic` and added regression coverage for the removed `--agentic-mode` flag.
- Added `LICENSE-COMMERCIAL.md`, sample threat-feed ingestion, and `sample_threat_feed.json`.
- Introduced recursive attack taxonomy directories across `attacks/` with visual and encoding payload examples.
- Added the CARTO certification blueprint under `docs/certification/`.
- Implemented an adaptive `AgenticRunner` with iterative requeueing, default `runs/agentic_results.json` output, payload cloaking, and hard-negative mining.
- Polished the launch README with demo video placeholder, sponsorship note, taxonomy links, and updated agentic quick-start guidance.