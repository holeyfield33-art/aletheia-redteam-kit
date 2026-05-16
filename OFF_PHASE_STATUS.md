# Off-Phase Status

Date: 2026-05-16
Branch: feature/dashboard-artifact-quicklinks

## Launch Decision

No-go for launch.

Reason:
- The repo security gate still fails in a clean container because `semgrep` is not present on PATH.
- `trufflehog` is now handled gracefully, but the gate cannot complete until `semgrep` is available or the gate degrades in the same way.

## Off-Phase Work Completed

- Dashboard launch queue and hosted launch APIs are in place.
- Bounded launch log tailing is implemented.
- Runner subprocess launch recursion is fixed.
- Campaign planning for run preparation is implemented.
- Agentic runner stop controls and learning artifacts are implemented.
- Command-center normalization now records campaign and learning artifact paths.
- Dashboard UI now shows run artifacts and artifact quick links.
- Security gate no longer hard-fails when `trufflehog` is missing.
- Regression tests were added for the new campaign, agentic, command-center, dashboard, and security-gate behavior.

## Remaining Work

- Make the security gate fully portable in a minimal container by handling missing `semgrep` the same way as `trufflehog`, or install `semgrep` in the target environment.
- Decide whether the dashboard quick-link helper should keep the current same-site restriction or add a stricter explicit allowlist for artifact paths.
- If launch readiness is required now, run the security gate in an environment where both `semgrep` and `trufflehog` are installed.