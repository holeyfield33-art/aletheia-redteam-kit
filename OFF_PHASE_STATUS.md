# Off-Phase Status — RETIRED

> **This document is retired as of 2026-06-18 and no longer reflects the codebase.**
> Kept for historical context only. Do not treat its launch decision as current.

## Why this was retired

The original no-go (2026-05-16) was based on a single blocker: the repo security
gate hard-failed in a clean container because `semgrep` was not on PATH.

That blocker no longer exists. The security gate now degrades gracefully when
`semgrep` is missing, exactly as it already did for `trufflehog`:

- `scripts/run_security_gates.py` reports the tool as `unavailable` instead of failing.
- `engine/repo_audit/scanner.py` guards the invocation with `shutil.which`.
- `semgrep` lives only in the optional `full`/`dev` profile, not the default `medium`.

Verified 2026-06-18 in a clean environment (system Python, neither `semgrep` nor
`trufflehog` installed): the gate runs to **exit 0**, and the full suite of 263
tests passes. The kit installs and runs end-to-end offline.

## Current launch blocker (non-technical)

The only remaining hard block is licensing, not execution:

- `LICENSE-COMMERCIAL.md` still contains unfilled placeholders
  (`[DATE]`, `[COMPANY NAME]`, `[JURISDICTION]`). This blocks commercial-license
  *distribution*, not running the kit. The permissive root `LICENSE` (MIT) is in
  place as the interim license.

---

<details>
<summary>Original 2026-05-16 status (historical — superseded)</summary>

Date: 2026-05-16
Branch: feature/dashboard-artifact-quicklinks

Launch decision at the time: No-go, because the repo security gate failed in a
clean container without `semgrep` on PATH. `trufflehog` was already handled
gracefully; `semgrep` was not. The recommended remediation was to make the gate
treat a missing `semgrep` the same way as a missing `trufflehog` — which has
since been done (see above).

Off-phase work completed in that cycle: dashboard launch queue and hosted launch
APIs, bounded launch-log tailing, runner subprocess recursion fix, campaign
planning, agentic runner stop controls and learning artifacts, command-center
normalization of artifact paths, dashboard artifact quick links, graceful
`trufflehog` handling, and regression tests for all of the above.

</details>
