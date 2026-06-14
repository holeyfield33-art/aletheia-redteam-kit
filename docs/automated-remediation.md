# Automated Remediation & Active Telemetry

This guide documents the closed-loop remediation runtime: how the kit measures
agentic degradation with real telemetry, turns failed probes into concrete
policy artifacts, and lets an operator approve and persist those artifacts with
one click. Everything here is deterministic and offline-capable — no LLM is
called to generate a fix.

## 1. Telemetry & metrics (real math, no stubs)

Two stdlib-only engines compute the signals that drive calibration and gating:

- **Semantic drift** — `engine/semantic_drift.py`. Each conversation turn is
  tokenized (`\w+`, lowercased) into a term-frequency vector; drift is the
  **maximum cosine distance** (`1 − cosine similarity`) across consecutive turn
  pairs. `compute_semantic_drift(history)` returns `0.0` (identical) … `1.0`
  (orthogonal). `flag_drift_violations(history, threshold=0.7)` returns the
  1-based indices of turns whose drift meets the threshold.
- **Disagreement & override** — `engine/disagreement_metrics.py`.
  `calculate_disagreement_score(outputs)` is the mean **token-level Jaccard
  dissimilarity** across all output pairs (`1 − |A∩B| / |A∪B|`).
  `calculate_override_rate(adjudication_log)` is the fraction of log entries
  where `adjudicated_decision != subsystem_decision`.

### Threshold calibration

`engine/calibration.py` + `scripts/calibrate_thresholds.py` replay the ME / HE /
APH suites (live or from a saved `summary.json`), map the drift / disagreement /
override scores of the **successful bypasses**, and recommend a tuned
`flag_drift_violations` threshold (per-suite **P10 of bypass drift**, with a
must-catch override for subtle drifts and a false-positive guard).

    python scripts/calibrate_thresholds.py --mode offline --summary runs/<dir>/summary.json --suite all

## 2. The probe suites that drive remediation

| Suite | Catalog | IDs | Vectors |
|-------|---------|-----|---------|
| **ME** — multi-encoding | `attacks/encoding/multi_encoding.json` | ME_001–006 | hex, ROT13, URL-encoding, nested base64+ROT13, zero-width separators, homoglyph+base64 |
| **HE** — hallucination exploitation | `attacks/advanced/hallucination_exploitation.json` | HE_001–005 | false authority citation, confidence inflation, fabricated precedent, Socratic drift, sycophancy via false consensus |
| **APH** — agentic planning hijack | `attacks/advanced/agentic_planning_hijack.json` | APH_001–005 | planning-loop sub-goal injection, tool selection override, fake memory history, sub-goal privilege escalation, recursive self-improvement bait |

The fixed hallucination probe families (`false_citation`, `confidence_inflation`,
`fact_fabrication`) used by the security-gate path live in
`kit/probes/hallucination_probe.py`.

## 3. The auto-remediation loop

A **bypass** is any row where `expected_decision == DENIED` but
`actual_decision == PROCEED`. `engine/remediation.py` groups bypasses by
technique and, for each failing technique, emits **one proposal** using a
deterministic template registry (no API/LLM call). Each proposal bundles three
artifacts:

| Artifact | Shape | Purpose |
|----------|-------|---------|
| `system_prompt_constraint` | guardrail clause (string) | appended to `system_prompt_patch.md` |
| `manifest_rule` | `{rule_id, applies_to_technique, decision: "DENY", severity, policy_version, justification}` | rule definition for the signed-manifest enforcement model |
| `zero_trust_policy_entry` | `{family, technique, category, expected_block: true}` | feeds `scripts/run_security_gates.py --zero-trust-policy-file` |

Proposal IDs are a stable hash of the technique (`REM-xxxxxxxx`), so re-running
generation is idempotent. Techniques with curated templates include
`tool_selection_override`, `recursive_self_improvement`, `fabricated_precedent`,
`fake_memory_history`, `sub_goal_poisoning`, `planning_loop_injection`,
`false_authority_citation`, and `encoded_instruction`; everything else falls back
to a generic hard-block template.

### Apply & persistence

`kit/remediation_store.py` persists proposals and, on approval, writes reviewable
artifacts under `<artifact-dir>/remediation/`:

    remediation/
      proposals.json            # proposal state (pending | approved)
      system_prompt_patch.md    # appended constraint clauses
      manifest_rules.json       # { policy_version, rules: [...] }
      zero_trust_policy.json    # { probes: [...] } — consumable by run_security_gates.py

All merges are **idempotent**: zero-trust entries are keyed by technique, manifest
rules by `rule_id`, and prompt clauses are de-duplicated. No pre-existing live
configuration is mutated — these are new, operator-reviewable patch files.

### Headless generation

`scripts/generate_remediation.py` runs the loop offline (from a `summary.json`)
or live (against the target when `ALETHEIA_API_KEY` is set), and can approve in
the same command:

    # Generate proposals from a saved run
    python scripts/generate_remediation.py --summary runs/<dir>/summary.json --artifact-dir runs

    # Generate and immediately approve+apply one proposal
    python scripts/generate_remediation.py --summary runs/<dir>/summary.json --approve REM-8a54442f

## 4. Cryptographic enforcement (NIST-2025-0035)

The kit's receipt trust chain uses **Ed25519**: `kit/verify.py` verifies the
signature on every engine receipt against the published public key
(`/.well-known/aletheia-receipt-key.pem`), and website mode performs the same
live verification.

The remediation engine produces the **manifest rule definitions** (`rule_id`,
`decision: DENY`, `policy_version`, `justification`) that populate the signed
enforcement manifest — providing the empirical, technique-level rule set that the
"Securing AI Agent Systems" (NIST-2025-0035) proposal calls for. To turn that
evidence into a submission dataset, `scripts/export_nist_telemetry.py` +
`engine/nist_export.py` export the adjudication telemetry for the agentic
techniques (e.g. `tool_selection_override`, `recursive_self_improvement_bait`)
and correlate bypasses with receipt **signature state** (signed vs.
unsigned/missing), emitting a hash-stamped JSON + CSV + Markdown dataset.

    python scripts/export_nist_telemetry.py --summary runs/<dir>/summary.json --suite APH HE

> Note: the kit *generates and verifies* — it emits the rule definitions and
> verifies remote Ed25519 receipt signatures. Signing of the assembled manifest
> is performed by the enforcement engine, not by this kit.

## 5. Operator approval in the dashboard

The static command center (`dashboard/index.html`, served by
`kit/dashboard_server.py`) exposes a **Remediation Proposals** panel with a
one-click **Approve & Apply** action. It is backed by two endpoints:

- `GET /api/remediation/proposals` → `{ "proposals": [...] }`
- `POST /api/remediation/approve` with `{ "proposal_id": "REM-…" }` → `202`,
  applies the three artifacts and persists `status: approved`

Both endpoints sit behind the dashboard's existing auth modes (basic / api-key /
proxy). `tests/test_remediation_dashboard.py` boots the real handler on a live
`ThreadingHTTPServer` and exercises the GET/POST flow over HTTP (empty list,
seeded list, approve+apply+persist, `400` on missing id, `404` on unknown id).

> The Next.js command center (`dashboard/sovereign-command-center`) hosts the
> **Attacks launcher** (run by category or all-at-once via `/api/payloads` and
> `/api/launch`). The one-click remediation approval panel currently lives in the
> static dashboard described above.

## 6. CI/CD: gating commits on agentic degradation

`scripts/redteam_gate.py` + `engine/ci_gates.py` run the suites headlessly and
**break the build** on either an override-rate regression (against a baseline
`summary.json`) or a critical must-block leak (e.g. `false_citation`,
`tool_selection_override`). It is wired into `.github/workflows/redteam-gate.yml`
and runs live when `ALETHEIA_API_KEY` is present, skipping cleanly otherwise.

    python scripts/redteam_gate.py --mode offline --suite all --summary runs/<dir>/summary.json
