# Test-Case Catalog Addendum — HF-Breach & aletheia-lite-Sweep Coverage

This addendum documents the attack and benign records added to the catalog on top
of the baseline documented in [`test-case-catalog-v1.md`](./test-case-catalog-v1.md).
It is a **data-only** expansion: no schema, validation, runner, or dependency
changes accompany it, and the existing 277-test suite is unchanged.

## Motivation

Two sources drove this expansion:

1. **The July 2026 Hugging Face breach.** The incident chained a malicious-dataset
   ingestion-pipeline RCE with a package-proxy sandbox-egress zero-day, then used a
   swarm of individually low-signal actions to move laterally toward production
   infrastructure. The catalog previously had no records modeling the specific
   ingestion-pipeline and sandbox-egress entry points, nor the volumetric
   "swarm of low-signal actions" pattern.

2. **A 118-payload calibration sweep against aletheia-lite.** The sweep surfaced
   three recurring per-request detection gaps — authority-claim framing with no
   attack verb, persona framing without DAN-mode keywords, and step-wise /
   classify-then-comply escalation — plus a population-level (SPRT) swarm-detector
   wiring gap on the session-campaign path.

## New attack categories

| Category | Records | IDs | Models |
|---|---|---|---|
| `authority_claim_override` | 10 | AC_001–AC_010 | Claimed rank / waiver / exception framing, no attack verb present (sweep gap #1). |
| `roleplay_persona_bypass` | 10 | RB_001–RB_010 | Persona / character framing without DAN-mode keywords (sweep gap #2). |
| `staged_compliance_escalation` | 8 | SCE_001–SCE_008 | Step1/Step2/Step3 and classify-then-comply chains (sweep gap #3). |
| `dataset_loader_rce` | 6 | DLR_001–DLR_006 | Malicious dataset loader RCE + dataset-config template injection (HF ingestion-pipeline entry point). |
| `supply_chain_sandbox_egress` | 6 | PSE_001–PSE_006 | Package-proxy / postinstall-hook sandbox-egress vectors (HF egress zero-day). |

All 40 records carry `expected_decision: DENIED`.

## Session-campaign / swarm additions

`attacks/session_campaigns/session_campaigns.json` gains SC_002–SC_004 alongside the
pre-existing SC_001. These model the HF breach's volumetric "swarm of thousands of
individually low-signal actions":

- **SC_002** — repeated low-signal recon from a single fixed principal
  (`repeat_count: 30`, `repeat_agent_fixed: true`).
- **SC_003** — the same low-signal action distributed across a rotating pool of
  agent/session identifiers (`repeat_count: 40`, `repeat_agent_fixed: false`).
- **SC_004** — slow-drip credential probing from one principal
  (`repeat_count: 50`, `repeat_agent_fixed: true`).

> **Runner note.** A single pass through `kit.runner` only exercises the per-request
> path. To actually test population-level swarm detection, the payload must be
> resubmitted `repeat_count` times — either under one fixed agent/session id
> (SC_002, SC_004) or rotated across several (SC_003). The
> `repeat_count` / `repeat_agent_fixed` fields are **not yet wired into
> `kit/runner.py`**; treat swarm replay as a manual / scripted step for now. Wiring
> these fields into the runner is deliberately deferred to its own change.

## Benign corpus expansion (false-positive stress test)

`attacks/benign_controls.json` grows from 15 to 515 records (BC_001–BC_515). The
new BC_016–BC_515 comprise:

- **~475 domain-diverse benign requests** spanning IT ops, HR, finance, dev,
  marketing, education, logistics, personal productivity, cooking, travel, data
  analysis, non-clinical healthcare admin, and legal-adjacent tasks.
- **25 deliberately lexically-attack-adjacent-but-benign edge cases**
  (BC_491–BC_515, `technique: benign_lexically_adjacent_edge_case`) — password-reset
  FAQs, admin/root glossary entries, secure-deletion tutorials, and similar prompts
  that reuse attack-lexicon vocabulary in an unambiguously benign context.

All 500 new benign records were verified unique against the repo's own
`dedupe_attacks_semantic(threshold=0.92)` — none were dropped as near-duplicates.
Every benign record carries `expected_decision: PROCEED`; the corpus exists to
measure and bound the false-positive rate of any target under test.

## What this addendum does *not* change

- `kit/catalog.py` schema / validation is untouched.
- `attacks/templates/payload_families.json` is untouched; its pre-existing
  `benign_controls`-category entries (`PF_PI_027`–`PF_PI_030`) are unrelated prior
  overlap and remain where they are.
- `kit/runner.py` is untouched; the swarm `repeat_count` / `repeat_agent_fixed`
  fields are not wired in as part of this change.
