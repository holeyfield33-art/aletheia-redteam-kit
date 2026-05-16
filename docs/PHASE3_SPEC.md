# Phase 3 Spec

This document defines the interface for the next stage of the red-team kit. It is intentionally specification-only.

## Goals

- Adversary emulation profiles: insider, external, compromised-plugin, poisoned-supplier.
- Differential testing: execute the same attack pack across multiple providers and flag regressions.
- Preserve the current contract that this kit generates and replays attacks; enforcement remains external.

## Proposed Interface

### Emulation Profiles

Each profile will be a JSON object with:

- `profile_id`
- `name`
- `threat_actor`
- `assumed_access`
- `default_probes`
- `default_scenarios`
- `notes`

Profiles are selection-only inputs. They do not modify policy logic.

### Differential Runs

Each differential run will accept:

- `baseline_provider`
- `comparison_provider`
- `attack_pack`
- `probe_pack`
- `scenario_pack`

The run output will include:

- provider-normalized decision counts
- leak regressions
- blast-radius deltas
- evidence trace references
- SARIF export support

### Required Output Fields

- `run_id`
- `profile_id`
- `provider_results`
- `regressions`
- `evidence_root`
- `sarif_path`

## Acceptance Criteria For Implementation

- Same attack pack produces comparable summaries across providers.
- Regresions are flagged when a provider transitions from blocked to leaked.
- Evidence trace format remains JSONL and reproducible.
- Scenario and probe metadata remain OWASP/NIST mapped.

## Non-Goals

- No sanitization layer is added here.
- No enforcement is implemented here.
- No multimodal model support is faked.
