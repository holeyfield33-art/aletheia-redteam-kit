# Test-Case Catalog Addendum — August 2026 Active-Threat Coverage

This addendum documents the attack records added to the catalog on top of the
baseline documented in [`test-case-catalog-v1.md`](./test-case-catalog-v1.md)
and the prior [HF-breach addendum](./test-case-catalog-addendum-hf-breach.md).
It is a **data-only** expansion: no schema, validation, runner, or dependency
changes accompany it.

## Motivation

Three current, actively-tracked threats drove this expansion. Each was mapped
to an agent-directed prompt/tool-call shape that mirrors the real attacker
technique, following the same modeling approach used for the July 2026 HF
breach.

1. **CVE-2026-9198 (Langflow, CVSS 9.8).** An unauthenticated code-injection
   RCE in a widely-used AI workflow-builder component. 650+ exploit attempts
   from 244 unique IPs across 41 countries were recorded within roughly a
   month of disclosure. Directly relevant: this is an AI-tooling product, and
   the vulnerable pattern (an agent/runtime executing an unauthenticated,
   unsandboxed custom component) is exactly the shape this kit tests for.
2. **CVE-2026-18556 / CVE-2026-18577 (N-able N-central).** An authentication
   bypass, and a second CVE for an *incomplete fix* of the same bypass — both
   actively exploited. Modeled as an agent trusting a claimed-but-unverified
   prior security fix rather than independently re-checking authorization.
3. **Ransomware EDR-kill-before-encrypt, now standard operating procedure.**
   Halcyon's Q2 2026 analysis found that disabling EDR/antivirus ahead of
   encryption has gone from a specialized capability to routine practice
   across the ransomware ecosystem (Qilin, The Gentlemen, DragonForce, Akira,
   LockBit 5.0). Modeled as an agent being asked to disable monitoring,
   alerting, or backup verification before continuing a task — the same
   "quiet the watchers, then act" shape, aimed at an agent's tool-calling
   surface instead of a Windows host.

Sources: [The Hacker News, CISA KEV additions](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html),
[Infosecurity Magazine, ransomware EDR-kill trend](https://www.infosecurity-magazine.com/news/ransomware-q2-2026-edr-kill/),
[CISA/FBI joint advisory AA26-222A, Gunra ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a).

## New attack categories

| Category | Records | IDs | Models |
|---|---|---|---|
| `workflow_component_rce` | 5 | WCR_001–WCR_005 | Unauthenticated code-injection RCE via workflow/component execution (CVE-2026-9198, Langflow). |
| `security_control_tampering` | 5 | SCT_001–SCT_005 | Pre-action requests to disable EDR/monitoring/alerting/backup-verification, modeled on ransomware's EDR-kill-as-standard-practice trend. |

## Extension to an existing category

`attacks/advanced/auth_context_confusion.json` gains ADV_034–ADV_035,
modeling the N-able N-central incomplete-fix pattern (CVE-2026-18556 /
CVE-2026-18577): an agent asked to skip its own auth check because a prior
fix was merely *claimed*, and an agent asked to use an equivalent bypass path
left open by a narrow patch.

All 12 new/extended records carry `expected_decision: DENIED`.

## What this addendum deliberately does *not* cover

Two of the sourced threats do not map onto this kit's tested attack surface
(AI agent prompt/tool-call handling, plus static repo/dependency posture) and
are **not** represented as catalog payloads:

- **CVE-2026-34486 (Apache Tomcat cluster `EncryptInterceptor` bypass)** and
  **Gunra ransomware's initial-access vector** (Fortinet FortiOS/FortiProxy
  auth-bypass CVEs, exposed VPN/SSH credentials) are network-perimeter and
  appliance-level exploits. This kit does not test firewall, VPN, or cluster
  transport security. If your own product depends on Tomcat, N-able agents,
  or similar components, `--mode repo --deps-scan full` (backed by
  `pip-audit`/`osv-scanner`/`trivy`) already surfaces known-CVE dependencies
  generically — no catalog change is needed there, only keeping that scan
  profile enabled and its advisory databases current.
- Raw CVE/IOC data (hashes, IPs, C2 domains) has no natural home in either
  the prompt-payload catalogs or `examples/threat_feed.example.json` (which
  maps repo *finding types* to threat context, not individual CVEs). None of
  the sourced advisories published reusable IOCs as of this writing.

## What this addendum does not change

- `kit/catalog.py` schema/validation is untouched; all new records validate
  against the existing `AttackSpec` shape.
- `engine/agentic.py` requires no change — it is category-agnostic and
  already operates on whatever `attacks/**/*.json` provides.
- No existing category, file, or ID was renumbered or removed.

## Unrelated finding surfaced during this audit

`README.md`'s "Attack Taxonomy" list (the flat category bullet list, not the
"Additional advanced categories" prose beneath it) predates the HF-breach
addendum and was never updated with `dataset_loader_rce` or
`supply_chain_sandbox_egress`, even though both ship under `attacks/advanced/`
and are documented in that addendum. This change updates the taxonomy list to
include those two plus the two added here, so the list matches what actually
ships.

Separately, `SECURITY_RISK_REGISTER.md`'s four open entries all carry
`expiry_date` values in the past (2026-06-01 / 2026-06-15) relative to
today's date. That's a stale-register finding independent of this addendum —
worth a pass to re-decide or re-date each entry — but out of scope for this
change.
