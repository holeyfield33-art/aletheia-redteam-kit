# Command Center Dashboard

This project dashboard is designed as an operator command center for API, website, repo, and combined security runs.

## Launch

Open `dashboard/index.html` in your browser.

Combined artifacts (`mode = combined`) can be loaded directly and switched between API/website/repo components using the Component filter.

## Primary Operator Workflow

1. Run one or more API scans with `python -m kit.runner`.
2. Run repository scan with `python -m kit.runner --mode repo --repo-path . --output repo_summary.json`.
3. Optionally run unified sweep with `python -m kit.runner --mode combined --target-url https://example.com --repo-path . --output combined_summary.json`.
4. Optionally attach a threat feed with `--threat-feed-file threat_feed.json` to enrich repo findings.
5. Keep baseline artifacts in `runs/index.json` and load history via Auto-scan.
6. Triage weak categories using the Mission Priority Board.
7. Filter to actionable rows using Command Filters and Quick Actions.
8. Export filtered rows to hand off incidents or create follow-up attack expansions.

## Command Filters

- Category filter: scope rows to one attack family.
- Decision filter: adapts by summary type.
API: `DENIED`, `PROCEED`, `UNKNOWN`, `ERROR`.
Website/repo: severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Mismatches only: show policy misses only.
- Search: free text over id, name, category, reason, and error fields.

## Quick Actions

- Focus Weakest Category:
  - Automatically selects the category with the lowest match rate.
  - Enables mismatch-only view for fast triage.
- Show Empty-200 Anomalies:
  - Filters to rows with empty JSON HTTP 200 response behavior.
  - Sets decision filter to `UNKNOWN`.
- Export Filtered JSON:
  - Downloads currently filtered rows as `filtered_results.json`.
- Show Repo Critical+High:
  - Enables mismatch-only view for repository findings.
  - Fast focus for exploitable hotspot triage.
- Export Repo Hotspots:
  - Downloads repo `CRITICAL`/`HIGH` findings as `repo_hotspots.json`.

## Mission Priority Board

The board ranks categories by low match rate and unknown-decision pressure.
Use it to prioritize:

- prompt_injection
- jailbreak
- policy_evasion

before lower-risk or already-stable families.

## Regression and Anomaly Panels

- Regression panel shows high-risk baseline/current block rates and drop percent.
- Mutation panel shows attempts/bypasses per mutation strategy.
- Gap Analysis panel highlights top bypass-prone techniques.

## Interpretation Guidance

- `UNKNOWN` decisions are safety-biased classifications for anomalous transport behavior.
- High `empty_200_anomalies` indicates API contract instability or edge-layer response stripping.
- Treat unknown/anomaly spikes as operational incidents, not model performance wins.
