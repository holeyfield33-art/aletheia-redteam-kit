# Command Center Dashboard

This project dashboard is designed as an operator command center for API and website security runs.

## Launch

Open `dashboard/index.html` in your browser.

Note: current dashboard panels are optimized for API and website summaries. Repo-audit summaries (`mode = repo`) are generated for CI and artifact review in this phase and will be promoted into first-class dashboard panels in the next phase.

## Primary Operator Workflow

1. Run one or more API scans with `python -m kit.runner`.
2. Run repository scan with `python -m kit.runner --mode repo --repo-path . --output repo_summary.json`.
3. Keep baseline artifacts in `runs/index.json` and load history via Auto-scan.
4. Triage weak categories using the Mission Priority Board.
5. Filter to actionable rows using Command Filters and Quick Actions.
6. Export filtered rows to hand off incidents or create follow-up attack expansions.

## Command Filters

- Category filter: scope rows to one attack family.
- Decision filter: focus on `DENIED`, `PROCEED`, `UNKNOWN`, or `ERROR`.
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
