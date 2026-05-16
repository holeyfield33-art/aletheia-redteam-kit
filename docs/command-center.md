# Command Center Dashboard

This project dashboard is the operator command center for API, website, repo, and combined security runs.

The UI is currently split into two frontends:

- `dashboard/index.html` - static, fast-loading overview for quick triage and run history.
- `dashboard/sovereign-command-center` - Next.js command center with the primary operator workflow.

## Launch

Open `dashboard/index.html` in your browser.

For a hosted, non-technical workflow, use the built-in server instead:

  python -m kit.runner dashboard --artifact-dir runs --serve --host 0.0.0.0 --port 8080 --auth-mode auto

Then open `http://<host>:8080/dashboard/`.
The hosted dashboard automatically reads the latest run catalog from `/api/runs`, so the operator does not need to drag files into the page.
When auth is enabled, browser users are redirected to `/login`, API clients can use the configured header mode, and `/api/health` remains unauthenticated for health checks.

Combined artifacts (`mode = combined`) can be loaded directly and switched between attack/website/repository surfaces using the surface filter.

## Sovereign Command Center (Next.js)

An additional operator UI exists at `dashboard/sovereign-command-center`.

Launch:

  cd dashboard/sovereign-command-center
  npm install
  npm run dev

Then open `http://localhost:3000`.

Sovereign API testing workflow:

1. Initialize workspace so payload categories are loaded.
2. Go to `Attack Lab` in the sidebar.
3. Set either single endpoint URL, batch URLs, or import JSON targets.
4. Toggle method fuzzing and parameter injection as needed.
5. Select payload categories to scope attack families, or keep default to use all.
6. Run tests and inspect result severity, status, and response signal.
7. Export endpoint test results as JSON for handoff.

Sovereign overview workflow:

1. Open the `Overview` tab for risk score, block rate, attack visibility, and latest run time.
2. Use `Runs` to inspect historical artifacts and run-level status.
3. Open `Launch` when you want to start a new run from the browser.
4. Use `Settings` for auth and export configuration.

## Primary Operator Workflow

1. Run one or more API scans with `python -m kit.runner`.
2. Run repository scan with `python -m kit.runner --mode repo --repo-path . --output repo_summary.json`.
3. Audit a public GitHub repo with `python -m kit.runner --mode repo --repo-url https://github.com/example/public-repo --output repo_summary.json`.
4. Optionally run unified sweep with `python -m kit.runner --mode combined --target-url https://example.com --repo-path . --output combined_summary.json`.
5. Write artifacts into `runs/` so the hosted dashboard can discover them automatically.
6. Start the hosted dashboard server and share the browser URL with the operator.
7. From the dashboard, paste a public GitHub repo URL into the launch field to queue a repo audit without leaving the browser.
8. Preferred browser-login mode: set `ALETHEIA_DASHBOARD_USERNAME`, `ALETHEIA_DASHBOARD_PASSWORD_HASH`, and `ALETHEIA_DASHBOARD_SESSION_SECRET` before launching the hosted dashboard server.
9. Backward-compatible browser-login mode: set `ALETHEIA_DASHBOARD_USERNAME` and `ALETHEIA_DASHBOARD_PASSWORD`; the server hashes it in memory and warns that `ALETHEIA_DASHBOARD_PASSWORD_HASH` is preferred.
10. Optional API key mode: set `ALETHEIA_DASHBOARD_API_KEY_HASH` and launch with `--auth-mode api-key`.
11. Optional reverse-proxy mode: set `ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH=true` and forward `X-Forwarded-User` or `Authorization` headers from nginx, Caddy, or Traefik.
12. Optionally attach a threat feed with `--threat-feed-file threat_feed.json` to enrich repo findings.
13. Keep baseline artifacts in `runs/index.json` and load history via Auto-scan.
14. Triage weak categories using the Mission Priority Board.
15. Filter to actionable rows using Command Filters and Quick Actions.
16. Export filtered rows to hand off incidents or create follow-up attack expansions.
17. Review API reconciliation coverage before closing transport/anomaly incidents.

## Current Attack Types

Current attack categories used by API and combined runs:

- `agent_conflict`
- `benign_controls`
- `context_poisoning`
- `data_exfiltration`
- `economic_pressure`
- `embedding_evasion`
- `encoding`
- `hybrid_tool`
- `jailbreak`
- `memory_poisoning`
- `multi_turn`
- `obfuscated`
- `policy_evasion`
- `prompt_injection`
- `session_campaigns`
- `side_channel`
- `tool_abuse`
- `visual_renderer`

## Audit Types Performed

The command center supports these run types:

- `api`: payload-driven model attack audit.
- `website`: browser route and UI control audit.
- `repo`: static repository security and supply-chain audit.
- `combined`: API + website + repo in one gated run.
- `agentic`: iterative autonomous adversarial loop.

## Secure Exposure

Recommended production settings:

- Use `ALETHEIA_DASHBOARD_PASSWORD_HASH` or `ALETHEIA_DASHBOARD_API_KEY_HASH` instead of plaintext secrets.
- Set `ALETHEIA_DASHBOARD_SESSION_SECRET` to a 32-byte random value.
- Keep `ALETHEIA_DASHBOARD_SECURE_COOKIES=true` when serving over HTTPS.
- Leave `/api/health` unauthenticated for liveness checks; protect all other dashboard and `/api/*` routes.
- Put the server behind TLS termination and optionally a reverse proxy that forwards `X-Forwarded-User`.

Docker compose example:

```yaml
services:
  dashboard:
    image: python:3.12-slim
    working_dir: /workspace
    command: >
      sh -lc "pip install . && python -m kit.runner dashboard --artifact-dir runs --serve --host 0.0.0.0 --port 8080 --auth-mode auto"
    environment:
      ALETHEIA_DASHBOARD_PASSWORD_HASH: ${ALETHEIA_DASHBOARD_PASSWORD_HASH}
      ALETHEIA_DASHBOARD_SESSION_SECRET: ${ALETHEIA_DASHBOARD_SESSION_SECRET}
      ALETHEIA_DASHBOARD_SECURE_COOKIES: "true"
    volumes:
      - .:/workspace
    ports:
      - "8080:8080"
```

Direct Next.js serving follows the same env vars and protects routes through `src/proxy.ts` plus route-level checks.

## Command Filters

- Surface filter: scope rows to attack, website, or repository results.
- Decision filter: adapts by summary type.
API: `DENIED`, `PROCEED`, `UNKNOWN`, `ERROR`.
Website/repo: severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Mismatches only: show policy misses only.
- Search: free text over id, name, category, reason, and error fields.

## Quick Actions

- Highlight weak spots:
  - Automatically selects the category with the lowest match rate.
  - Enables mismatch-only view for fast triage.
- Show unverified 200s:
  - Filters to rows with empty JSON HTTP 200 response behavior.
  - Sets decision filter to `UNKNOWN`.
- Export filtered JSON:
  - Downloads currently filtered rows as `filtered_results.json`.
- Show critical + high:
  - Enables mismatch-only view for repository findings.
  - Fast focus for exploitable hotspot triage.
- Export weak spots:
  - Downloads repo `CRITICAL`/`HIGH` findings as `repo_hotspots.json`.

## Mission Priority Board

The board ranks categories by low match rate and unknown-decision pressure.
Use it to prioritize:

- prompt_injection
- jailbreak
- policy_evasion

before lower-risk or already-stable families.

## Regression and Anomaly Panels

- Regression panel shows baseline/current block rates and drop percent.
- Mutation panel shows attempts/bypasses per mutation strategy.
- Defense Weak Spots panel highlights top bypass-prone techniques.

## Reconciliation Signals

For API and combined artifacts, review the `reconciliation` object:

- `total_reconciled`: count of previously `UNKNOWN`/`ERROR` rows resolved from saved decisions
- `reconcilable_total`: rows eligible for automated reconciliation from receipts/log APIs
- `unreconciled`: unresolved rows that still need operator investigation
- `reconciliation_coverage_pct`: coverage percentage for reconcilable rows
- `unreconciled_request_ids`: concrete IDs for escalation and dashboard traceability
- `skipped_request_ids`: IDs that require operator-authenticated lookup and are excluded from automated coverage

Coverage policy:

- API runs enforce reconciliation coverage when errors are present.
- Auth-gated receipt endpoints do not count against automated coverage; they are surfaced in `skipped_request_ids`.
- Coverage below 95% surfaces `api:reconciliation_coverage_below_threshold`.

## Interpretation Guidance

- `UNKNOWN` decisions are safety-biased classifications for anomalous transport behavior.
- Reconciled `UNKNOWN`/`ERROR` rows should be treated as authoritative enforcement outcomes.
- High `empty_200_anomalies` indicates API contract instability or edge-layer response stripping.
- Treat unknown/anomaly spikes as operational incidents, not model performance wins.
