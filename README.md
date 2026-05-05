# aletheia-redteam-kit

Adversarial test kit for the [Aletheia](https://aletheia-core.com) AI security
API. Fires ~100 attacks at the hosted engine and produces a cryptographically
signed receipt for every decision.

## What it does

1. Loads ~100 adversarial payloads from `attacks/*.json`
   (prompt injection, data exfiltration, tool abuse, jailbreak, policy evasion,
   plus 10 benign controls).
2. Sends each payload to `https://api.aletheia-core.com/v1/audit`.
3. Records the signed receipt the engine returns for every decision.
4. Writes `summary.json` with full results, per-category stats, and signatures.
5. Renders a static dashboard (`dashboard/index.html`) that reads the JSON.
6. Can run a website UI audit mode to crawl routes and probe buttons/tabs,
   writing `website_summary.json` findings.

Receipts also appear in your Aletheia dashboard at
[app.aletheia-core.com](https://app.aletheia-core.com) automatically - every
API call is logged on the engine side under your tenant.

## Setup (60 seconds)

    git clone https://github.com/holeyfield33-art/aletheia-redteam-kit
    cd aletheia-redteam-kit
    pip install -e .
    cp .env.example .env
    # edit .env, paste your API key from https://app.aletheia-core.com/keys
    export $(cat .env | xargs)
    python -m kit.runner

Open `dashboard/index.html` in a browser.

## Running against a self-hosted Aletheia

Set `ALETHEIA_BASE_URL`:

    ALETHEIA_BASE_URL=https://aletheia.your-company.internal python -m kit.runner

## Website UI audit mode (routes/buttons/tabs)

Install optional browser dependency and browser binary:

    pip install -e ".[web]"
    playwright install chromium

If browser runtime libraries are missing in your environment:

    python -m playwright install-deps chromium

Run website mode:

    python -m kit.runner --mode website --target-url https://example.com

This writes `website_summary.json` (or `--output`) with route and interaction
findings, severity totals, required-route checks, and gate evaluation.

When the Playwright browser backend cannot start (for example due to missing
system libraries), the runner automatically falls back to an HTTP route-only
audit backend and records this in `audit_backend` and `backend_warning`.

Disable fallback to require browser-mode only:

    python -m kit.runner --mode website --target-url https://example.com --no-browser-fallback

Custom finding rules (Phase 2 item 1):

        cat > rules.json <<'JSON'
        [
            {
                "name": "Debug token leak",
                "pattern": "debug-token",
                "target": "body",
                "severity": "HIGH",
                "expected": "Debug markers are not exposed in production"
            },
            {
                "name": "Admin route discovered",
                "pattern": "/admin($|/)",
                "target": "url",
                "match": "regex",
                "severity": "MEDIUM"
            }
        ]
        JSON

        python -m kit.runner --mode website --target-url https://example.com --rules-file rules.json

Rule fields:

- `name` (required): human-readable rule name
- `pattern` (required): substring or regex to detect
- `target` (optional): one of `body`, `url`, `title`, `headers` (default `body`)
- `match` (optional): `contains` or `regex` (default `contains`)
- `case_sensitive` (optional): boolean (default `false`)
- `severity` (optional): `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` (default `MEDIUM`)
- `type` (optional): finding type string (default `custom_rule`)
- `title` (optional): custom finding title
- `expected` (optional): expected secure state string

Authenticated multi-step workflows (Phase 2 item 2):

        cat > auth_flow.json <<'JSON'
        [
            { "action": "goto", "url": "/login" },
            { "action": "fill", "selector": "input[name='email']", "value": "user@example.com" },
            { "action": "fill", "selector": "input[name='password']", "value": "REPLACE_ME" },
            { "action": "click", "selector": "button[type='submit']" },
            { "action": "wait_for_url", "url": "/dashboard", "timeout_ms": 12000 }
        ]
        JSON

        python -m kit.runner --mode website \
            --target-url https://example.com \
            --auth-workflow-file auth_flow.json \
            --auth-seed-url /dashboard \
            --auth-seed-url /settings

Auth step actions:

- `goto`: navigate to `url` (relative or absolute)
- `fill`: fill `selector` with `value`
- `click`: click `selector`
- `wait_for_selector`: wait until `selector` appears
- `wait_for_url`: wait for final `url`

If browser mode is unavailable and HTTP fallback is used, auth workflows cannot be executed; the summary will include an `auth_failure` finding and `auth.error = "auth_workflow_requires_browser_backend"`.

## Verifying receipt signatures

    pip install -e ".[verify]"
    python -c "from kit.verify import verify_summary; \
               print(verify_summary('summary.json'))"

## What this kit doesn't do

- Run a local Aletheia engine (use the hosted one).
- Provide a gateway, database, or middleware (none needed).
- Probe non-Aletheia targets (that's Phase 2).
- Generate PDF reports (Phase 2).

## License

MIT.
