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
