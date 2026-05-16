# Sovereign Command Center

Next.js operator dashboard for local audit execution and adversarial endpoint testing.

## Capabilities

- Combined-mode run controls with per-component selection: API, website, and repo.
- Regular and pre-connection simulation runs through `/api/engine`.
- Inspector workspaces for integrity, supply chain, narrative, and adversarial outcomes.
- API endpoint adversarial testing with:
	- single endpoint URL input
	- batch endpoint input (one URL per line)
	- JSON target upload (`[{ "url": "...", "method": "POST" }]`)
	- HTTP method fuzzing
	- parameter injection modes (query/header/body)
	- payload category filtering sourced from `attacks/*.json`
	- payload category filtering sourced from recursive catalogs under `attacks/**/*.json` (including advanced classes in `attacks/advanced/`)
	- saved test profiles (save/load/delete)
	- result export and clear actions

## Local Development

```bash
cd dashboard/sovereign-command-center
npm install
npm run dev
```

Open `http://localhost:3000`.

## Build and Validate

```bash
npm run lint
npm run build
```

## API Routes

- `POST /api/engine`
	- runs sovereign audit orchestration for selected project/runtime/mode-selection
- `GET /api/payloads`
	- returns payload preview from recursive catalogs under `attacks/**/*.json`
- `POST /api/test-endpoint`
	- runs adversarial endpoint tests and returns normalized result rows

## Notes

- Intended for local/operator environments.
- API endpoint tests can generate high request volume when method fuzzing and injection are both enabled.
- If payload categories are empty in API testing, initialize workspace or run payload refresh first.
