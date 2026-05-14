# Public Roadmap

## Current Status

**Latest Release**: `v0.2.1` (May 2026)

## v0.3 Preparation Status

### Command Center Edition Workstream

- [x] Start v0.3 work on a dedicated branch without bumping release metadata early
- [x] Introduce target abstraction groundwork for API-compatible providers
- [x] Add generic OpenAI-compatible target support via profile-based client configuration
- [ ] Expand payload scale to 500+ entries with family-based variation
- [x] Deepen multi-turn orchestrators (Crescendo, TAP-style refinement, Skeleton-Key persistence)
- [x] Add plugin skeleton with example attack generators and enrichers
- [ ] Improve reconciliation reliability to consistently exceed 95%
- [ ] Strengthen hosted dashboard authentication before release

**Active Features**:

- API audit mode with request-id capture and receipt reconciliation framework
- Website audit mode with trust verification and auth bypass probing
- Repository audit mode with supply-chain dependency scanning (P1.5, new)
- Combined mode that merges all three into unified artifacts
- Command-center CLI with subcommands: `run`, `dashboard`, `compare`, `export`, `gate`
- Hosted dashboard server with auto-discovery (v0.3)
- Normalized SQLite artifacts alongside JSON (v0.3)
- Sovereign Next.js dashboard with selectable combined modes and adversarial API endpoint testing

## Near-term Priorities

### P0: API Reliability (May 2026)

- [x] Request-id capture on all audit attempts
- [ ] **Receipt reconciliation**: map unknown/error outcomes to platform decisions
- [ ] Error categorization and adaptive backoff tuning
- Target: Reconciliation coverage ≥95%, error rate < 5%

### P1: Website & Repo Findings (May–June 2026)

- [ ] Resolve critical website findings (receipt key endpoint health)
- [ ] Reduce website HIGH auth bypass findings to gate threshold (≤3)
- [ ] Add malware/typosquatting signals to dependency findings
- [ ] Improve code pattern detection (SHA1, CORS wildcard)
- [x] Add operator endpoint testing controls (single/batch/JSON target inputs)
- [x] Add payload category filtering in sovereign endpoint testing flow

### P1.5: Supply-Chain Hardening (May 2026)

- [x] Multi-language dependency scanning (`pip-audit`, `osv-scanner`)
- [x] Normalize dependency findings with severity/reachability
- [x] Dependency-specific gates (`--max-deps-critical`, etc.)
- [ ] Threat feed integration for malicious/typosquatting detection
- [ ] Dashboard section for top vulnerable dependencies

### P2: Code Hardening (June 2026)

- [ ] Weak crypto detection and remediation guidance (SHA1 → SHA-256)
- [ ] CORS configuration hardening recommendations
- [ ] Security baseline gate for repository patterns

## Medium-term (Q3 2026)

- **Authentication**: Add reverse-proxy auth (basic auth, OIDC, SSO) for hosted dashboard
- **Deployment**: Docker compose and systemd service templates
- **Sovereign UX**: extend endpoint testing with replay presets and saved target profiles
- **Agentic expansion**: Add mutation-based attacks and iterative bypass strategies
- **Dashboard querying**: Browser-side SQLite query engine or server-backed `/api/query` endpoint
- **Reporting**: PDF/HTML report generation for audit findings

## Long-term (Q4 2026+)

- **Cloud hosting**: Managed aletheia-redteam-kit service (beta)
- **Integrations**: Slack, GitHub Actions, GitLab CI/CD, Jira native plugins
- **API v2**: Simplified audit API for programmatic access
- **Performance**: Multi-threaded attack execution (currently serial)
- **Extensibility**: Plugin system for custom attack catalogs and audit modes

## Known Limitations

- **No async I/O**: Currently synchronous. Parallelization requires threading or multiprocessing.
- **No persistent data store**: Artifacts are filesystem-based JSON/SQLite; no central database.
- **Limited auth**: Hosted dashboard has no auth; assume trusted network environment for now.
- **Single-target per run**: Each audit run targets one mode (API+URL, repo path, website URL); combined mode runs sequential sweeps.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Issue tracking and branch workflow
- Testing and code style guidelines
- Common tasks (add attack, add CLI flag, fix gate, etc.)

Issues marked `good-first-issue` or `help-wanted` are ready for external contributors.

## Timeline Notes

- P0 (API relability): **May–early June** — blocks v0.3 release readiness
- P1 (Website/Repo findings): **June** — parallel with P1.5; feeds into v0.3.x
- P1.5 (Supply-chain): **May (in progress)** — ships in v0.3
- P2 (Code hardening): **June–July** — v0.3.x enhancements
- Medium-term (Auth/Deploy): **Q3 planning** — v0.4 target

## FAQ

**Why is reconciliation manual instead of automatic?**  
The platform APIs have different receipt formats and access patterns. Operator-controlled reconciliation gives transparency into which decisions were recovered.

**Why SQLite alongside JSON?**  
JSON is human-readable and dashboard-friendly; SQLite enables downstream tooling and querying without extra dependencies.

**When will there be a managed SaaS?**  
Evaluating cloud hosting for Q4 2026 if demand justifies the operational overhead.

**How stable is the CLI?**  
CLI is considered stable; the core API changed significantly in v0.2 (subcommands) but major breaking changes are unlikely moving forward.

## Getting Help

- **Issues**: Check [`.github/ISSUES.md`](.github/ISSUES.md) for the full backlog with descriptions and acceptance criteria.
- **Discussions**: Use GitHub discussions for questions and design feedback.
- **Reporting Bugs**: Create an issue with reproduction steps and environment details.

---

Last updated: May 7, 2026  
Maintained by: @holeyfield33-art
