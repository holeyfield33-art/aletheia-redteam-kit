# Prioritized Issues for Aletheia Red-Team Kit

This file documents key issues derived from the audit report. Use these to create GitHub issues in the repository.

---

## P0: API Reliability & Receipt Reconciliation

### Issue: Implement receipt reconciliation for API unknown/error outcomes

**Title:** feat(api): reconcile unknown/error decisions from platform receipts

**Description:**

The API audit captures `request_id` for every attempt, but many responses are classified as `UNKNOWN` or `ERROR` due to transport/response anomalies. However, the platform's decision receipts show concrete outcomes (`PROCEED`, `DENIED`, `SANDBOX_BLOCKED`) for the same requests.

**Current Behavior:**
- API errors (72/157 attacks) and empty JSON 200 responses (52/157) are surfaced as `UNKNOWN`/`ERROR`
- These are treated as potential bypasses rather than operational anomalies
- Coverage is ~21% expectation match rate; reconciliation coverage is 0% against receipts

**Expected Behavior:**
- When API calls return `UNKNOWN` or `ERROR`, persist the `request_id`
- Query platform Decision Receipts using the `request_id`
- Map authoritative receipt outcomes back into summary metrics
- Report reconciliation coverage as a gate condition

**Acceptance Criteria:**
- [ ] `kit/client.py` persists `request_id` even when response is `UNKNOWN`/`ERROR`
- [ ] New `reconcile_results()` function maps `request_id` → receipt decision
- [ ] Add `reconciliation` object to summary with `total_reconciled`, `unreconciled`, `coverage_pct`
- [ ] Add `reconciliation_coverage_below_threshold` gate violation when coverage < 95%
- [ ] Reconciliation is applied in `combined` mode and exposed in command-center artifacts
- [ ] All existing tests pass; new coverage for reconciliation logic

**Related Files:**
- `kit/client.py` (DecisionLookup, audit flow)
- `kit/runner.py` (summarize, gating logic)
- `tests/test_client.py` (reconciliation test coverage)

**Labels:** `P0`, `api`, `reliability`, `help-wanted`

---

### Issue: Stabilize API response contract and error handling

**Title:** fix(api): reduce HTTP errors and empty 200 anomalies

**Description:**

The API audit is generating 72 HTTP errors and 52 empty JSON 200 responses out of 157 attacks. This indicates either:
1. API availability issues or rate-limiting in the live environment
2. Contract instability (malformed responses, missing decision field)
3. Edge-layer response stripping

**Current Impact:**
- Expectation match rate: 21% (artificially low due to errors)
- Cannot distinguish API security posture from operational health

**Expected Behavior:**
- Capture and categorize all error types (5xx, rate-limit, timeout, malformed JSON, missing decision field)
- Implement adaptive pacing/backoff (already in code but may need tuning)
- Document anomaly signals for operators

**Acceptance Criteria:**
- [ ] Implement request retry logic with exponential backoff for 5xx responses
- [ ] Categorize errors by type: transport, rate-limit (429), malformed response, missing decision
- [ ] API summary includes `error_breakdown` with counts per category
- [ ] Add a gate violation `api:errors_present` when error count > threshold (default 0)
- [ ] Document expected HTTP behaviors in README
- [ ] Tests validate error categorization and retry behavior

**Related Files:**
- `kit/client.py` (AletheiaClient, audit retry logic)
- `kit/runner.py` (error categorization, summarize)
- `tests/test_client.py`

**Labels:** `P0`, `api`, `reliability`, `good-first-issue`

---

## P1: Website Audit Findings Remediation

### Issue: Reduce website critical findings (receipt key endpoint health)

**Title:** fix(website-audit): resolve critical findings from trust verification

**Description:**

Website audit identified 2 critical findings:
1. Receipt key endpoint (`/.well-known/aletheia-receipt-key.pem`) returns HTTP 503
2. Trust verification fails as a result

Both block the `website:critical>0` gate.

**Current Impact:**
- Pass rate: 83.8% (should be ≥95%)
- Exploitability: 100 (critical)
- Website verdict: UNSAFE

**Expected Behavior:**
- Receipt key endpoint returns HTTP 200 with valid PEM
- Trust verification succeeds
- Website critical findings = 0

**Acceptance Criteria:**
- [ ] Endpoint available at `https://aletheia-core.com/.well-known/aletheia-receipt-key.pem`
- [ ] Valid Ed25519 PEM format
- [ ] Website audit re-passes trust verification
- [ ] No critical findings in next audit run

**Notes:**
- This is likely a deployment/operations issue on aletheia-core.com, not a kit issue
- Document the resolution for other red-teamers

**Labels:** `P1`, `website`, `operations`, `blocked-by-external`

---

### Issue: Reduce website HIGH findings from auth bypass probes

**Title:** feat(website-audit): investigate and document auth bypass findings

**Description:**

Website audit identified 4 HIGH findings of type `auth_bypass` out of 6 total findings:
- Pass rate: 83.8% (target: ≥95%)
- Each bypass represents a potential RBAC or session management weakness

**Current Impact:**
- Website verdict: UNSAFE
- Blocks `website:high>3` gate

**Expected Behavior:**
- Understand root cause of bypass findings (is it a probing strategy issue or real vulnerability?)
- Either remediate auth logic on aletheia-core.com or update kit probing strategy

**Acceptance Criteria:**
- [ ] Document the 4 auth bypass findings with reproduction steps
- [ ] Propose fix (operations, kit update, or both)
- [ ] Website high findings ≤ 3
- [ ] Pass rate ≥ 95%

**Notes:**
- Likely operations/auth remediation on aletheia-core.com
- May require collaboration with platform team

**Labels:** `P1`, `website`, `auth`, `investigation`

---

## P1.5: Supply-Chain & Dependency Hardening

### Issue: Add multi-language dependency scanning to repo mode

**Title:** feat(repo-audit): add pip-audit + osv-scanner for dependency advisories (P1.5)

**Description:**

Repository audit is missing supply-chain coverage. Add automated dependency scanning to identify vulnerable packages across Python, Node, and other common lockfiles.

**Scope:**
- Auto-detect manifest files (requirements.txt, package-lock.json, etc.)
- Run `pip-audit` for Python dependencies
- Run `osv-scanner` for multi-language support when available
- Normalize findings as `dependency_vulnerability` findings with severity/reachability

**Current State:**
- Repo audit only covers code patterns and config drift
- No dependency advisory integration

**Expected Behavior:**
- `python -m kit.runner --mode repo --deps-scan auto` auto-detects and scans
- `--deps-scan full` forces explicit runs even if advisory tool missing
- New findings added to repo summary under `dependencies` key
- Dependency-specific gates: `--max-deps-critical`, `--max-deps-high`

**Acceptance Criteria:**
- [ ] Implement `DependencyScanRunner` that wraps `pip-audit` and `osv-scanner`
- [ ] Auto-detect manifest files in repo
- [ ] Normalize findings to `dependency_vulnerability` type
- [ ] Add reachability and exploitability indicators
- [ ] Support `--deps-scan {off,auto,full}` flag
- [ ] Add dependency gates with configurable thresholds
- [ ] Tests cover Python and optional Node manifest detection
- [ ] Document in README under "Repository audit mode"
- [ ] Optional: add to combined mode (already implemented in prior work)

**Related Files:**
- `engine/repo_audit/scanner.py` (primary implementation)
- `kit/runner.py` (CLI flags, gating)
- `pyproject.toml` (optional `[deps]` extra for osv-scanner, pip-audit)
- Docs: README, docs/command-center.md

**Labels:** `P1.5`, `repo-audit`, `supply-chain`, `help-wanted`, `good-first-issue`

---

### Issue: Add malware/tampering indicators to dependency findings

**Title:** feat(repo-audit): enrich dependency findings with malware/typosquatting signals

**Description:**

Extend dependency findings to include metadata beyond CVE advisories:
- Malicious package indicators from threat feeds
- Typosquatting detection (e.g., `numpy` vs `nympy`)
- Package age and maintenance signals
- Source integrity checks

**Current State:**
- Only CVE-based advisories from `pip-audit`/`osv-scanner`

**Expected Behavior:**
- Dependency findings include `threat_signal` enum: `none`, `malicious`, `typosquatting`, `unmaintained`, `suspicious_source`
- Threat feed integration optional (via `threat_feed.json`)
- Dashboard displays top-risk dependency findings

**Acceptance Criteria:**
- [ ] Add `threat_signal` field to dependency vulnerability findings
- [ ] Integrate threat feed data for malicious/typosquatting detection
- [ ] Document threat feed format in README
- [ ] Tests validate threat signal assignment
- [ ] Dashboard displays threat signals in dependency section

**Related Files:**
- `engine/repo_audit/scanner.py` (dependency scanning logic)
- `threat_feed.json` (threat intelligence mappings)
- `dashboard/index.html` (display logic for dependencies)

**Labels:** `P1.5`, `repo-audit`, `supply-chain`, `threat-intelligence`

---

## P2: Code Pattern Hardening

### Issue: Replace SHA1 with SHA-256+ in codebase

**Title:** fix(repo-audit): detect and flag weak SHA1 usage

**Description:**

Repository scan identified SHA1 usage, which is cryptographically weak. Recommend SHA-256 or stronger for new code.

**Current State:**
- Finding type: `weak_hash_sha1`
- Exists in codebase somewhere (location to be determined)
- Gate: not yet blocking

**Expected Behavior:**
- Repo audit identifies SHA1 in common places (git history, code, config)
- Findings surface with recommendation to use SHA-256
- Dashboard flags as medium-severity code pattern issue

**Acceptance Criteria:**
- [ ] Implement `detect_weak_hash()` in repo scanner
- [ ] Scan common file patterns: `*.py`, `*.js`, `*.go`, config files
- [ ] Create finding with remediation guidance
- [ ] Verify repo itself doesn't use SHA1 (fix if so)
- [ ] Add gate violation `repo:weak_hash_detected` (default: warn, not fail)
- [ ] Tests validate pattern detection

**Related Files:**
- `engine/repo_audit/scanner.py` (scanner logic)
- `kit/runner.py` (gating)

**Labels:** `P2`, `repo-audit`, `code-hardening`, `security`, `good-first-issue`

---

### Issue: Restrict CORS from wildcard to explicit origins

**Title:** fix(repo-audit): detect overly permissive CORS configuration

**Description:**

Repository scan identified wildcard CORS origin configuration (`Access-Control-Allow-Origin: *`), which is overly permissive.

**Current State:**
- Finding type: `cors_wildcard_origin`
- Exists in codebase (location to be determined)
- Gate: not yet blocking

**Expected Behavior:**
- Repo audit identifies CORS wildcard in common places (code, config, web server config)
- Findings surface with recommendation to restrict to explicit origins
- Dashboard flags as medium-severity security config issue

**Acceptance Criteria:**
- [ ] Implement `detect_cors_wildcard()` in repo scanner
- [ ] Scan config files, source code, web server configs
- [ ] Create finding with remediation guidance and example
- [ ] Add gate violation `repo:cors_wildcard_detected` (default: warn)
- [ ] Verify repo itself doesn't use wildcard CORS (fix if so)
- [ ] Tests validate pattern detection

**Related Files:**
- `engine/repo_audit/scanner.py` (scanner logic)
- `kit/runner.py` (gating)

**Labels:** `P2`, `repo-audit`, `security-config`, `good-first-issue`

---

## Meta Issues

### Issue: Create open-source contribution guide

**Title:** docs: add CONTRIBUTING.md for open-source contributors

**Description:**

Help external contributors understand:
- How to set up the dev environment
- Testing strategy and how to run tests
- Issue triage process
- PR expectations and code style

**Acceptance Criteria:**
- [ ] `CONTRIBUTING.md` file created
- [ ] Development setup instructions
- [ ] Testing and CI workflow
- [ ] Code style guidelines
- [ ] Issue/PR templates (optional)

**Labels:** `docs`, `good-first-issue`, `help-wanted`

---

### Issue: Add roadmap document

**Title:** docs: create PUBLIC_ROADMAP.md for transparency

**Description:**

Share the direction of the project with the community. Include:
- Current version and recent releases
- P0/P1/P1.5/P2 priorities
- Future feature directions (e.g., additional audit modes, cloud hosting)
- Deprecation plans

**Acceptance Criteria:**
- [ ] `PUBLIC_ROADMAP.md` file created
- [ ] Linked from README
- [ ] Updated quarterly

**Labels:** `docs`, `roadmap`

