# Adversarial Red-Team Review: OSS Acceptance Security Posture

**Target**: `aletheia-redteam-kit`  
**Version Reviewed**: v1.2.0 / v1.3.0 (Phase 3)  
**Review Date**: 2026-05-20  
**Scope**: OSS acceptance criteria — supply chain, credential leakage, input validation, command injection, TLS hardening, dependency hygiene, secret management, and code maturity.

---

## Executive Summary

This repository demonstrates a **mature security posture** for an open-source red-team toolkit. The maintainers have invested in defense-in-depth: input sanitization, rate limiting, authenticated dashboard serving, credential masking, and path traversal guards. **No live secrets or hard-coded credentials were detected** in committed code. The dependency surface is intentionally minimal (`httpx` + `bcrypt` core runtime). Below we enumerate the key findings, threats, and mitigations.

---

## 1. Dependency & Supply Chain Analysis

### Core Runtime Dependencies (Low Risk)

| Dependency | Version Constraint | Purpose | Known CVEs |
|-----------|-------------------|---------|------------|
| `httpx` | >=0.27 | HTTP client for API calls | None critical at time of review |
| `bcrypt` | >=4.2 | Password hashing for dashboard auth | None critical at time of review |

### Optional Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | >=42.0 | Receipt signature verification |
| `playwright` | >=1.53 | Browser-based website audit |
| `pip-audit` | >=2.7 | Dependency vulnerability scanning |
| `cyclonedx-bom` | >=4.1 | SBOM generation |
| `pytest` | >=8.0 | Test framework (dev only) |

### Supply-Chain Observations

| Risk | Finding | Severity |
|------|---------|----------|
| **Dependency confusion** | No lockfile for Python deps (`pyproject.toml` only). `pip install -e .` resolves from PyPI at install time with no pinned hashes. | **MEDIUM** |
| **npm dependency rot** | `package-lock.json` is empty (`"packages": {}`). The Next.js dashboard at `dashboard/sovereign-command-center/` likely manages its own `package-lock.json`. The root-level empty lockfile may confuse automated supply-chain scanners. | **LOW** |
| **External tool invocation** | Subprocess calls to `pip-audit`, `osv-scanner`, `semgrep`, `bandit`, `trivy`, `npm audit`, and `git`. Each external tool expands the supply-chain risk surface. | **MEDIUM** |
| **Threat-feed integration** | `sample_threat_feed.json` contains 3 placeholder entries. Real deployments must provide production threat feeds, introducing data injection risk. | **LOW** |

**Recommendations**:
- Pin `pyproject.toml` dependencies with exact versions or hash-pinned requirements.
- Either populate the root `package-lock.json` or remove it to avoid scanner confusion.
- Add a `requirements-lock.txt` with hashed pins for reproducible installs.

---

## 2. Secret & Credential Leakage

### Static Analysis Results
- **No live credentials detected** in committed code.
- Test fixtures use the marker comment `# aletheia-redteam:allowed-test-fixture` and are excluded via `.gitleaks.toml` path allowlist.
- The `.gitleaks.toml` config allows `tests/`, `test/`, `runs/`, and regex `aletheia-redteam:allowed-test-fixture`.

### API Key Handling

| Mechanism | Implementation | Risk |
|-----------|---------------|------|
| `ALETHEIA_API_KEY` | Read from env in `kit/client.py`, sent via `X-API-Key` or `Authorization` header. Never logged. | **LOW** |
| `ALETHEIA_GITHUB_TOKEN` | Read from env or `--repo-token` flag. Delivered via `GIT_ASKPASS` — never appears in subprocess arguments or logs. | **LOW** (well mitigated) |
| `ALETHEIA_DASHBOARD_*` | Passwords and API keys stored as bcrypt hashes. Plaintext fallback emits a runtime warning. | **LOW** |

### Dashboard Authentication Credentials
- `ALETHEIA_DASHBOARD_PASSWORD_HASH` — bcrypt hash (preferred)
- `ALETHEIA_DASHBOARD_API_KEY_HASH` — bcrypt hash (preferred)
- `ALETHEIA_DASHBOARD_SESSION_SECRET` — auto-generated with `token_urlsafe(32)` if unset
- Plaintext envvar forms (`ALETHEIA_DASHBOARD_PASSWORD`, `ALETHEIA_DASHBOARD_API_KEY`) trigger runtime warnings.

---

## 3. Input Validation & Injection Vectors

### 3.1 CLI Argument Sanitization (`kit/runner.py`)

| Function | Controls | Bypass Risk |
|----------|----------|-------------|
| `_sanitize_user_string()` | Max length (2048), control-char filter, strip | **LOW** |
| `_sanitize_json_path()` | Requires `.json` suffix, length check | **LOW** |
| `_sanitize_repo_url()` | Blocks `file://` URIs, restricts to GitHub URLs or shorthand | **LOW** (well mitigated) |
| `_sanitize_legacy_args()` | Applies all above to every user-supplied CLI parameter | **LOW** |

### 3.2 Path Traversal – Dashboard Server (`kit/dashboard_server.py`)

| Code Location | Control | Assessment |
|--------------|---------|------------|
| `_resolve_run_path()` | Checks for `..` in path fragment, rejects control chars, verifies resolved path is under `artifact_root` via `os.path.commonpath` | **LOW** (effective guard) |
| `_sanitize_repo_url_input()` | Rejects URLs with control chars, max length 512 | **LOW** |
| `sanitize_next_path()` | Only allows paths starting with `/`, blocks `//` prefix | **LOW** |

### 3.3 Command Injection – Dashboard `/api/repo-audit` Endpoint

The endpoint accepts a `repo_url` from the HTTP POST body and passes it to `_launch_public_repo_audit()` which builds a subprocess command:

```python
command = [
    sys.executable, "-m", "kit.runner", "run",
    "--mode", "repo",
    "--repo-url", normalized_repo_url,  # user-controlled
    ...
]
process = subprocess.Popen(command, ...)
```

**Risk Assessment**: The repo URL is sanitized via `_sanitize_repo_url_input()` (rejects control chars) and `_normalize_public_github_repo_url()`. Since the URL is passed as a **list element** to `subprocess.Popen`, shell injection is not possible. A crafted URL like `https://github.com/valid/repo.git;malicious` would be passed as a literal argument, not executed by a shell. **Low likelihood of successful command injection.**

### 3.4 `os.system()` Call in `runner.py`

```python
os.system(f'{browser} "{dashboard_path.resolve()}" >/dev/null 2>&1')
```

The `browser` variable comes from `shutil.which("open")` or platform equivalents, and `dashboard_path.resolve()` is a controlled internal file path. The command is not user-controllable. **LOW** risk.

### 3.5 TLS Verification Disabled in Website Audit — **HIGH SEVERITY**

**Finding**: In `kit/web_audit/runner.py` line 64:

```python
context = browser.new_context(ignore_https_errors=True)
```

This disables TLS certificate validation for all Playwright-based website audits. A network attacker performing a MITM attack could:
- Intercept and modify all traffic between the audit engine and the target website
- Inject malicious responses or harvest credentials
- Subvert audit results

**Severity**: **HIGH** — impacts the integrity of every website audit when browser mode is used.

**Recommendation**: Make `ignore_https_errors` configurable with a default of `False`, or add a warning when TLS verification is disabled. Only enable it as an explicit opt-in for testing internal/development targets with self-signed certificates.

---

## 4. Dependency Vulnerability Scanning Integration

The repo audit mode integrates multiple external vulnerability scanners via subprocess:

| Scanner | Command | Requires External Binary |
|---------|---------|------------------------|
| `pip-audit` | `subprocess.run(["pip-audit", "-f", "json"])` | Yes |
| `osv-scanner` | `subprocess.run(["osv-scanner", ...])` | Yes |
| `semgrep` | `subprocess.run(["semgrep", "--config", "auto", "--json"])` | Yes |
| `bandit` | `subprocess.run(["bandit", "-r", "-f", "json"])` | Yes |
| `trivy` | `subprocess.run(["trivy", "fs", "--format", "json"])` | Yes |
| `npm audit` | `subprocess.run(["npm", "audit", "--json"])` | Yes |

**Risk**: Each scanner invocation expands the attack surface. A compromised or malicious scanner binary could execute arbitrary code in the context of the audit process. The scanners are configured to fail gracefully with `{"status": "unavailable"}` if not found on `PATH`.

**Recommendation**: Consider sandboxing scanner execution (e.g., running in a container or with restricted permissions) for CI/CD deployment scenarios.

---

## 5. Dashboard Security Hardening

| Feature | Implementation | Assessment |
|---------|---------------|------------|
| **Auth modes** | `basic` (password), `api-key`, `proxy`, `disabled` | Well-structured |
| **Default auth (v1.2.0+)** | `--serve` defaults to `--auth-mode basic` | Positive hardening |
| **Rate limiting** | 30 requests/min default, configurable via env | Effective |
| **Session cookies** | `HttpOnly`, `SameSite=Lax`/`Strict`, configurable TTL (8-24h) | Secure |
| **Login rate limiting** | 5 attempts per 15-min window, 15-min lockout | Effective |
| **Warnings** | Loud warning when auth is disabled | Positive |
| **TLS documentation** | README recommends reverse proxy with TLS termination | Sufficient guidance |

---

## 6. Code Maturity & OSS Acceptance Indicators

| Criteria | Assessment | Score |
|----------|-----------|-------|
| **CHANGELOG maintained** | Yes, v1.1→v1.2→v1.3 with detailed security items | ⭐⭐⭐⭐⭐ |
| **CONTRIBUTING guide** | Present, detailed with setup, workflow, testing | ⭐⭐⭐⭐⭐ |
| **Test coverage** | 30+ test files, CI workflow present | ⭐⭐⭐⭐ |
| **Security documentation** | Ethical-use statement, launch checklist, deployment guidance | ⭐⭐⭐⭐⭐ |
| **Dependency hygiene** | Minimal core deps, optional scanner deps well-isolated | ⭐⭐⭐⭐ |
| **Secret handling** | No committed secrets, env-based config, secure token passing | ⭐⭐⭐⭐⭐ |
| **Input sanitization** | Comprehensive in CLI, dashboard, and file paths | ⭐⭐⭐⭐ |
| **Supply-chain scanning** | Built-in `pip-audit`/`osv-scanner` integration | ⭐⭐⭐⭐ |
| **Update frequency** | Active development (3 releases in minor version range) | ⭐⭐⭐⭐ |

---

## 7. Risk Register Summary

| # | Finding | Severity | Recommended Action |
|---|---------|----------|-------------------|
| 1 | TLS verification disabled in Playwright web audits (`ignore_https_errors=True`) | **HIGH** | Default to `False`; make configurable |
| 2 | No pinned dependency hashes in `pyproject.toml` | **MEDIUM** | Hash-pin or add lockfile |
| 3 | Empty root `package-lock.json` | **LOW** | Remove or populate |
| 4 | External tool subprocess execution without sandboxing | **MEDIUM** | Containerize for CI |
| 5 | Plaintext credential envvar fallback still accepted | **MEDIUM** | Deprecate in v2.0; reject plaintext |
| 6 | `os.system()` call in `runner.py` for opening browser | **LOW** | Acceptable risk (not user-controllable) |
| 7 | Dashboard `session_secret` auto-generated when unset (ephemeral) | **LOW** | Acceptable with warning |

---

## 8. Overall OSS Acceptance Verdict

**PASS** with **3 actionable improvement items**.

The `aletheia-redteam-kit` demonstrates a security-conscious development approach rare in red-team tooling. The codebase features consistent input validation, credential hygiene, rate limiting, and an active changelog. The single highest-priority finding is the hard-coded `ignore_https_errors=True` in the Playwright web audit runner (severity: **HIGH**), which undermines the integrity of website audits in production environments by disabling TLS certificate verification.

The repository is positioned well for OSS adoption. With the three highest-severity findings addressed, it would represent a **best-in-class** security posture for an adversarial testing toolkit.