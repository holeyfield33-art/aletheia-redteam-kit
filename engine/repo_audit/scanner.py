"""Static repository risk scanner for secrets, config, and dependency hygiene."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from math import log2
from pathlib import Path
import stat
import tempfile
import shutil
import subprocess
import os
import re
import tomllib
import json
from collections import defaultdict
from urllib.parse import urlparse
from typing import Any

from src.reporting.enricher import enrich_repo_summary
from src.scanners.dep_vuln import scan_dependency_advisories
from src.scanners.dependency_utils import (
    _classify_dependency_finding_type,
    _normalize_dependency_severity,
)
from src.scanners.git_history_secrets import scan_git_history_secrets

try:  # pragma: no cover - unavailable on some platforms
    import resource
except Exception:  # pragma: no cover - defensive
    resource = None

# ---------------------------------------------------------------------------
# Scan profile definitions
# ---------------------------------------------------------------------------
#
# Each profile is a set of scanner names that will be executed.  The names
# map onto the scanner functions that _audit_repo_root dispatches to.
#
# "light"   – secrets + CI config + language-risk patterns only (fastest)
# "medium"  – light + dependency hygiene + advisory scans (default, was the
#              only behaviour before Phase 3)
# "full"    – medium + semgrep, bandit, trivy, npm-audit (all optional tools)
# "custom"  – operator-supplied JSON profile file (see --scan-profile-file)
#
SCAN_PROFILE_LIGHT = {"secrets", "ci_config", "language_risks", "threat_feed"}
SCAN_PROFILE_MEDIUM = SCAN_PROFILE_LIGHT | {"dep_hygiene", "dep_advisories"}
SCAN_PROFILE_FULL = SCAN_PROFILE_MEDIUM | {"semgrep", "bandit", "trivy", "npm_audit", "git_history_secrets"}

SCAN_PROFILES: dict[str, set[str]] = {
    "light": SCAN_PROFILE_LIGHT,
    "medium": SCAN_PROFILE_MEDIUM,
    "full": SCAN_PROFILE_FULL,
}


def _resolve_scan_profile(
    profile: str | None,
    profile_file: str | None = None,
) -> set[str]:
    """Return the set of enabled scanner names for *profile*.

    If *profile* is ``"custom"`` the caller must supply *profile_file*, which
    must be a JSON object with a ``"scanners"`` key listing scanner names.
    """
    if profile in {None, "medium", ""}:
        return set(SCAN_PROFILE_MEDIUM)
    if profile == "light":
        return set(SCAN_PROFILE_LIGHT)
    if profile == "full":
        return set(SCAN_PROFILE_FULL)
    if profile == "custom":
        if not profile_file:
            raise ValueError("--scan-profile-file is required when --scan-profile custom is used")
        raw = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        scanners = raw.get("scanners") if isinstance(raw, dict) else raw
        if not isinstance(scanners, list):
            raise ValueError("scan profile file must contain a JSON object with a 'scanners' list")
        return {str(s) for s in scanners}
    raise ValueError(f"Unknown scan profile: {profile!r}; choose light, medium, full, or custom")


@dataclass(frozen=True)
class Finding:
    severity: str
    type: str
    title: str
    file: str
    line: int | None
    evidence: str
    recommendation: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "type": self.type,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "api_key_literal",
        "Potential API key literal",
        re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"]?[a-z0-9_\-]{16,}['\"]?"),
    ),
    (
        "private_key_block",
        "Private key material in repository",
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----"),
    ),
    (
        "password_literal",
        "Hardcoded password literal",
        re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ),
]

ALLOWED_TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".sh", ".js", ".ts", ".tsx", ".jsx", ".html", ".css",
}

PY_RISK_PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "python_dynamic_exec_untrusted",
        "Dynamic code execution with untrusted input",
        "HIGH",
        re.compile(r"\b(eval|exec)\s*\(\s*(input\(|request\.)"),
        "Avoid executing user-controlled strings. Replace with strict parsing/dispatch logic.",
    ),
    (
        "python_subprocess_shell_true",
        "Subprocess execution with shell=True",
        "HIGH",
        re.compile(r"subprocess\.(run|Popen|call|check_output)\([^\n]*shell\s*=\s*True"),
        "Use shell=False and pass command arguments as a list.",
    ),
    (
        "python_pickle_loads",
        "Deserialization via pickle.loads",
        "HIGH",
        re.compile(r"\bpickle\.loads\s*\("),
        "Do not deserialize untrusted pickle payloads.",
    ),
    (
        "python_yaml_unsafe_load",
        "Potential unsafe yaml.load usage",
        "HIGH",
        re.compile(r"\byaml\.load\s*\([^\n]*(Loader\s*=\s*yaml\.SafeLoader)?"),
        "Use yaml.safe_load for untrusted data.",
    ),
    (
        "python_flask_debug_true",
        "Flask app running with debug=True",
        "MEDIUM",
        re.compile(r"\.run\([^\n]*debug\s*=\s*True"),
        "Disable debug mode in production deployments.",
    ),
]

JS_RISK_PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "javascript_eval",
        "JavaScript eval usage",
        "HIGH",
        re.compile(r"\beval\s*\("),
        "Remove eval and use safe parsing/dispatch mechanisms.",
    ),
    (
        "javascript_function_constructor",
        "Function constructor usage",
        "HIGH",
        re.compile(r"new\s+Function\s*\("),
        "Avoid runtime code generation from strings.",
    ),
    (
        "javascript_child_process_exec_untrusted",
        "Command execution with potentially untrusted request data",
        "HIGH",
        re.compile(r"\bexec\s*\([^\n]*(req\.|request\.)"),
        "Do not pass request data into command execution.",
    ),
]

DRIFT_PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "tls_verification_disabled",
        "TLS certificate verification disabled",
        "HIGH",
        re.compile(r"(verify\s*=\s*False|ssl[_-]?verify\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)", re.IGNORECASE),
        "Enable TLS verification in all HTTP clients and runtime environments.",
    ),
    (
        "cors_wildcard_origin",
        "Overly permissive CORS wildcard policy",
        "MEDIUM",
        re.compile(r"(Access-Control-Allow-Origin[^\n]*\*|origin\s*:\s*['\"]\*['\"])", re.IGNORECASE),
        "Restrict CORS origins to trusted allowlists for production deployments.",
    ),
    (
        "jwt_none_algorithm",
        "JWT 'none' algorithm accepted",
        "HIGH",
        re.compile(r"alg['\"]?\s*[:=]\s*['\"]none['\"]", re.IGNORECASE),
        "Reject JWT tokens using the 'none' algorithm and enforce signed tokens.",
    ),
]

WEAK_CRYPTO_PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "weak_hash_md5",
        "Weak hash algorithm usage (MD5)",
        "MEDIUM",
        re.compile(r"(hashlib\.md5\s*\(|createHash\s*\(\s*['\"]md5['\"])"),
        "Use a stronger algorithm such as SHA-256 or better as appropriate.",
    ),
    (
        "weak_hash_sha1",
        "Weak hash algorithm usage (SHA1)",
        "MEDIUM",
        re.compile(r"(hashlib\.sha1\s*\(|createHash\s*\(\s*['\"]sha1['\"])"),
        "Use a stronger algorithm such as SHA-256 or better as appropriate.",
    ),
]

DEFAULT_THREAT_FEED: list[dict[str, str]] = [
    {
        "finding_type": "python_subprocess_shell_true",
        "threat": "Command injection",
        "reference": "https://owasp.org/www-community/attacks/Command_Injection",
    },
    {
        "finding_type": "python_dynamic_exec_untrusted",
        "threat": "Arbitrary code execution",
        "reference": "https://owasp.org/www-community/attacks/Code_Injection",
    },
    {
        "finding_type": "javascript_eval",
        "threat": "Code injection",
        "reference": "https://owasp.org/www-community/attacks/Code_Injection",
    },
    {
        "finding_type": "dependency_vulnerability",
        "threat": "Known vulnerable dependency",
        "reference": "https://owasp.org/www-project-top-ten/",
    },
    {
        "finding_type": "dependency_malware_suspect",
        "threat": "Potential malicious or compromised dependency",
        "reference": "https://osv.dev/",
    },
    {
        "finding_type": "dependency_tampering_risk",
        "threat": "Potential dependency tampering or typosquatting",
        "reference": "https://owasp.org/www-project-software-assurance-maturity-model/",
    },
    {
        "finding_type": "private_key_block",
        "threat": "Credential/key compromise",
        "reference": "https://owasp.org/www-project-secrets-management/",
    },
]

DEPENDENCY_FILE_PATTERNS: dict[str, tuple[str, ...]] = {
    "python": (
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-prod.txt",
        "Pipfile.lock",
        "poetry.lock",
    ),
    "javascript": (
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
    ),
    "go": ("go.mod", "go.sum"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"),
    "dotnet": ("packages.lock.json",),
    "rust": ("Cargo.lock", "Cargo.toml"),
    "ruby": ("Gemfile", "Gemfile.lock"),
}

ECOSYSTEM_LANGUAGE_MAP: dict[str, str] = {
    "PyPI": "python",
    "npm": "javascript",
    "Go": "go",
    "Maven": "java",
    "NuGet": "dotnet",
    "crates.io": "rust",
    "RubyGems": "ruby",
}

TEST_FIXTURE_ALLOWLIST_MARKER = "aletheia-redteam:allowed-test-fixture"
TEST_FIXTURE_GLOBS = (
    "tests/**",
    "test/**",
)
SECRET_ALLOWLIST_FILE = ".aletheia-secret-allowlist"
SECRET_LOW_TRUST_PATH_GLOBS = (
    "*.md",
    "*.sample",
    "*.example",
    ".env.example",
    ".env.sample",
    "docs/**",
    "examples/**",
    "test/**",
    "tests/**",
    "fixtures/**",
    "fixture/**",
)
ENV_REFERENCE_PATTERNS = (
    re.compile(r"\bprocess\.env\b"),
    re.compile(r"\bos\.environ\b"),
    re.compile(r"\bos\.getenv\b"),
    re.compile(r"\bgetenv\b"),
    re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"),
)
PLACEHOLDER_SECRET_PATTERNS = (
    re.compile(r"(?i)\byour_[a-z0-9_]*\b"),
    re.compile(r"(?i)\bchangeme\b"),
    re.compile(r"(?i)\bplaceholder\b"),
    re.compile(r"(?i)\bdummy\b"),
    re.compile(r"(?i)\btest_key\b"),
    re.compile(r"(?i)\bxxx+\b"),
    re.compile(r"\.\.\."),
    re.compile(r"<[^>]+>"),
    re.compile(r"\{\{[^}]+\}\}"),
)
SECRET_ENTROPY_THRESHOLD = 3.6


@dataclass(frozen=True)
class AllowlistEntry:
    file_glob: str
    finding_type: str
    evidence_pattern: re.Pattern[str]
    owner: str
    reason: str
GENERATED_ARTIFACT_GLOBS = (
    "summary.json",
    "summary_*.json",
    "website_summary.json",
    "report.md",
    "runs/**",
)

GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def is_test_file(file_path: str) -> bool:
    if not file_path:
        return False
    normalized = str(file_path).replace("\\", "/").lower()
    return (
        "/tests/" in normalized
        or "/test/" in normalized
        or normalized.startswith("tests/")
        or normalized.startswith("test/")
        or ".test." in normalized
        or ".spec." in normalized
    )


def is_first_party_file(file_path: str) -> bool:
    normalized = str(file_path or "").replace("\\", "/")
    if not normalized:
        return False
    ignored_markers = (
        "/node_modules/",
        "/.next/",
        "/.venv/",
        "/env/",
        "/dist/",
        "/build/",
    )
    if normalized.startswith((".venv/", "env/", "dist/", "build/")):
        return False
    return not any(marker in normalized for marker in ignored_markers)


def _finding_value(finding: Finding | dict[str, Any], field: str) -> Any:
    if isinstance(finding, Finding):
        return getattr(finding, field)
    return finding.get(field)


def should_ignore_finding(
    finding: Finding | dict[str, Any],
    *,
    ignore_test_fixtures: bool = True,
) -> bool:
    file_path = str(_finding_value(finding, "file") or _finding_value(finding, "path") or "")
    finding_type = str(_finding_value(finding, "type") or "")
    evidence = str(_finding_value(finding, "evidence") or "").lower()
    normalized_file = file_path.replace("\\", "/").lower()

    if ignore_test_fixtures and is_test_file(normalized_file) and finding_type in {
        "password_literal",
        "api_key_literal",
        "high_entropy_secret_literal",
        "private_key_block",
    }:
        return True

    if ("auth.py" in normalized_file or "client.py" in normalized_file) and any(
        keyword in evidence
        for keyword in ("token", "getenv", "env.get", "os.getenv", "payload", "construct")
    ):
        if finding_type in {"password_literal", "api_key_literal", "high_entropy_secret_literal"}:
            return True

    if ("scanner.py" in normalized_file or "repo_audit/" in normalized_file) and finding_type in {
        "cors_wildcard_origin",
        "weak_hash_sha1",
    }:
        return True

    return False


def _is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in ALLOWED_TEXT_SUFFIXES:
        return True
    return path.name in {"Dockerfile", "Makefile"}


def _iter_source_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        if _is_ignored_scan_path(rel):
            continue
        if any(fnmatch(str(rel).replace("\\", "/"), pattern) for pattern in GENERATED_ARTIFACT_GLOBS):
            continue
        if _is_probably_text(path):
            files.append(path)
    return files


def _is_ignored_scan_path(path: Path) -> bool:
    ignored_parts = {".git", ".venv", "venv", "env", "node_modules", ".next", "dist", "build", "__pycache__", ".pytest_cache"}
    return any(part in ignored_parts for part in path.parts)


def _detect_dependency_manifests(repo_root: Path) -> dict[str, list[str]]:
    detected: dict[str, list[str]] = {language: [] for language in DEPENDENCY_FILE_PATTERNS}

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        if _is_ignored_scan_path(rel):
            continue

        rel_str = str(rel).replace("\\", "/")
        name = path.name
        for language, patterns in DEPENDENCY_FILE_PATTERNS.items():
            if name in patterns:
                detected[language].append(rel_str)
                continue
            if language == "python" and name.startswith("requirements") and name.endswith(".txt"):
                detected[language].append(rel_str)
            if language == "dotnet" and name.endswith(".csproj"):
                detected[language].append(rel_str)

    return {language: sorted(set(paths)) for language, paths in detected.items()}


def _matches_fixture_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return is_test_file(normalized) or any(fnmatch(normalized, pattern) for pattern in TEST_FIXTURE_GLOBS)


def _is_allowlisted_fixture_line(rel_path: str, line: str) -> bool:
    return _matches_fixture_path(rel_path) and TEST_FIXTURE_ALLOWLIST_MARKER in line


def _is_low_trust_secret_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lower()
    if _matches_fixture_path(normalized):
        return True
    return any(fnmatch(normalized, pattern) for pattern in SECRET_LOW_TRUST_PATH_GLOBS)


def _is_env_reference_line(line: str) -> bool:
    return any(pattern.search(line) for pattern in ENV_REFERENCE_PATTERNS)


def _is_placeholder_secret(candidate: str) -> bool:
    normalized = candidate.strip().lower()
    if not normalized:
        return False
    if normalized.startswith("<") and normalized.endswith(">"):
        return True
    if normalized in {"...", "xxx", "xxxx", "xxxxx", "test_key"}:
        return True
    return any(pattern.search(normalized) for pattern in PLACEHOLDER_SECRET_PATTERNS)


def _has_mixed_character_classes(candidate: str) -> bool:
    has_alpha = any(char.isalpha() for char in candidate)
    has_digit = any(char.isdigit() for char in candidate)
    has_symbol = any(char in "_-+/=" for char in candidate)
    return has_alpha and has_digit and has_symbol


def _extract_secret_candidate(line: str) -> str:
    stripped = line.split("#", 1)[0].strip()
    if not stripped:
        return ""
    if "=" in stripped:
        stripped = stripped.split("=", 1)[1].strip()
    elif ":" in stripped and re.search(r"(?i)(api[_-]?key|token|secret|password|session)", stripped):
        stripped = stripped.split(":", 1)[1].strip()
    matches = re.findall(r"['\"]([^'\"]{1,256})['\"]", stripped)
    if matches:
        return matches[0].strip()
    return stripped.strip(" ,;")


def _secret_finding_severity(rel_path: str, finding_type: str, candidate: str) -> str | None:
    if _is_placeholder_secret(candidate):
        return None

    low_trust_path = _is_low_trust_secret_path(rel_path)
    if finding_type in {"api_key_literal", "password_literal"}:
        return "LOW" if low_trust_path else "HIGH"

    if finding_type == "private_key_block":
        return "LOW" if low_trust_path else "CRITICAL"

    if low_trust_path:
        return "LOW"

    entropy = _shannon_entropy(candidate)
    if _has_mixed_character_classes(candidate) and entropy >= SECRET_ENTROPY_THRESHOLD:
        return "HIGH"
    return "LOW"


def _load_secret_allowlist(repo_root: Path) -> list[AllowlistEntry]:
    allowlist_path = repo_root / SECRET_ALLOWLIST_FILE
    if not allowlist_path.exists():
        return []

    entries: list[AllowlistEntry] = []
    for raw_line in allowlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "# owner:" not in line or "# reason:" not in line:
            continue

        body, comment_blob = line.split("#", 1)
        parts = [part.strip() for part in body.split("|")]
        if len(parts) < 3:
            continue

        file_glob, finding_type, evidence_pattern = parts[:3]
        owner_match = re.search(r"#\s*owner:\s*([^#]+)", f"#{comment_blob}", re.IGNORECASE)
        reason_match = re.search(r"#\s*reason:\s*(.+)$", f"#{comment_blob}", re.IGNORECASE)
        if not owner_match or not reason_match:
            continue
        try:
            entries.append(
                AllowlistEntry(
                    file_glob=file_glob,
                    finding_type=finding_type,
                    evidence_pattern=re.compile(evidence_pattern or ".*"),
                    owner=owner_match.group(1).strip(),
                    reason=reason_match.group(1).strip(),
                )
            )
        except re.error:
            continue

    return entries


def _is_allowlisted_by_file(rel_path: str, finding_type: str, evidence: str, allowlist: list[AllowlistEntry]) -> bool:
    normalized = rel_path.replace("\\", "/")
    for entry in allowlist:
        if not fnmatch(normalized, entry.file_glob):
            continue
        if entry.finding_type not in {"*", finding_type}:
            continue
        if entry.evidence_pattern.search(evidence):
            return True
    return False


def _scan_secrets(
    repo_root: Path,
    files: list[Path],
    *,
    include_test_fixtures: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    allowlist = _load_secret_allowlist(repo_root)
    for path in files:
        rel = str(path.relative_to(repo_root))
        if not include_test_fixtures and _matches_fixture_path(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for idx, line in enumerate(text.splitlines(), 1):
            if _is_allowlisted_fixture_line(rel, line):
                continue
            if _is_env_reference_line(line):
                continue
            for finding_type, title, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    evidence = line.strip()
                    if _is_allowlisted_by_file(rel, finding_type, evidence, allowlist):
                        continue
                    candidate = _extract_secret_candidate(line)
                    severity = _secret_finding_severity(rel, finding_type, candidate)
                    if severity is None:
                        continue
                    findings.append(
                        Finding(
                            severity=severity,
                            type=finding_type,
                            title=title,
                            file=rel,
                            line=idx,
                            evidence=line.strip()[:220],
                            recommendation="Move sensitive values to runtime secrets and rotate exposed credentials.",
                        )
                    )

            if _contains_high_entropy_secret_literal(line):
                evidence = line.strip()
                if _is_allowlisted_by_file(rel, "high_entropy_secret_literal", evidence, allowlist):
                    continue
                candidate = _extract_secret_candidate(line)
                severity = _secret_finding_severity(rel, "high_entropy_secret_literal", candidate)
                if severity is None:
                    continue
                findings.append(
                    Finding(
                        severity=severity,
                        type="high_entropy_secret_literal",
                        title="Potential high-entropy secret literal",
                        file=rel,
                        line=idx,
                        evidence=line.strip()[:220],
                        recommendation="Store generated secrets in a secrets manager and rotate exposed values.",
                    )
                )
    return findings


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * log2(probability)
    return entropy


def _contains_high_entropy_secret_literal(line: str) -> bool:
    if "http://" in line or "https://" in line:
        return False
    if _is_env_reference_line(line):
        return False
    if not re.search(r"(?i)(api[_-]?key|token|secret|password|session)", line):
        return False
    for candidate in re.findall(r"['\"]([A-Za-z0-9_\-+/=]{20,})['\"]", line):
        if _has_mixed_character_classes(candidate) and _shannon_entropy(candidate) >= SECRET_ENTROPY_THRESHOLD:
            return True
    return False


def _scan_ci_config(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows_dir = repo_root / ".github" / "workflows"
    if not workflows_dir.exists():
        findings.append(
            Finding(
                severity="MEDIUM",
                type="missing_ci_workflows",
                title="No CI workflows found",
                file=".github/workflows",
                line=None,
                evidence="workflow directory missing",
                recommendation="Add CI workflows with security and regression gates.",
            )
        )
        return findings

    for wf in workflows_dir.glob("*.y*ml"):
        rel = str(wf.relative_to(repo_root))
        text = wf.read_text(encoding="utf-8", errors="ignore")
        if "pull_request_target" in text:
            findings.append(
                Finding(
                    severity="HIGH",
                    type="risky_pr_target_trigger",
                    title="Workflow uses pull_request_target",
                    file=rel,
                    line=None,
                    evidence="pull_request_target trigger present",
                    recommendation="Use pull_request unless pull_request_target is strictly required and hardened.",
                )
            )
        if "permissions: write-all" in text:
            findings.append(
                Finding(
                    severity="HIGH",
                    type="broad_workflow_permissions",
                    title="Workflow uses write-all permissions",
                    file=rel,
                    line=None,
                    evidence="permissions: write-all",
                    recommendation="Apply least-privilege job permissions.",
                )
            )
    return findings


def _scan_dependency_hygiene(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    deps = _load_declared_dependencies(repo_root)
    if deps is None:
        findings.append(
            Finding(
                severity="MEDIUM",
                type="missing_pyproject",
                title="Missing pyproject.toml",
                file="pyproject.toml",
                line=None,
                evidence="file not found",
                recommendation="Define dependencies and build metadata in pyproject.toml.",
            )
        )
        return findings

    for dep in deps:
        dep_text = str(dep)
        if not any(op in dep_text for op in [">=", "==", "~=", "<=", "<", ">"]):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    type="unpinned_dependency",
                    title="Dependency has no version constraint",
                    file="pyproject.toml",
                    line=None,
                    evidence=dep_text,
                    recommendation="Add explicit dependency version constraints for reproducibility.",
                )
            )

    return findings


def _load_declared_dependencies(repo_root: Path) -> list[str] | None:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return None

    data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="ignore"))
    deps = list(((data.get("project") or {}).get("dependencies") or []))
    optional = ((data.get("project") or {}).get("optional-dependencies") or {})
    for _, values in optional.items():
        deps.extend(values or [])
    return [str(dep) for dep in deps]


def _severity_rank(value: str | None) -> int:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(str(value or "").strip().upper(), 0)


def _parse_pip_audit_payload(payload: dict, report_rel: str) -> tuple[list[Finding], list[dict[str, str]]]:
    findings: list[Finding] = []
    metadata: list[dict[str, str]] = []

    dependencies = []
    if isinstance(payload, dict):
        dependencies = payload.get("dependencies") or []
    if not isinstance(dependencies, list):
        return findings, metadata

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or "unknown")
        version = str(dep.get("version") or "unknown")
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id") or vuln.get("alias") or "unknown-advisory")
            description = str(vuln.get("description") or "Dependency vulnerability detected")
            fix_versions = vuln.get("fix_versions") or []
            fix_hint = ", ".join(str(item) for item in fix_versions[:3]) if isinstance(fix_versions, list) and fix_versions else "latest secure version"
            severity = _normalize_dependency_severity(vuln.get("severity"))
            finding_type = _classify_dependency_finding_type(advisory_id=vuln_id, description=description)
            findings.append(
                Finding(
                    severity=severity,
                    type=finding_type,
                    title=f"Dependency advisory: {vuln_id}",
                    file=report_rel,
                    line=None,
                    evidence=f"{name}=={version}: {description[:160]}",
                    recommendation=f"Upgrade {name} to a patched version ({fix_hint}) and rerun dependency audit.",
                )
            )
            metadata.append(
                {
                    "package": name,
                    "version": version,
                    "advisory_id": vuln_id,
                    "severity": severity,
                    "language": "python",
                    "reachability": "unknown",
                    "tool": "pip_audit",
                    "type": finding_type,
                }
            )

    return findings, metadata


def _parse_osv_payload(payload: dict) -> tuple[list[Finding], list[dict[str, str]]]:
    findings: list[Finding] = []
    metadata: list[dict[str, str]] = []

    results = payload.get("results") if isinstance(payload, dict) else []
    if not isinstance(results, list):
        return findings, metadata

    for result in results:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages") or []
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            package_info_obj = package.get("package")
            package_info = package_info_obj if isinstance(package_info_obj, dict) else {}
            package_name = str(package_info.get("name") or package.get("name") or "unknown")
            ecosystem = str(package_info.get("ecosystem") or package.get("ecosystem") or "")
            language = ECOSYSTEM_LANGUAGE_MAP.get(ecosystem, "unknown")
            is_direct = bool(package.get("isDirect") or package.get("direct") or package.get("is_direct"))
            reachability = "direct" if is_direct else "transitive"

            vulnerabilities = package.get("vulnerabilities") or result.get("vulnerabilities") or package.get("vulns") or []
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or (vuln.get("aliases") or ["unknown-osv"])[0])
                summary = str(vuln.get("summary") or vuln.get("details") or "Dependency vulnerability detected")
                severity = _normalize_dependency_severity(vuln.get("severity") or vuln.get("database_specific", {}).get("severity"))
                finding_type = _classify_dependency_finding_type(advisory_id=vuln_id, description=summary)
                findings.append(
                    Finding(
                        severity=severity,
                        type=finding_type,
                        title=f"Dependency advisory: {vuln_id}",
                        file="osv-scanner",
                        line=None,
                        evidence=f"{package_name} ({ecosystem or 'unknown ecosystem'}, {reachability}): {summary[:160]}",
                        recommendation=f"Upgrade or replace {package_name}, verify lockfiles, and rerun osv-scanner.",
                    )
                )
                metadata.append(
                    {
                        "package": package_name,
                        "version": str(package.get("version") or package_info.get("version") or "unknown"),
                        "advisory_id": vuln_id,
                        "severity": severity,
                        "language": language,
                        "reachability": reachability,
                        "tool": "osv_scanner",
                        "type": finding_type,
                    }
                )

    return findings, metadata


def _scan_dependency_advisories(repo_root: Path, *, deps_scan: str = "auto", timeout_seconds: int = 180) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    raw_findings, dependency_summary = scan_dependency_advisories(
        repo_root,
        deps_scan=deps_scan,
        timeout_seconds=timeout_seconds,
    )
    for raw in raw_findings:
        try:
            findings.append(Finding(**raw))
        except TypeError:
            continue
    return findings, dependency_summary


def _scan_language_risks(repo_root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []

    for path in files:
        suffix = path.suffix.lower()
        if suffix not in {".py", ".js", ".ts", ".tsx", ".jsx"}:
            continue

        rel = str(path.relative_to(repo_root))
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for idx, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _is_allowlisted_fixture_line(rel, line):
                continue

            if suffix == ".py":
                for finding_type, title, severity, pattern, recommendation in PY_RISK_PATTERNS:
                    if finding_type == "python_yaml_unsafe_load":
                        if "yaml.load(" in line and "SafeLoader" not in line:
                            findings.append(
                                Finding(
                                    severity=severity,
                                    type=finding_type,
                                    title=title,
                                    file=rel,
                                    line=idx,
                                    evidence=stripped[:220],
                                    recommendation=recommendation,
                                )
                            )
                        continue

                    if pattern.search(line):
                        findings.append(
                            Finding(
                                severity=severity,
                                type=finding_type,
                                title=title,
                                file=rel,
                                line=idx,
                                evidence=stripped[:220],
                                recommendation=recommendation,
                            )
                        )

            if suffix in {".js", ".ts", ".tsx", ".jsx"}:
                for finding_type, title, severity, pattern, recommendation in JS_RISK_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                severity=severity,
                                type=finding_type,
                                title=title,
                                file=rel,
                                line=idx,
                                evidence=stripped[:220],
                                recommendation=recommendation,
                            )
                        )

            for finding_type, title, severity, pattern, recommendation in WEAK_CRYPTO_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            severity=severity,
                            type=finding_type,
                            title=title,
                            file=rel,
                            line=idx,
                            evidence=stripped[:220],
                            recommendation=recommendation,
                        )
                    )

            for finding_type, title, severity, pattern, recommendation in DRIFT_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            severity=severity,
                            type=finding_type,
                            title=title,
                            file=rel,
                            line=idx,
                            evidence=stripped[:220],
                            recommendation=recommendation,
                        )
                    )

    return findings


def _score(findings: list[Finding]) -> tuple[int, dict[str, int], dict[str, int]]:
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_type[finding.type] = by_type.get(finding.type, 0) + 1

    penalty = by_severity["CRITICAL"] * 30 + by_severity["HIGH"] * 12 + by_severity["MEDIUM"] * 5 + by_severity["LOW"] * 2
    risk_score = max(0, 100 - penalty)
    return risk_score, by_severity, by_type


def _load_threat_feed(repo_root: Path, threat_feed_path: str | None) -> tuple[dict[str, list[dict[str, str]]], list[Finding], str]:
    findings: list[Finding] = []
    source = "built_in"

    if threat_feed_path:
        path = Path(threat_feed_path)
        if not path.is_absolute():
            path = repo_root / path
    else:
        path = repo_root / "threat_feed.json"

    feed_records: list[dict[str, str]] = DEFAULT_THREAT_FEED
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(raw, list):
                source = str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)
                feed_records = [item for item in raw if isinstance(item, dict)]
            else:
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        type="invalid_threat_feed",
                        title="Invalid threat feed format",
                        file=str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path),
                        line=None,
                        evidence="threat feed must be a JSON array",
                        recommendation="Format threat_feed.json as a JSON array of mapping objects.",
                    )
                )
        except json.JSONDecodeError:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    type="invalid_threat_feed",
                    title="Threat feed parse failure",
                    file=str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path),
                    line=None,
                    evidence="invalid JSON",
                    recommendation="Fix JSON syntax in threat_feed.json.",
                )
            )

    index: dict[str, list[dict[str, str]]] = defaultdict(list)
    for item in feed_records:
        finding_type = str(item.get("finding_type") or "").strip()
        if not finding_type:
            continue
        index[finding_type].append(
            {
                "threat": str(item.get("threat") or "unknown"),
                "reference": str(item.get("reference") or ""),
            }
        )

    return dict(index), findings, source


def _serialize_finding(finding: Finding, threat_index: dict[str, list[dict[str, str]]]) -> dict:
    data = finding.as_dict()
    contexts = threat_index.get(finding.type) or []
    if contexts:
        data["threat_context"] = contexts
    return data


def _normalize_public_github_repo_url(repo_url: str) -> str:
    raw = str(repo_url or "").strip()
    if not raw:
        raise ValueError("repo_url is required")
    if raw.startswith("git@"):
        raise ValueError("SSH clone URLs are not supported for public GitHub repo audits")

    if "://" not in raw:
        raw = f"https://github.com/{raw.lstrip('/')}"

    parsed = urlparse(raw)
    host = parsed.netloc.lower()
    if host not in {"github.com", "www.github.com"}:
        raise ValueError("Only public github.com repository URLs are supported in this phase")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("GitHub repository URL must not include credentials or custom ports")
    if parsed.query or parsed.fragment:
        raise ValueError("GitHub repository URL must not include query strings or fragments")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub repository URL must include owner and repo name")
    if len(parts) > 2:
        raise ValueError("GitHub repository URL must point to the repository root")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not GITHUB_OWNER_RE.fullmatch(owner):
        raise ValueError("Invalid GitHub repository owner")
    if not GITHUB_REPO_RE.fullmatch(repo):
        raise ValueError("Invalid GitHub repository name")
    return f"https://github.com/{owner}/{repo}.git"


def _clone_resource_limits() -> None:
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (200 * 1024 * 1024, 200 * 1024 * 1024))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Private-repo clone helpers (Phase 3)
# ---------------------------------------------------------------------------

def _make_askpass_script(token: str) -> Path:
    """Write a minimal GIT_ASKPASS script that echoes the token securely.

    The token is stored in a chmod-700 temp file so it never appears in
    subprocess command-line arguments (visible in /proc/$PID/cmdline).
    The file is deleted by the caller after the clone completes.
    """
    # Escape single quotes so the script can't be shell-injected.
    safe_token = token.replace("'", "'\\''")
    fd, path_str = tempfile.mkstemp(prefix="aletheia-git-cred-", suffix=".sh")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f"#!/bin/sh\nprintf '%s' '{safe_token}'\n")
    except Exception:
        os.unlink(path_str)
        raise
    cred_path = Path(path_str)
    cred_path.chmod(stat.S_IRWXU)
    return cred_path


def _clone_github_repo(
    repo_url: str,
    clone_root: Path,
    *,
    token: str | None = None,
) -> tuple[Path, str]:
    """Clone a GitHub repository (public or private) and return ``(clone_root, display_url)``.

    When *token* is provided it is passed via ``GIT_ASKPASS`` so it never
    appears in subprocess command-line arguments.  The display URL returned is
    always the token-free HTTPS URL suitable for logging and summary output.
    """
    canonical_url = _normalize_public_github_repo_url(repo_url)
    clone_root.mkdir(parents=True, exist_ok=True)
    timeout_seconds = max(30, min(900, int(os.environ.get("ALETHEIA_REPO_CLONE_TIMEOUT_SEC", "180"))))
    env = dict(os.environ)
    env.setdefault("GIT_TERMINAL_PROMPT", "0")

    cred_path: Path | None = None
    if token:
        cred_path = _make_askpass_script(token)
        env["GIT_ASKPASS"] = str(cred_path)
        env["GIT_USERNAME"] = "x-token-auth"

    run_kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": timeout_seconds,
        "env": env,
    }
    if os.name != "nt" and resource is not None:
        run_kwargs["preexec_fn"] = _clone_resource_limits

    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--depth",
                "1",
                "--single-branch",
                canonical_url,
                str(clone_root),
            ],
            **run_kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Unable to clone GitHub repository {canonical_url}: clone timed out after {timeout_seconds}s"
        ) from exc
    finally:
        if cred_path and cred_path.exists():
            cred_path.unlink(missing_ok=True)

    if result.returncode != 0:
        details = (result.stderr or result.stdout or "unknown clone failure").strip()
        raise RuntimeError(f"Unable to clone GitHub repository {canonical_url}: {details}")
    return clone_root, canonical_url


# ---------------------------------------------------------------------------
# Optional external scanner integrations (Phase 3)
# ---------------------------------------------------------------------------

def _run_tool_json(
    cmd: list[str],
    cwd: str,
    timeout: int,
) -> tuple[dict | list | None, str | None]:
    """Run *cmd* and return ``(parsed_json, error_reason)``."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        payload_text = result.stdout.strip()
        if not payload_text:
            return None, "empty_output"
        return json.loads(payload_text), None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except json.JSONDecodeError:
        return None, "non_json_output"
    except FileNotFoundError:
        return None, "binary_not_found"


def _scan_semgrep(repo_root: Path) -> tuple[list[Finding], dict]:
    """Run ``semgrep --config auto`` and normalise findings (Phase 3)."""
    tool_key = "semgrep"
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return [], {tool_key: {"status": "unavailable", "reason": "binary_not_found"}}

    payload, err = _run_tool_json(
        [semgrep_bin, "--config", "auto", "--json", "--no-git-ignore", "--quiet", "."],
        cwd=str(repo_root),
        timeout=300,
    )
    if payload is None:
        status = "timeout" if err == "timeout" else "invalid_output"
        return [], {tool_key: {"status": status, "reason": err or "unknown"}}

    findings: list[Finding] = []
    for item in (payload.get("results") or []) if isinstance(payload, dict) else []:
        sev_raw = str((item.get("extra") or {}).get("severity") or "WARNING").upper()
        severity = "HIGH" if sev_raw in {"ERROR", "HIGH"} else ("LOW" if sev_raw in {"INFO", "LOW"} else "MEDIUM")
        findings.append(
            Finding(
                severity=severity,
                type="semgrep_" + re.sub(r"[^a-z0-9_]", "_", str(item.get("check_id") or "finding").lower())[:64],
                title=str((item.get("extra") or {}).get("message") or item.get("check_id") or "Semgrep finding"),
                file=str(item.get("path") or "unknown"),
                line=int((item.get("start") or {}).get("line") or 0) or None,
                evidence=str((item.get("extra") or {}).get("lines") or "")[:256],
                recommendation=str((item.get("extra") or {}).get("fix") or "Review semgrep finding and remediate per rule guidance."),
            )
        )
    return findings, {
        tool_key: {
            "status": "executed",
            "findings": len(findings),
        }
    }


def _scan_bandit(repo_root: Path) -> tuple[list[Finding], dict]:
    """Run ``bandit -r -f json`` and normalise findings (Phase 3)."""
    tool_key = "bandit"
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return [], {tool_key: {"status": "unavailable", "reason": "binary_not_found"}}

    payload, err = _run_tool_json(
        [bandit_bin, "-r", "-f", "json", "--quiet", "."],
        cwd=str(repo_root),
        timeout=180,
    )
    if payload is None:
        status = "timeout" if err == "timeout" else "invalid_output"
        return [], {tool_key: {"status": status, "reason": err or "unknown"}}

    findings: list[Finding] = []
    for item in (payload.get("results") or []) if isinstance(payload, dict) else []:
        sev_raw = str(item.get("issue_severity") or "MEDIUM").upper()
        severity = sev_raw if sev_raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
        findings.append(
            Finding(
                severity=severity,
                type="bandit_" + re.sub(r"[^a-z0-9_]", "_", str(item.get("test_id") or "finding").lower()),
                title=str(item.get("issue_text") or "Bandit finding"),
                file=str(item.get("filename") or "unknown"),
                line=int(item.get("line_number") or 0) or None,
                evidence=str(item.get("code") or "")[:256],
                recommendation="Review bandit finding and remediate per CWE guidance.",
            )
        )
    return findings, {
        tool_key: {
            "status": "executed",
            "findings": len(findings),
        }
    }


def _scan_trivy(repo_root: Path) -> tuple[list[Finding], dict]:
    """Run ``trivy fs --format json`` and normalise findings (Phase 3)."""
    tool_key = "trivy"
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        return [], {tool_key: {"status": "unavailable", "reason": "binary_not_found"}}

    payload, err = _run_tool_json(
        [trivy_bin, "fs", "--format", "json", "--quiet", "."],
        cwd=str(repo_root),
        timeout=300,
    )
    if payload is None:
        status = "timeout" if err == "timeout" else "invalid_output"
        return [], {tool_key: {"status": status, "reason": err or "unknown"}}

    findings: list[Finding] = []
    for result_block in (payload.get("Results") or []) if isinstance(payload, dict) else []:
        target_file = str(result_block.get("Target") or "unknown")
        for vuln in result_block.get("Vulnerabilities") or []:
            sev_raw = str(vuln.get("Severity") or "MEDIUM").upper()
            severity = sev_raw if sev_raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
            vuln_id = str(vuln.get("VulnerabilityID") or "unknown")
            pkg_name = str(vuln.get("PkgName") or "unknown")
            findings.append(
                Finding(
                    severity=severity,
                    type="trivy_vuln",
                    title=f"{vuln_id} in {pkg_name}",
                    file=target_file,
                    line=None,
                    evidence=str(vuln.get("Title") or vuln.get("Description") or "")[:256],
                    recommendation=str(vuln.get("FixedVersion") and f"Upgrade {pkg_name} to {vuln['FixedVersion']}." or "Review Trivy advisory and apply available fix."),
                )
            )
    return findings, {
        tool_key: {
            "status": "executed",
            "findings": len(findings),
        }
    }


def _scan_npm_audit(repo_root: Path) -> tuple[list[Finding], dict]:
    """Run ``npm audit --json`` on any ``package.json`` found (Phase 3)."""
    tool_key = "npm_audit"
    npm_bin = shutil.which("npm")
    if not npm_bin:
        return [], {tool_key: {"status": "unavailable", "reason": "binary_not_found"}}
    if not (repo_root / "package.json").exists():
        return [], {tool_key: {"status": "skipped", "reason": "no_package_json"}}

    payload, err = _run_tool_json(
        [npm_bin, "audit", "--json"],
        cwd=str(repo_root),
        timeout=120,
    )
    if payload is None:
        status = "timeout" if err == "timeout" else "invalid_output"
        return [], {tool_key: {"status": status, "reason": err or "unknown"}}

    findings: list[Finding] = []
    # npm audit --json format (npm v7+)
    for pkg_name, vuln in (payload.get("vulnerabilities") or {}).items():
        if not isinstance(vuln, dict):
            continue
        sev_raw = str(vuln.get("severity") or "moderate").lower()
        severity_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
        severity = severity_map.get(sev_raw, "MEDIUM")
        via = vuln.get("via") or []
        evidence_parts = [str(v.get("title") or v) for v in via if isinstance(v, dict)][:3]
        findings.append(
            Finding(
                severity=severity,
                type="npm_audit_vuln",
                title=f"npm vulnerability in {pkg_name}",
                file="package.json",
                line=None,
                evidence="; ".join(evidence_parts)[:256] or f"severity: {sev_raw}",
                recommendation=f"Run 'npm audit fix' or upgrade {pkg_name} to a non-vulnerable version.",
            )
        )
    return findings, {
        tool_key: {
            "status": "executed",
            "findings": len(findings),
        }
    }


def _clone_public_github_repo(repo_url: str, clone_root: Path) -> Path:
    canonical_url = _normalize_public_github_repo_url(repo_url)
    clone_root.mkdir(parents=True, exist_ok=True)
    timeout_seconds = max(30, min(900, int(os.environ.get("ALETHEIA_REPO_CLONE_TIMEOUT_SEC", "180"))))
    env = dict(os.environ)
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    run_kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": timeout_seconds,
        "env": env,
    }
    if os.name != "nt" and resource is not None:
        run_kwargs["preexec_fn"] = _clone_resource_limits

    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--depth",
                "1",
                "--single-branch",
                canonical_url,
                str(clone_root),
            ],
            **run_kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Unable to clone public GitHub repository {canonical_url}: clone timed out after {timeout_seconds}s"
        ) from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "unknown clone failure").strip()
        raise RuntimeError(f"Unable to clone public GitHub repository {canonical_url}: {details}")
    return clone_root


def _audit_repo_root(
    root: Path,
    *,
    threat_feed_path: str | None,
    include_test_fixtures: bool,
    deps_scan: str,
    dep_scan_timeout: int,
    history_scan_depth: int,
    enabled_scanners: set[str] | None = None,
) -> dict:
    """Core scanning dispatch.  *enabled_scanners* is a set of scanner names
    to run; when ``None`` the medium (default) profile is used."""
    if enabled_scanners is None:
        enabled_scanners = set(SCAN_PROFILE_MEDIUM)

    files = _iter_source_files(root)

    findings: list[Finding] = []
    if "secrets" in enabled_scanners:
        findings.extend(_scan_secrets(root, files, include_test_fixtures=include_test_fixtures))
    if "ci_config" in enabled_scanners:
        findings.extend(_scan_ci_config(root))
    if "dep_hygiene" in enabled_scanners:
        findings.extend(_scan_dependency_hygiene(root))

    # dep_advisories honours the legacy deps_scan knob inside the profile
    dep_findings: list[Finding] = []
    dependency_summary: dict = {"scan_mode": deps_scan, "tools": {}}
    if "dep_advisories" in enabled_scanners:
        dep_findings, dependency_summary = _scan_dependency_advisories(
            root,
            deps_scan=deps_scan,
            timeout_seconds=dep_scan_timeout,
        )
    findings.extend(dep_findings)

    if "language_risks" in enabled_scanners:
        findings.extend(_scan_language_risks(root, files))

    threat_index, threat_feed_findings, threat_feed_source = _load_threat_feed(root, threat_feed_path)
    if "threat_feed" in enabled_scanners:
        findings.extend(threat_feed_findings)

    # Optional external-tool scanners (Phase 3)
    extra_tool_summary: dict[str, dict] = {}
    if "semgrep" in enabled_scanners:
        sg_findings, sg_meta = _scan_semgrep(root)
        findings.extend(sg_findings)
        extra_tool_summary.update(sg_meta)
    if "bandit" in enabled_scanners:
        bd_findings, bd_meta = _scan_bandit(root)
        findings.extend(bd_findings)
        extra_tool_summary.update(bd_meta)
    if "trivy" in enabled_scanners:
        tv_findings, tv_meta = _scan_trivy(root)
        findings.extend(tv_findings)
        extra_tool_summary.update(tv_meta)
    if "npm_audit" in enabled_scanners:
        na_findings, na_meta = _scan_npm_audit(root)
        findings.extend(na_findings)
        extra_tool_summary.update(na_meta)

    if "git_history_secrets" in enabled_scanners:
        gh_findings, gh_meta = scan_git_history_secrets(root, history_scan_depth=history_scan_depth)
        findings.extend(Finding(**finding) for finding in gh_findings)
        extra_tool_summary["git_history_secrets"] = gh_meta

    # Deduplicate same type/file/line/evidence to reduce noise.
    deduped: dict[tuple[str, str, int | None, str], Finding] = {}
    for finding in findings:
        key = (finding.type, finding.file, finding.line, finding.evidence)
        deduped[key] = finding
    unique_findings = list(deduped.values())

    filtered_findings = [
        finding
        for finding in unique_findings
        if not should_ignore_finding(finding, ignore_test_fixtures=not include_test_fixtures)
    ]

    first_party_non_test_findings = [
        finding
        for finding in filtered_findings
        if is_first_party_file(finding.file) and not is_test_file(finding.file)
    ]
    first_party_non_test_high = sum(1 for finding in first_party_non_test_findings if finding.severity == "HIGH")
    first_party_non_test_critical = sum(1 for finding in first_party_non_test_findings if finding.severity == "CRITICAL")

    risk_score, by_severity, by_type = _score(filtered_findings)

    threat_match_total = 0
    threat_match_by_type: dict[str, int] = {}
    for finding in filtered_findings:
        if finding.type in threat_index:
            threat_match_total += 1
            threat_match_by_type[finding.type] = threat_match_by_type.get(finding.type, 0) + 1

    gates = {
        "pass": first_party_non_test_critical == 0 and first_party_non_test_high <= 5,
        "violations": [],
    }
    if first_party_non_test_critical > 0:
        gates["violations"].append("critical_repo_findings")
    if first_party_non_test_high > 5:
        gates["violations"].append("high_repo_findings_over_limit")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "repo",
        "repo_root": str(root),
        "source": {
            "kind": "local_path",
            "value": str(root),
        },
        "files_scanned": len(files),
        "secret_scan": {
            "include_test_fixtures": include_test_fixtures,
            "excluded_globs": [] if include_test_fixtures else list(TEST_FIXTURE_GLOBS),
            "allowlist_marker": TEST_FIXTURE_ALLOWLIST_MARKER,
        },
        "enabled_scanners": sorted(enabled_scanners),
        "ignored_artifacts": list(GENERATED_ARTIFACT_GLOBS),
        "dependencies": dependency_summary,
        "extra_tools": extra_tool_summary,
        "findings_total": len(filtered_findings),
        "findings_by_severity": by_severity,
        "findings_by_type": by_type,
        "first_party_non_test_findings_total": len(first_party_non_test_findings),
        "first_party_non_test_by_severity": {
            "CRITICAL": first_party_non_test_critical,
            "HIGH": first_party_non_test_high,
            "MEDIUM": sum(1 for finding in first_party_non_test_findings if finding.severity == "MEDIUM"),
            "LOW": sum(1 for finding in first_party_non_test_findings if finding.severity == "LOW"),
        },
        "first_party_non_test_high_critical_count": first_party_non_test_critical + first_party_non_test_high,
        "risk_score": risk_score,
        "threat_feed": {
            "source": threat_feed_source,
            "matches_total": threat_match_total,
            "matches_by_type": threat_match_by_type,
        },
        "gates": gates,
        "findings": [
            _serialize_finding(finding, threat_index)
            for finding in sorted(filtered_findings, key=lambda item: (item.severity, item.file, item.line or 0))
        ],
    }


def run_repo_audit(
    repo_path: str | Path = ".",
    repo_url: str | None = None,
    threat_feed_path: str | None = None,
    *,
    include_test_fixtures: bool = False,
    deps_scan: str = "auto",
    dep_scan_timeout: int = 180,
    history_scan_depth: int = 100,
    repo_token: str | None = None,
    scan_profile: str | None = None,
    scan_profile_file: str | None = None,
    enrich_report: bool = False,
) -> dict:
    """Run static repository checks and return summary dictionary.

    Parameters
    ----------
    repo_path:
        Local filesystem path to audit (default: current directory).
    repo_url:
        GitHub HTTPS URL to clone and audit.  Supports public repos as well
        as private repos when *repo_token* is provided.
    repo_token:
        GitHub personal-access token (PAT) or fine-grained token with
        ``Contents: read`` scope.  Passed via ``GIT_ASKPASS``; never logged
        or stored in summary output.
    scan_profile:
        One of ``"light"``, ``"medium"`` (default), ``"full"``, or
        ``"custom"`` (requires *scan_profile_file*).
    scan_profile_file:
        JSON file path for a custom profile.  Must contain
        ``{"scanners": ["secrets", "bandit", ...]}``.  Only used when
        *scan_profile* is ``"custom"``.
    deps_scan:
        Dependency-advisory scan mode: ``"auto"``, ``"full"``, or ``"off"``.
        Overridden when *scan_profile* is ``"light"`` (sets to ``"off"``
        implicitly via enabled_scanners).
    dep_scan_timeout:
        Maximum runtime in seconds for dependency advisory tooling.
    history_scan_depth:
        Commit history depth to inspect for git-history secret scanning.
    enrich_report:
        When True, attach a report overview summary to the audit output.
    """
    # Resolve the active scanner set once so both code paths share it.
    effective_deps_scan = deps_scan
    if scan_profile == "light":
        # light profile excludes dep_advisories; honour explicit override
        effective_deps_scan = "off"
    enabled_scanners = _resolve_scan_profile(scan_profile, scan_profile_file)

    if repo_url:
        with tempfile.TemporaryDirectory(prefix="aletheia-github-repo-") as temp_dir:
            root, display_url = _clone_github_repo(
                repo_url, Path(temp_dir), token=repo_token
            )
            summary = _audit_repo_root(
                root,
                threat_feed_path=threat_feed_path,
                include_test_fixtures=include_test_fixtures,
                deps_scan=effective_deps_scan,
                dep_scan_timeout=dep_scan_timeout,
                history_scan_depth=history_scan_depth,
                enabled_scanners=enabled_scanners,
            )
            is_private = bool(repo_token)
            summary["source"] = {
                "kind": "github_private" if is_private else "github_public",
                "value": repo_url,
                "resolved": display_url,
                "authenticated": is_private,
            }
            summary["scan_profile"] = scan_profile or "medium"
            if enrich_report:
                summary = enrich_repo_summary(summary)
            return summary

    root = Path(repo_path).resolve()
    summary = _audit_repo_root(
        root,
        threat_feed_path=threat_feed_path,
        include_test_fixtures=include_test_fixtures,
        deps_scan=effective_deps_scan,
        dep_scan_timeout=dep_scan_timeout,
        history_scan_depth=history_scan_depth,
        enabled_scanners=enabled_scanners,
    )
    summary["scan_profile"] = scan_profile or "medium"
    if enrich_report:
        summary = enrich_repo_summary(summary)
    return summary
