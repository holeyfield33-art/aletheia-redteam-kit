"""Static repository risk scanner for secrets, config, and dependency hygiene."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from math import log2
from pathlib import Path
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

try:  # pragma: no cover - unavailable on some platforms
    import resource
except Exception:  # pragma: no cover - defensive
    resource = None


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
        if rel.parts and rel.parts[0] in {".git", ".venv", "venv", "env", "node_modules", "dist", "build", "__pycache__", ".pytest_cache"}:
            continue
        if any(fnmatch(str(rel).replace("\\", "/"), pattern) for pattern in GENERATED_ARTIFACT_GLOBS):
            continue
        if _is_probably_text(path):
            files.append(path)
    return files


def _is_ignored_scan_path(path: Path) -> bool:
    return any(part in {".git", ".venv", "venv", "env", "node_modules", "dist", "build", "__pycache__", ".pytest_cache"} for part in path.parts)


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


def _scan_secrets(
    repo_root: Path,
    files: list[Path],
    *,
    include_test_fixtures: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
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
            for finding_type, title, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            severity="CRITICAL" if finding_type == "private_key_block" else "HIGH",
                            type=finding_type,
                            title=title,
                            file=rel,
                            line=idx,
                            evidence=line.strip()[:220],
                            recommendation="Move sensitive values to runtime secrets and rotate exposed credentials.",
                        )
                    )

            if _contains_high_entropy_secret_literal(line):
                findings.append(
                    Finding(
                        severity="HIGH",
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
    if not re.search(r"(?i)(api[_-]?key|token|secret|password|session)", line):
        return False
    for candidate in re.findall(r"['\"]([A-Za-z0-9_\-+/=]{20,})['\"]", line):
        has_alpha = any(char.isalpha() for char in candidate)
        has_digit = any(char.isdigit() for char in candidate)
        has_symbol = any(char in "_-+/=" for char in candidate)
        if (has_alpha and has_digit and has_symbol) and _shannon_entropy(candidate) >= 3.6:
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


def _normalize_dependency_severity(value: str | None) -> str:
    severity = str(value or "").strip().upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return severity
    if severity in {"MODERATE"}:
        return "MEDIUM"
    return "HIGH"


def _classify_dependency_finding_type(*, advisory_id: str, description: str) -> str:
    blob = f"{advisory_id} {description}".lower()
    if any(token in blob for token in ("malware", "backdoor", "trojan", "compromised")):
        return "dependency_malware_suspect"
    if any(token in blob for token in ("typosquat", "typosquatting", "dependency confusion", "substitution")):
        return "dependency_tampering_risk"
    return "dependency_vulnerability"


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
                        "severity": severity,
                        "language": language,
                        "reachability": reachability,
                        "tool": "osv_scanner",
                        "type": finding_type,
                    }
                )

    return findings, metadata


def _scan_dependency_advisories(repo_root: Path, *, deps_scan: str = "auto") -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    dep_meta: list[dict[str, str]] = []
    manifests = _detect_dependency_manifests(repo_root)

    tools: dict[str, dict[str, str]] = {
        "pip_audit": {"status": "not_run"},
        "osv_scanner": {"status": "not_run"},
    }

    report_path = repo_root / "pip-audit-report.json"
    report_rel = str(report_path.relative_to(repo_root))
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
            report_findings, report_meta = _parse_pip_audit_payload(report, report_rel)
            findings.extend(report_findings)
            dep_meta.extend(report_meta)
            tools["pip_audit"] = {"status": "report_loaded", "source": report_rel}
        except json.JSONDecodeError:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    type="invalid_pip_audit_report",
                    title="Invalid pip-audit report format",
                    file=report_rel,
                    line=None,
                    evidence="Could not parse pip-audit-report.json as JSON",
                    recommendation="Regenerate report using 'pip-audit -f json -o pip-audit-report.json'.",
                )
            )
            tools["pip_audit"] = {"status": "report_invalid", "source": report_rel}

    python_manifests = manifests.get("python") or []
    if deps_scan in {"auto", "full"} and python_manifests and tools["pip_audit"]["status"] == "not_run":
        pip_audit_bin = shutil.which("pip-audit")
        if not pip_audit_bin:
            tools["pip_audit"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            try:
                result = subprocess.run(
                    [pip_audit_bin, "-f", "json"],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                payload_text = result.stdout.strip() or "{}"
                payload = json.loads(payload_text)
                report_findings, report_meta = _parse_pip_audit_payload(payload, "pip-audit:runtime")
                findings.extend(report_findings)
                dep_meta.extend(report_meta)
                tools["pip_audit"] = {
                    "status": "executed",
                    "exit_code": str(result.returncode),
                    "source": "runtime_scan",
                }
            except subprocess.TimeoutExpired:
                tools["pip_audit"] = {"status": "timeout", "reason": "scan_timed_out"}
            except json.JSONDecodeError:
                tools["pip_audit"] = {"status": "invalid_output", "reason": "non_json_output"}

    non_python_manifests = any((paths for language, paths in manifests.items() if language != "python" and paths))
    should_run_osv = deps_scan == "full" or (deps_scan == "auto" and non_python_manifests)
    if should_run_osv:
        osv_bin = shutil.which("osv-scanner")
        if not osv_bin:
            tools["osv_scanner"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            osv_commands = [
                [osv_bin, "scan", "--recursive", "--format", "json", "."],
                [osv_bin, "--recursive", "--format", "json", "."],
            ]
            executed = False
            for cmd in osv_commands:
                try:
                    result = subprocess.run(
                        cmd,
                        cwd=str(repo_root),
                        capture_output=True,
                        text=True,
                        timeout=180,
                        check=False,
                    )
                    payload_text = result.stdout.strip()
                    if not payload_text:
                        continue
                    payload = json.loads(payload_text)
                    osv_findings, osv_meta = _parse_osv_payload(payload)
                    findings.extend(osv_findings)
                    dep_meta.extend(osv_meta)
                    tools["osv_scanner"] = {
                        "status": "executed",
                        "exit_code": str(result.returncode),
                        "source": "runtime_scan",
                    }
                    executed = True
                    break
                except subprocess.TimeoutExpired:
                    tools["osv_scanner"] = {"status": "timeout", "reason": "scan_timed_out"}
                    executed = True
                    break
                except json.JSONDecodeError:
                    continue
            if not executed and tools["osv_scanner"]["status"] == "not_run":
                tools["osv_scanner"] = {"status": "invalid_output", "reason": "non_json_output"}

    dep_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    dep_by_language: dict[str, int] = {}
    dep_by_reachability = {"direct": 0, "transitive": 0, "unknown": 0}
    for item in dep_meta:
        severity = item.get("severity", "HIGH")
        dep_by_severity[severity] = dep_by_severity.get(severity, 0) + 1
        language = item.get("language", "unknown")
        dep_by_language[language] = dep_by_language.get(language, 0) + 1
        reachability = item.get("reachability", "unknown")
        dep_by_reachability[reachability] = dep_by_reachability.get(reachability, 0) + 1

    exploitability_score = min(
        100,
        dep_by_severity.get("CRITICAL", 0) * 20
        + dep_by_severity.get("HIGH", 0) * 8
        + dep_by_severity.get("MEDIUM", 0) * 3
        + dep_by_reachability.get("direct", 0) * 2,
    )

    summary = {
        "scan_mode": deps_scan,
        "manifests": manifests,
        "tools": tools,
        "findings_total": len(dep_meta),
        "findings_by_severity": dep_by_severity,
        "findings_by_language": dep_by_language,
        "reachability": dep_by_reachability,
        "exploitability_score": int(exploitability_score),
    }

    return findings, summary


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
) -> dict:
    files = _iter_source_files(root)

    findings: list[Finding] = []
    findings.extend(_scan_secrets(root, files, include_test_fixtures=include_test_fixtures))
    findings.extend(_scan_ci_config(root))
    findings.extend(_scan_dependency_hygiene(root))
    dep_findings, dependency_summary = _scan_dependency_advisories(root, deps_scan=deps_scan)
    findings.extend(dep_findings)
    findings.extend(_scan_language_risks(root, files))
    threat_index, threat_feed_findings, threat_feed_source = _load_threat_feed(root, threat_feed_path)
    findings.extend(threat_feed_findings)

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
        "ignored_artifacts": list(GENERATED_ARTIFACT_GLOBS),
        "dependencies": dependency_summary,
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
) -> dict:
    """Run static repository checks and return summary dictionary."""
    if repo_url:
        with tempfile.TemporaryDirectory(prefix="aletheia-github-repo-") as temp_dir:
            root = _clone_public_github_repo(repo_url, Path(temp_dir))
            summary = _audit_repo_root(
                root,
                threat_feed_path=threat_feed_path,
                include_test_fixtures=include_test_fixtures,
                deps_scan=deps_scan,
            )
            summary["source"] = {
                "kind": "github_public",
                "value": repo_url,
                "resolved": _normalize_public_github_repo_url(repo_url),
            }
            return summary

    root = Path(repo_path).resolve()
    return _audit_repo_root(
        root,
        threat_feed_path=threat_feed_path,
        include_test_fixtures=include_test_fixtures,
        deps_scan=deps_scan,
    )
