"""Static repository risk scanner for secrets, config, and dependency hygiene."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from math import log2
from pathlib import Path
import re
import tomllib
import json
from collections import defaultdict


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
        "finding_type": "private_key_block",
        "threat": "Credential/key compromise",
        "reference": "https://owasp.org/www-project-secrets-management/",
    },
]

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


def _matches_fixture_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(fnmatch(normalized, pattern) for pattern in TEST_FIXTURE_GLOBS)


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


def _scan_dependency_advisories(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    report_path = repo_root / "pip-audit-report.json"
    if not report_path.exists():
        return findings

    try:
        report = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        findings.append(
            Finding(
                severity="MEDIUM",
                type="invalid_pip_audit_report",
                title="Invalid pip-audit report format",
                file=str(report_path.relative_to(repo_root)),
                line=None,
                evidence="Could not parse pip-audit-report.json as JSON",
                recommendation="Regenerate report using 'pip-audit -f json -o pip-audit-report.json'.",
            )
        )
        return findings

    dependencies = []
    if isinstance(report, dict):
        dependencies = report.get("dependencies") or []
    if not isinstance(dependencies, list):
        return findings

    report_rel = str(report_path.relative_to(repo_root))
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
            findings.append(
                Finding(
                    severity="HIGH",
                    type="dependency_vulnerability",
                    title=f"Dependency advisory: {vuln_id}",
                    file=report_rel,
                    line=None,
                    evidence=f"{name}=={version}: {description[:160]}",
                    recommendation=f"Upgrade {name} to a patched version ({fix_hint}) and rerun dependency audit.",
                )
            )

    return findings


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


def run_repo_audit(
    repo_path: str | Path = ".",
    threat_feed_path: str | None = None,
    *,
    include_test_fixtures: bool = False,
) -> dict:
    """Run static repository checks and return summary dictionary."""
    root = Path(repo_path).resolve()
    files = _iter_source_files(root)

    findings: list[Finding] = []
    findings.extend(_scan_secrets(root, files, include_test_fixtures=include_test_fixtures))
    findings.extend(_scan_ci_config(root))
    findings.extend(_scan_dependency_hygiene(root))
    findings.extend(_scan_dependency_advisories(root))
    findings.extend(_scan_language_risks(root, files))
    threat_index, threat_feed_findings, threat_feed_source = _load_threat_feed(root, threat_feed_path)
    findings.extend(threat_feed_findings)

    # Deduplicate same type/file/line/evidence to reduce noise.
    deduped: dict[tuple[str, str, int | None, str], Finding] = {}
    for finding in findings:
        key = (finding.type, finding.file, finding.line, finding.evidence)
        deduped[key] = finding
    unique_findings = list(deduped.values())

    risk_score, by_severity, by_type = _score(unique_findings)

    threat_match_total = 0
    threat_match_by_type: dict[str, int] = {}
    for finding in unique_findings:
        if finding.type in threat_index:
            threat_match_total += 1
            threat_match_by_type[finding.type] = threat_match_by_type.get(finding.type, 0) + 1

    gates = {
        "pass": by_severity.get("CRITICAL", 0) == 0 and by_severity.get("HIGH", 0) <= 5,
        "violations": [],
    }
    if by_severity.get("CRITICAL", 0) > 0:
        gates["violations"].append("critical_repo_findings")
    if by_severity.get("HIGH", 0) > 5:
        gates["violations"].append("high_repo_findings_over_limit")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "repo",
        "repo_root": str(root),
        "files_scanned": len(files),
        "secret_scan": {
            "include_test_fixtures": include_test_fixtures,
            "excluded_globs": [] if include_test_fixtures else list(TEST_FIXTURE_GLOBS),
            "allowlist_marker": TEST_FIXTURE_ALLOWLIST_MARKER,
        },
        "ignored_artifacts": list(GENERATED_ARTIFACT_GLOBS),
        "findings_total": len(unique_findings),
        "findings_by_severity": by_severity,
        "findings_by_type": by_type,
        "risk_score": risk_score,
        "threat_feed": {
            "source": threat_feed_source,
            "matches_total": threat_match_total,
            "matches_by_type": threat_match_by_type,
        },
        "gates": gates,
        "findings": [
            _serialize_finding(finding, threat_index)
            for finding in sorted(unique_findings, key=lambda item: (item.severity, item.file, item.line or 0))
        ],
    }
