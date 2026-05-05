"""Static repository risk scanner for secrets, config, and dependency hygiene."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import tomllib


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
        if _is_probably_text(path):
            files.append(path)
    return files


def _scan_secrets(repo_root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        rel = str(path.relative_to(repo_root))
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for idx, line in enumerate(text.splitlines(), 1):
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
    return findings


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
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
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

    data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="ignore"))
    deps = list(((data.get("project") or {}).get("dependencies") or []))
    optional = ((data.get("project") or {}).get("optional-dependencies") or {})
    for _, values in optional.items():
        deps.extend(values or [])

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


def _score(findings: list[Finding]) -> tuple[int, dict[str, int], dict[str, int]]:
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_type[finding.type] = by_type.get(finding.type, 0) + 1

    penalty = by_severity["CRITICAL"] * 30 + by_severity["HIGH"] * 12 + by_severity["MEDIUM"] * 5 + by_severity["LOW"] * 2
    risk_score = max(0, 100 - penalty)
    return risk_score, by_severity, by_type


def run_repo_audit(repo_path: str | Path = ".") -> dict:
    """Run static repository checks and return summary dictionary."""
    root = Path(repo_path).resolve()
    files = _iter_source_files(root)

    findings: list[Finding] = []
    findings.extend(_scan_secrets(root, files))
    findings.extend(_scan_ci_config(root))
    findings.extend(_scan_dependency_hygiene(root))

    # Deduplicate same type/file/line/evidence to reduce noise.
    deduped: dict[tuple[str, str, int | None, str], Finding] = {}
    for finding in findings:
        key = (finding.type, finding.file, finding.line, finding.evidence)
        deduped[key] = finding
    unique_findings = list(deduped.values())

    risk_score, by_severity, by_type = _score(unique_findings)

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
        "findings_total": len(unique_findings),
        "findings_by_severity": by_severity,
        "findings_by_type": by_type,
        "risk_score": risk_score,
        "gates": gates,
        "findings": [finding.as_dict() for finding in sorted(unique_findings, key=lambda item: (item.severity, item.file, item.line or 0))],
    }
