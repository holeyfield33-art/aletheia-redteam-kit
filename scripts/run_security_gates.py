from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any


def _find_binary(name: str) -> str | None:
    """Locate a binary on PATH or, as a fallback, in the active venv bin directory."""
    found = which(name)
    if found:
        return found
    # Fallback: resolve from the Python interpreter's directory (venv or pyenv)
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    return None


@dataclass(frozen=True)
class SuppressionEntry:
    scanner: str
    file_glob: str
    finding_type: str
    evidence_pattern: re.Pattern[str]
    owner: str
    reason: str


@dataclass(frozen=True)
class SecurityFinding:
    scanner: str
    finding_type: str
    file: str
    line: int | None
    severity: str
    evidence: str
    title: str


def _load_suppressions(path: Path | None, *, scanner: str) -> list[SuppressionEntry]:
    if path is None or not path.exists():
        return []

    entries: list[SuppressionEntry] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "# owner:" not in line or "# reason:" not in line:
            raise ValueError(f"Invalid suppression entry (missing owner/reason): {raw_line}")

        body, comment_blob = line.split("#", 1)
        parts = [part.strip() for part in body.split("|")]
        if len(parts) < 4:
            raise ValueError(f"Invalid suppression entry (expected scanner|file_glob|finding_type|evidence_regex): {raw_line}")

        entry_scanner, file_glob, finding_type, evidence_regex = parts[:4]
        owner_match = re.search(r"#\s*owner:\s*([^#]+)", f"#{comment_blob}", re.IGNORECASE)
        reason_match = re.search(r"#\s*reason:\s*(.+)$", f"#{comment_blob}", re.IGNORECASE)
        if not owner_match or not reason_match:
            raise ValueError(f"Invalid suppression entry (missing owner/reason): {raw_line}")

        if entry_scanner not in {scanner, "*"}:
            continue

        entries.append(
            SuppressionEntry(
                scanner=entry_scanner,
                file_glob=file_glob,
                finding_type=finding_type,
                evidence_pattern=re.compile(evidence_regex or ".*"),
                owner=owner_match.group(1).strip(),
                reason=reason_match.group(1).strip(),
            )
        )

    return entries


def _matches_suppression(entry: SuppressionEntry, *, file_path: str, finding_type: str, evidence: str) -> bool:
    from fnmatch import fnmatch

    normalized = file_path.replace("\\", "/")
    if not fnmatch(normalized, entry.file_glob):
        return False
    if entry.finding_type not in {"*", finding_type}:
        return False
    return bool(entry.evidence_pattern.search(evidence))


def _filter_findings(findings: list[SecurityFinding], suppressions: list[SuppressionEntry]) -> list[SecurityFinding]:
    kept: list[SecurityFinding] = []
    for finding in findings:
        suppressed = any(
            _matches_suppression(suppression, file_path=finding.file, finding_type=finding.finding_type, evidence=finding.evidence)
            for suppression in suppressions
        )
        if not suppressed:
            kept.append(finding)
    return kept


def _run_trufflehog(repo_root: Path, suppressions: list[SuppressionEntry]) -> list[SecurityFinding]:
    binary = _find_binary("trufflehog")
    if not binary:
        print(json.dumps({"trufflehog": "unavailable", "reason": "binary not found on PATH or venv"}, indent=2), file=sys.stderr)
        return []

    command = subprocess.run(
        [binary, "filesystem", "--json", str(repo_root)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    raw_findings: list[SecurityFinding] = []
    for line in command.stdout.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue

        file_path = (
            parsed.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file")
            or parsed.get("SourceMetadata", {})
            .get("Data", {})
            .get("Path")
            or "unknown"
        )
        raw_findings.append(
            SecurityFinding(
                scanner="trufflehog",
                finding_type=str(parsed.get("DetectorName") or "trufflehog_detector"),
                file=str(file_path),
                line=None,
                severity="HIGH",
                evidence=str(parsed.get("Raw") or "Potential secret disclosed."),
                title=str(parsed.get("DetectorName") or "Potential secret"),
            )
        )

    return _filter_findings(raw_findings, suppressions)


def _run_semgrep(repo_root: Path, rules_file: Path, suppressions: list[SuppressionEntry]) -> list[SecurityFinding]:
    binary = _find_binary("semgrep")
    if not binary:
        print(json.dumps({"semgrep": "unavailable", "reason": "binary not found on PATH or venv"}, indent=2), file=sys.stderr)
        return []

    command = subprocess.run(
        [binary, "--config", str(rules_file), "--json", str(repo_root)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if not command.stdout.strip():
        return []

    parsed = json.loads(command.stdout)
    raw_findings: list[SecurityFinding] = []
    for result in parsed.get("results") or []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        file_path = str(result.get("path") or "unknown")
        raw_findings.append(
            SecurityFinding(
                scanner="semgrep",
                finding_type=str(result.get("check_id") or "semgrep_rule"),
                file=file_path,
                line=int((result.get("start") or {}).get("line") or 0) or None,
                severity=str(extra.get("severity") or "MEDIUM").upper(),
                evidence=str(extra.get("lines") or extra.get("message") or "Pattern matched by Semgrep."),
                title=str(extra.get("message") or result.get("check_id") or "Semgrep finding"),
            )
        )

    return _filter_findings(raw_findings, suppressions)


def _write_report(path: Path, *, trufflehog: list[SecurityFinding], semgrep: list[SecurityFinding]) -> None:
    data: dict[str, Any] = {
        "trufflehog": {
            "count": len(trufflehog),
            "findings": [finding.__dict__ for finding in trufflehog],
        },
        "semgrep": {
            "count": len(semgrep),
            "findings": [finding.__dict__ for finding in semgrep],
        },
        "total": len(trufflehog) + len(semgrep),
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run security gates for the Aletheia repo")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--secret-allowlist", required=True)
    parser.add_argument("--semgrep-rules", required=True)
    parser.add_argument("--semgrep-suppressions", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    secret_allowlist = Path(args.secret_allowlist).resolve()
    semgrep_suppressions = Path(args.semgrep_suppressions).resolve()
    semgrep_rules = Path(args.semgrep_rules).resolve()
    output = Path(args.output).resolve()

    secret_entries = _load_suppressions(secret_allowlist, scanner="trufflehog")
    semgrep_entries = _load_suppressions(semgrep_suppressions, scanner="semgrep")

    trufflehog_findings = _run_trufflehog(repo_root, secret_entries)
    semgrep_findings = _run_semgrep(repo_root, semgrep_rules, semgrep_entries)

    _write_report(output, trufflehog=trufflehog_findings, semgrep=semgrep_findings)

    if trufflehog_findings or semgrep_findings:
        print(json.dumps({"trufflehog": len(trufflehog_findings), "semgrep": len(semgrep_findings)}, indent=2))
        return 1

    print(json.dumps({"trufflehog": 0, "semgrep": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
