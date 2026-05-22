from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

DEPENDENCY_MANIFEST_PATTERNS: dict[str, set[str]] = {
    "python": {"pyproject.toml", "requirements.txt", "Pipfile"},
    "npm": {"package.json", "package-lock.json", "yarn.lock"},
    "cargo": {"Cargo.toml", "Cargo.lock"},
    "go": {"go.mod", "go.sum"},
    "ruby": {"Gemfile", "Gemfile.lock"},
}

DEFAULT_DEP_SCAN_TIMEOUT = 180


def detect_dependency_manifests(repo_root: Path) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {key: [] for key in DEPENDENCY_MANIFEST_PATTERNS}
    manifests["other"] = []

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue

        file_name = path.name
        matched = False
        for language, patterns in DEPENDENCY_MANIFEST_PATTERNS.items():
            if file_name in patterns:
                manifests[language].append(str(path.relative_to(repo_root)))
                matched = True
                break
        if not matched and file_name.endswith(".lock"):
            manifests["other"].append(str(path.relative_to(repo_root)))

    return {key: sorted(paths) for key, paths in manifests.items()}


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


def _build_finding(
    severity: str,
    title: str,
    advisory_id: str,
    report_rel: str,
    evidence: str,
    recommendation: str,
    finding_type: str | None = None,
) -> dict[str, Any]:
    normalized_severity = _normalize_dependency_severity(severity)
    return {
        "severity": normalized_severity,
        "type": finding_type or _classify_dependency_finding_type(advisory_id=advisory_id, description=evidence),
        "title": title,
        "file": report_rel,
        "line": None,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


def _parse_pip_audit_payload(payload: Any, report_rel: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
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
                _build_finding(
                    severity=severity,
                    title=f"Dependency advisory: {vuln_id}",
                    advisory_id=vuln_id,
                    report_rel=report_rel,
                    evidence=f"{name}=={version}: {description[:160]}",
                    recommendation=f"Upgrade {name} to a patched version ({fix_hint}) and rerun dependency audit.",
                    finding_type=finding_type,
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


def _parse_osv_payload(payload: Any) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
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
            language = package_info.get("ecosystem") or package.get("ecosystem") or "unknown"
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
                    _build_finding(
                        severity=severity,
                        title=f"Dependency advisory: {vuln_id}",
                        advisory_id=vuln_id,
                        report_rel="osv-scanner",
                        evidence=f"{package_name} ({ecosystem or 'unknown ecosystem'}, {reachability}): {summary[:160]}",
                        recommendation=f"Upgrade or replace {package_name}, verify lockfiles, and rerun osv-scanner.",
                        finding_type=finding_type,
                    )
                )
                metadata.append(
                    {
                        "severity": severity,
                        "language": str(language),
                        "reachability": reachability,
                        "tool": "osv_scanner",
                        "type": finding_type,
                    }
                )

    return findings, metadata


def _parse_npm_audit_payload(payload: Any, report_rel: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
    metadata: list[dict[str, str]] = []
    vulnerabilities = {}

    if isinstance(payload, dict):
        vulnerabilities = payload.get("advisories") or payload.get("vulnerabilities") or {}
        if not vulnerabilities and "auditReport" in payload and isinstance(payload["auditReport"], dict):
            vulnerabilities = payload["auditReport"].get("vulnerabilities") or {}

    if not isinstance(vulnerabilities, dict):
        return findings, metadata

    for name, item in vulnerabilities.items():
        if not isinstance(item, dict):
            continue
        severity = _normalize_dependency_severity(item.get("severity"))
        title = str(item.get("title") or item.get("name") or f"Vulnerability in {name}")
        finding_type = _classify_dependency_finding_type(advisory_id=name, description=title)
        evidence_parts = []
        if "via" in item and isinstance(item["via"], list):
            for via in item["via"]:
                if isinstance(via, dict):
                    evidence_parts.append(str(via.get("title") or via.get("source") or ""))
        if not evidence_parts:
            evidence_parts.append(str(item.get("overview") or item.get("findings") or title))
        evidence = f"{name}: {', '.join(evidence_parts)[:160]}"
        fix_hint = []
        if isinstance(item.get("fixAvailable"), dict):
            fix_hint = [str(item.get("fixAvailable", {}).get("version") or item.get("findings") or "latest secure version")]
        if not fix_hint and isinstance(item.get("range"), str):
            fix_hint = [item.get("range")]
        fix_hint_text = ", ".join(fix_hint) if fix_hint else "latest secure version"

        findings.append(
            _build_finding(
                severity=severity,
                title=f"Dependency advisory: {name}",
                advisory_id=name,
                report_rel=report_rel,
                evidence=evidence,
                recommendation=f"Upgrade {name} to a secure version ({fix_hint_text}) and rerun npm audit.",
                finding_type=finding_type,
            )
        )
        metadata.append(
            {
                "severity": severity,
                "language": "javascript",
                "reachability": "unknown",
                "tool": "npm_audit",
                "type": finding_type,
            }
        )

    return findings, metadata


def _parse_cargo_audit_payload(payload: Any, report_rel: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
    metadata: list[dict[str, str]] = []
    vulnerabilities = []

    if isinstance(payload, dict):
        violations = payload.get("vulnerabilities") or {}
        if isinstance(violations, dict):
            vulnerabilities = violations.get("list") or []
        elif isinstance(violations, list):
            vulnerabilities = violations
    if not isinstance(vulnerabilities, list):
        return findings, metadata

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        advisory = vuln.get("advisory") or {}
        if not isinstance(advisory, dict):
            continue
        pkg = vuln.get("package") or {}
        package_name = str(pkg.get("name") or "unknown")
        vuln_id = str(advisory.get("id") or advisory.get("url") or f"cargo-{package_name}")
        title = str(advisory.get("title") or advisory.get("description") or f"Cargo advisory for {package_name}")
        severity = _normalize_dependency_severity(advisory.get("severity") or vuln.get("severity"))
        finding_type = _classify_dependency_finding_type(advisory_id=vuln_id, description=title)
        evidence = f"{package_name}: {title[:160]}"
        recommendation = f"Upgrade {package_name} according to advisory {vuln_id} and rerun cargo audit."

        findings.append(
            _build_finding(
                severity=severity,
                title=f"Dependency advisory: {vuln_id}",
                advisory_id=vuln_id,
                report_rel=report_rel,
                evidence=evidence,
                recommendation=recommendation,
                finding_type=finding_type,
            )
        )
        metadata.append(
            {
                "severity": severity,
                "language": "rust",
                "reachability": "unknown",
                "tool": "cargo_audit",
                "type": finding_type,
            }
        )

    return findings, metadata


def _run_command(cmd: list[str], repo_root: Path, timeout_seconds: int) -> tuple[str, str, int, bool]:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return result.stdout or "", result.stderr or "", result.returncode, False
    except subprocess.TimeoutExpired as exc:
        return "", str(exc), -1, True


def _parse_tool_payload(
    repo_root: Path,
    tool_name: str,
    payload: Any,
    report_rel: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    if tool_name == "pip_audit":
        return _parse_pip_audit_payload(payload, report_rel)
    if tool_name == "osv_scanner":
        return _parse_osv_payload(payload)
    if tool_name == "npm_audit":
        return _parse_npm_audit_payload(payload, report_rel)
    if tool_name == "cargo_audit":
        return _parse_cargo_audit_payload(payload, report_rel)
    return [], [], {}


def _collect_dependency_findings(repo_root: Path, deps_scan: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifests = detect_dependency_manifests(repo_root)
    findings: list[dict[str, Any]] = []
    metadata: list[dict[str, str]] = []
    tools: dict[str, dict[str, Any]] = {
        "pip_audit": {"status": "not_run"},
        "osv_scanner": {"status": "not_run"},
        "npm_audit": {"status": "not_run"},
        "cargo_audit": {"status": "not_run"},
    }

    report_path = repo_root / "pip-audit-report.json"
    if report_path.exists():
        payload = _load_json(report_path)
        if payload is None:
            findings.append(
                _build_finding(
                    severity="MEDIUM",
                    title="Invalid pip-audit report format",
                    advisory_id="invalid_pip_audit_report",
                    report_rel=str(report_path.relative_to(repo_root)),
                    evidence="Could not parse pip-audit-report.json as JSON",
                    recommendation="Regenerate report using 'pip-audit -f json -o pip-audit-report.json'.",
                )
            )
            tools["pip_audit"] = {"status": "report_invalid", "source": str(report_path.relative_to(repo_root))}
        else:
            findings_payload, payload_meta = _parse_pip_audit_payload(payload, str(report_path.relative_to(repo_root)))
            findings.extend(findings_payload)
            metadata.extend(payload_meta)
            tools["pip_audit"] = {"status": "report_loaded", "source": str(report_path.relative_to(repo_root))}

    python_manifests = manifests.get("python") or []
    if deps_scan in {"auto", "full"} and python_manifests and tools["pip_audit"]["status"] == "not_run":
        pip_audit_bin = shutil.which("pip-audit")
        if not pip_audit_bin:
            tools["pip_audit"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            stdout, stderr, exit_code, timed_out = _run_command([pip_audit_bin, "-f", "json"], repo_root, timeout_seconds)
            if timed_out:
                tools["pip_audit"] = {"status": "timeout", "reason": "scan_timed_out"}
            else:
                try:
                    payload = json.loads(stdout or "{}")
                    findings_payload, payload_meta = _parse_pip_audit_payload(payload, "pip-audit:runtime")
                    findings.extend(findings_payload)
                    metadata.extend(payload_meta)
                    tools["pip_audit"] = {"status": "executed", "exit_code": str(exit_code), "source": "runtime_scan"}
                except json.JSONDecodeError:
                    tools["pip_audit"] = {"status": "invalid_output", "reason": "non_json_output", "stderr": stderr[:512]}

    npm_manifests = manifests.get("npm") or []
    if deps_scan in {"auto", "full"} and npm_manifests:
        npm_bin = shutil.which("npm")
        if not npm_bin:
            tools["npm_audit"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            stdout, stderr, exit_code, timed_out = _run_command([npm_bin, "audit", "--json"], repo_root, timeout_seconds)
            if timed_out:
                tools["npm_audit"] = {"status": "timeout", "reason": "scan_timed_out"}
            else:
                try:
                    payload = json.loads(stdout or "{}")
                    findings_payload, payload_meta = _parse_npm_audit_payload(payload, "npm-audit")
                    findings.extend(findings_payload)
                    metadata.extend(payload_meta)
                    tools["npm_audit"] = {"status": "executed", "exit_code": str(exit_code), "source": "runtime_scan"}
                except json.JSONDecodeError:
                    tools["npm_audit"] = {"status": "invalid_output", "reason": "non_json_output", "stderr": stderr[:512]}

    cargo_manifests = manifests.get("cargo") or []
    if deps_scan in {"auto", "full"} and cargo_manifests:
        cargo_bin = shutil.which("cargo-audit")
        if not cargo_bin:
            tools["cargo_audit"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            stdout, stderr, exit_code, timed_out = _run_command([cargo_bin, "audit", "--json"], repo_root, timeout_seconds)
            if timed_out:
                tools["cargo_audit"] = {"status": "timeout", "reason": "scan_timed_out"}
            else:
                try:
                    payload = json.loads(stdout or "{}")
                    findings_payload, payload_meta = _parse_cargo_audit_payload(payload, "cargo-audit")
                    findings.extend(findings_payload)
                    metadata.extend(payload_meta)
                    tools["cargo_audit"] = {"status": "executed", "exit_code": str(exit_code), "source": "runtime_scan"}
                except json.JSONDecodeError:
                    tools["cargo_audit"] = {"status": "invalid_output", "reason": "non_json_output", "stderr": stderr[:512]}

    should_run_osv = deps_scan == "full" or (deps_scan == "auto" and any(manifests.get(lang) for lang in ["npm", "cargo", "go", "ruby"]))
    if should_run_osv:
        osv_bin = shutil.which("osv-scanner")
        if not osv_bin:
            tools["osv_scanner"] = {"status": "unavailable", "reason": "binary_not_found"}
        else:
            stdout, stderr, exit_code, timed_out = _run_command([osv_bin, "scan", "--recursive", "--format", "json", "."], repo_root, timeout_seconds)
            if timed_out:
                tools["osv_scanner"] = {"status": "timeout", "reason": "scan_timed_out"}
            else:
                try:
                    payload = json.loads(stdout or "{}")
                    findings_payload, payload_meta = _parse_osv_payload(payload)
                    findings.extend(findings_payload)
                    metadata.extend(payload_meta)
                    tools["osv_scanner"] = {"status": "executed", "exit_code": str(exit_code), "source": "runtime_scan"}
                except json.JSONDecodeError:
                    tools["osv_scanner"] = {"status": "invalid_output", "reason": "non_json_output", "stderr": stderr[:512]}

    dep_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    dep_by_language: dict[str, int] = {}
    dep_by_reachability = {"direct": 0, "transitive": 0, "unknown": 0}
    for item in metadata:
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
        "findings_total": len(metadata),
        "findings_by_severity": dep_by_severity,
        "findings_by_language": dep_by_language,
        "reachability": dep_by_reachability,
        "exploitability_score": int(exploitability_score),
    }

    return findings, summary


def scan_dependency_advisories(repo_root: Path, *, deps_scan: str = "auto", timeout_seconds: int = DEFAULT_DEP_SCAN_TIMEOUT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _collect_dependency_findings(repo_root, deps_scan, timeout_seconds)
