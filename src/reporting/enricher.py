from __future__ import annotations

from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _compute_executive_risk(summary: dict[str, Any]) -> int:
    # Two source scales run in OPPOSITE directions:
    #   risk_score          -> health scale: 100 = clean repo, 0 = severe.
    #   exploitability_score -> danger scale: 0 = no exploitable deps, 100 = many.
    # Executive risk is a danger scale (higher = worse), so we invert risk_score
    # into a danger value before blending. A clean repo now reports ~0, not 65.
    risk_danger = 100 - int(summary.get("risk_score", 100))
    dep_danger = int((summary.get("dependencies") or {}).get("exploitability_score", 0))
    blended = (risk_danger * 0.65) + (dep_danger * 0.35)
    return int(min(100, max(0, round(blended))))


def _format_manifest_overview(summary: dict[str, Any]) -> str:
    manifests = (summary.get("dependencies") or {}).get("manifests", {}) or {}
    entries = []
    for language, paths in manifests.items():
        if paths:
            entries.append(f"{language} ({len(paths)})")
    return ", ".join(entries) if entries else "No dependency manifests detected."


def _build_trust_boundary_summary(summary: dict[str, Any]) -> str:
    scanners = summary.get("enabled_scanners", [])
    components = []
    if "ci_config" in scanners:
        components.append("CI/CD and pipeline configuration")
    if "dep_advisories" in scanners:
        components.append("dependency supply chain and advisory detection")
    if "git_history_secrets" in scanners:
        components.append("repository history and secret artifact review")
    if "semgrep" in scanners or "bandit" in scanners or "trivy" in scanners:
        components.append("static code and policy scanning")
    if not components:
        return "This audit captured only baseline repository content without expanded trust boundary analysis."
    return "Audit coverage includes " + ", ".join(components) + "."


def _build_scope_limitations(summary: dict[str, Any]) -> list[str]:
    limitations: list[str] = []
    dependencies = summary.get("dependencies") or {}
    tools = dependencies.get("tools") or {}
    for tool_name, tool_meta in tools.items():
        status = str(tool_meta.get("status", ""))
        if status in {"unavailable", "timeout", "invalid_output", "report_invalid", "error"}:
            limitations.append(
                f"{tool_name} was not fully available ({status}). Results may miss advisory coverage for that ecosystem."
            )
    if "git_history_secrets" in summary.get("enabled_scanners", []) and (
        summary.get("extra_tools", {}).get("git_history_secrets", {}).get("status") == "skipped"
    ):
        limitations.append("Git history scanning was skipped because the repository history was unavailable or not initialized.")
    if not limitations:
        limitations.append("No explicit scanner availability issues detected. Coverage is limited to configured scan profile and available tooling.")
    return limitations


def _top_findings(summary: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    findings = summary.get("findings") or []
    sorted_findings = sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity", "LOW")).upper(), 3), item.get("type", ""), item.get("file", "")),
    )
    return sorted_findings[:limit]


def enrich_repo_summary(summary: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(summary)
    enriched["report_overview"] = {
        "executive_risk_score": _compute_executive_risk(summary),
        "architecture_summary": _format_manifest_overview(summary),
        "trust_boundary_summary": _build_trust_boundary_summary(summary),
        "scope_limitations": _build_scope_limitations(summary),
        "top_findings": _top_findings(summary),
        "generated_at": datetime.now().isoformat(),
    }
    return enriched


def render_markdown_report(summary: dict[str, Any]) -> str:
    if "report_overview" not in summary:
        summary = enrich_repo_summary(summary)

    overview = summary["report_overview"]
    lines: list[str] = []
    lines.append(f"# Repository Security Audit Report")
    lines.append("")
    lines.append(f"Generated: {overview.get('generated_at')}")
    lines.append(f"Repository: {summary.get('repo_root')}")
    lines.append(f"Scan profile: {summary.get('scan_profile', 'medium')}")
    lines.append(f"Risk score: {summary.get('risk_score', 0)}")
    lines.append(f"Executive risk score: {overview.get('executive_risk_score')}")
    lines.append("")
    lines.append("## Architecture & Dependency Coverage")
    lines.append(overview.get("architecture_summary", "No architecture summary available."))
    lines.append("")
    lines.append("## Trust Boundary Summary")
    lines.append(overview.get("trust_boundary_summary", "No trust boundary summary available."))
    lines.append("")
    lines.append("## Scope Limitations")
    for limitation in overview.get("scope_limitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    lines.append("## Top Findings")
    for finding in overview.get("top_findings", []):
        lines.append(
            f"- [{finding.get('severity')}] {finding.get('title')} in {finding.get('file')}:{finding.get('line') or 'n/a'}"
        )
    lines.append("")
    lines.append("## Recommended Remediation")
    lines.append(
        "Review CRITICAL and HIGH findings first, prioritize dependency updates and secret rotation, "
        "and rerun the audit after applying fixes."
    )
    return "\n".join(lines)
