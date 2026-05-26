from __future__ import annotations


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
