from __future__ import annotations

from typing import Any

SEVERITY_SCORE: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


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


def summarize_dependency_metadata(metadata: list[dict[str, Any]]) -> dict[str, Any]:
    package_rows: dict[str, dict[str, Any]] = {}
    suspicious_by_package: dict[str, bool] = {}

    for item in metadata:
        package_name = str(item.get("package") or "unknown")
        advisory_id = str(item.get("advisory_id") or "unknown")
        severity = _normalize_dependency_severity(item.get("severity") if item.get("severity") is not None else "HIGH")
        finding_type = str(item.get("type") or "dependency_vulnerability")
        language = str(item.get("language") or "unknown")
        reachability = str(item.get("reachability") or "unknown")
        tool = str(item.get("tool") or "unknown")

        pkg_entry = package_rows.setdefault(
            package_name,
            {
                "name": package_name,
                "advisory_ids": [],
                "languages": {},
                "reachability": {},
                "tools": {},
                "finding_types": {},
                "max_severity": severity,
                "advisory_count": 0,
            },
        )

        if advisory_id not in pkg_entry["advisory_ids"]:
            pkg_entry["advisory_ids"].append(advisory_id)

        pkg_entry["advisory_count"] += 1
        pkg_entry["max_severity"] = max(pkg_entry["max_severity"], severity, key=lambda value: SEVERITY_SCORE.get(value, 0))
        pkg_entry["languages"][language] = pkg_entry["languages"].get(language, 0) + 1
        pkg_entry["reachability"][reachability] = pkg_entry["reachability"].get(reachability, 0) + 1
        pkg_entry["tools"][tool] = pkg_entry["tools"].get(tool, 0) + 1
        pkg_entry["finding_types"][finding_type] = pkg_entry["finding_types"].get(finding_type, 0) + 1

        if finding_type in {"dependency_malware_suspect", "dependency_tampering_risk"}:
            suspicious_by_package[package_name] = True

    top_packages = sorted(
        package_rows.values(),
        key=lambda entry: (
            -entry["advisory_count"],
            -SEVERITY_SCORE.get(entry["max_severity"], 0),
            entry["name"],
        ),
    )

    top_suspicious_packages = sorted(
        (
            {
                "name": name,
                "advisory_ids": pkg["advisory_ids"],
                "finding_types": pkg["finding_types"],
                "max_severity": pkg["max_severity"],
                "suspicious_advisory_count": sum(
                    count for ftype, count in pkg["finding_types"].items() if ftype in {"dependency_malware_suspect", "dependency_tampering_risk"}
                ),
            }
            for name, pkg in package_rows.items()
            if any(ftype in {"dependency_malware_suspect", "dependency_tampering_risk"} for ftype in pkg["finding_types"])
        ),
        key=lambda item: (-item["suspicious_advisory_count"], -SEVERITY_SCORE.get(item["max_severity"], 0), item["name"],),
    )

    return {
        "top_packages": top_packages,
        "signals": {
            "malware_suspect_total": sum(
                1 for item in metadata if item.get("type") == "dependency_malware_suspect"
            ),
            "tampering_risk_total": sum(
                1 for item in metadata if item.get("type") == "dependency_tampering_risk"
            ),
            "suspicious_package_total": len(suspicious_by_package),
            "top_suspicious_packages": [
                {
                    "name": item["name"],
                    "advisory_ids": item["advisory_ids"],
                    "finding_types": item["finding_types"],
                    "max_severity": item["max_severity"],
                }
                for item in top_suspicious_packages
            ],
        },
    }
