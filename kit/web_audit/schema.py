from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FindingType = Literal[
    "route_error",
    "dead_click",
    "tab_failure",
    "js_error",
    "network_error",
    "perf_timeout",
    "custom_rule",
    "auth_failure",
    "prompt_injection",
    "signature_failure",
    "auth_bypass",
]


@dataclass(slots=True)
class Finding:
    """One website finding with reproducible evidence."""

    severity: Severity
    type: FindingType
    title: str
    page_url: str
    element_selector: str | None
    action: Literal[
        "visit",
        "click",
        "tab_switch",
        "custom_rule_check",
        "auth_step",
        "attack_simulation",
        "trust_verification",
        "auth_probe",
    ]
    expected: str
    observed: str
    evidence: dict[str, Any]
    reproducible_steps: list[str]

    def to_dict(self) -> dict[str, Any]:
        finding_id = _finding_id(self.type, self.page_url, self.element_selector or "")
        return {
            "id": finding_id,
            "severity": self.severity,
            "type": self.type,
            "title": self.title,
            "page_url": self.page_url,
            "element_selector": self.element_selector,
            "action": self.action,
            "expected": self.expected,
            "observed": self.observed,
            "evidence": self.evidence,
            "reproducible_steps": self.reproducible_steps,
        }


def _finding_id(finding_type: str, page_url: str, selector: str) -> str:
    material = f"{finding_type}|{page_url}|{selector}".encode("utf-8")
    return f"WA_{sha1(material).hexdigest()[:10].upper()}"
