from __future__ import annotations

from kit.web_audit.schema import Finding


def test_finding_to_dict_contains_required_fields() -> None:
    finding = Finding(
        severity="HIGH",
        type="route_error",
        title="Route returned error status",
        page_url="https://example.com/account",
        element_selector=None,
        action="visit",
        expected="HTTP < 400",
        observed="HTTP 500",
        evidence={"status_code": 500},
        reproducible_steps=["Navigate to /account"],
    )

    payload = finding.to_dict()
    assert payload["id"].startswith("WA_")
    assert payload["severity"] == "HIGH"
    assert payload["type"] == "route_error"
    assert payload["page_url"] == "https://example.com/account"
    assert payload["evidence"]["status_code"] == 500


def test_finding_id_is_deterministic() -> None:
    finding = Finding(
        severity="MEDIUM",
        type="dead_click",
        title="Button click had no observable effect",
        page_url="https://example.com",
        element_selector="button_or_role_button[0]",
        action="click",
        expected="URL or UI state changes",
        observed="No navigation change detected",
        evidence={},
        reproducible_steps=["Navigate", "Click"],
    )

    first = finding.to_dict()["id"]
    second = finding.to_dict()["id"]
    assert first == second
