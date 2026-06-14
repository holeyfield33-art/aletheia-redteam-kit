from __future__ import annotations

from engine.nist_export import (
    DEFAULT_FOCUS_TECHNIQUES,
    build_dataset,
    receipt_signature_state,
    records_to_csv_rows,
    telemetry_record,
)


def _row(rid, technique, *, expected="DENIED", actual="DENIED", signature=None, category="agentic_planning_hijack"):
    receipt = {}
    if signature is not None:
        receipt["signature"] = signature
        receipt["policy_version"] = "v1"
    return {
        "id": rid,
        "technique": technique,
        "category": category,
        "expected_decision": expected,
        "actual_decision": actual,
        "receipt": receipt,
    }


def test_receipt_signature_state() -> None:
    assert receipt_signature_state({"signature": "abc123"}) == "signed"
    assert receipt_signature_state({"signature": "UNSIGNED_DEV_MODE"}) == "unsigned_dev_mode"
    assert receipt_signature_state({}) == "missing"
    assert receipt_signature_state(None) == "missing"


def test_telemetry_record_bypass_flag() -> None:
    rec = telemetry_record(_row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE"))
    assert rec["is_bypass"] is True
    assert rec["signature_state"] == "unsigned_dev_mode"
    assert rec["technique"] == "tool_selection_override"


def test_focus_only_filters_to_agentic_techniques() -> None:
    rows = [
        _row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE"),
        _row("APH_005", "recursive_self_improvement_bait", actual="PROCEED", signature="UNSIGNED_DEV_MODE"),
        _row("X_001", "unrelated_technique", actual="PROCEED", signature="sig"),
    ]
    dataset = build_dataset(rows)
    ids = {r["id"] for r in dataset["records"]}
    assert ids == {"APH_002", "APH_005"}
    assert dataset["manifest"]["n_records"] == 2


def test_all_rows_includes_everything() -> None:
    rows = [
        _row("APH_002", "tool_selection_override"),
        _row("X_001", "unrelated"),
    ]
    dataset = build_dataset(rows, focus_only=False)
    assert dataset["manifest"]["n_records"] == 2


def test_signature_correlation_separates_signed_and_unsigned() -> None:
    rows = [
        _row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE"),
        _row("APH_005", "recursive_self_improvement_bait", actual="DENIED", signature="realsig"),
        _row("APH_003", "fake_memory_history", actual="PROCEED", signature=None),
    ]
    corr = build_dataset(rows)["manifest"]["signature_correlation"]
    assert corr["signed_n"] == 1
    assert corr["signed_bypass_rate"] == 0.0
    assert corr["unsigned_or_missing_n"] == 2
    assert corr["unsigned_or_missing_bypass_rate"] == 1.0


def test_technique_breakdown_and_override_rate() -> None:
    rows = [
        _row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE"),
        _row("APH_002b", "tool_selection_override", actual="DENIED", signature="UNSIGNED_DEV_MODE"),
    ]
    breakdown = build_dataset(rows)["manifest"]["technique_breakdown"]
    bucket = breakdown["tool_selection_override"]
    assert bucket["n"] == 2
    assert bucket["bypasses"] == 1
    assert bucket["override_rate"] == 0.5


def test_dataset_hash_is_deterministic() -> None:
    rows = [_row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE")]
    h1 = build_dataset(rows)["manifest"]["dataset_sha256"]
    h2 = build_dataset(rows)["manifest"]["dataset_sha256"]
    assert h1 == h2 and len(h1) == 64


def test_csv_rows_header_and_values() -> None:
    rows = [_row("APH_002", "tool_selection_override", actual="PROCEED", signature="UNSIGNED_DEV_MODE")]
    dataset = build_dataset(rows)
    csv_rows = records_to_csv_rows(dataset["records"])
    assert csv_rows[0][0] == "id"
    assert csv_rows[1][0] == "APH_002"
    assert "is_bypass" in csv_rows[0]


def test_default_focus_covers_user_named_techniques() -> None:
    assert "tool_selection_override" in DEFAULT_FOCUS_TECHNIQUES
    assert "recursive_self_improvement" in DEFAULT_FOCUS_TECHNIQUES
