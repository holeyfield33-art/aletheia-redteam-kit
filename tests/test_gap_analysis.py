from __future__ import annotations

from engine.gap_analysis import UNKNOWN_TECHNIQUE, TAXONOMY_VERSION, build_gap_report


def test_build_gap_report_groups_by_custom_technique() -> None:
    results = [
        {
            "id": "PI_001",
            "technique": "nested_instruction",
            "expected_decision": "DENIED",
            "actual_decision": "PROCEED",
        },
        {
            "id": "PI_002",
            "technique": "nested_instruction",
            "expected_decision": "DENIED",
            "actual_decision": "DENIED",
        },
        {
            "id": "PE_001",
            "technique": "hypothetical_framing",
            "expected_decision": "DENIED",
            "actual_decision": "PROCEED",
        },
        {
            "id": "BC_001",
            "technique": "benign_lookup",
            "expected_decision": "PROCEED",
            "actual_decision": "PROCEED",
        },
    ]

    report = build_gap_report(results)
    assert report["taxonomy"] == TAXONOMY_VERSION
    assert report["total_tests"] == 4
    assert report["total_missed_blocks"] == 2
    assert report["techniques"]["nested_instruction"]["total"] == 2
    assert report["techniques"]["nested_instruction"]["missed_blocks"] == 1
    assert report["techniques"]["nested_instruction"]["bypass_rate"] == 50.0
    assert report["techniques"]["hypothetical_framing"]["bypass_rate"] == 100.0
    assert report["top_gaps"][0]["technique"] == "hypothetical_framing"


def test_build_gap_report_uses_unspecified_when_missing() -> None:
    report = build_gap_report(
        [
            {
                "id": "TA_001",
                "expected_decision": "DENIED",
                "actual_decision": "PROCEED",
            }
        ]
    )
    assert UNKNOWN_TECHNIQUE in report["techniques"]
    assert report["techniques"][UNKNOWN_TECHNIQUE]["missed_blocks"] == 1
