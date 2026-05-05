"""API analysis and multi-turn parsing helpers."""
from __future__ import annotations

import re

MULTI_TURN_REGEX = re.compile(r"turn\s+\d+\s*/\s*\d+\s*:\s*", re.IGNORECASE)
HIGH_RISK_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "data_exfiltration",
    "tool_abuse",
    "policy_evasion",
    "obfuscated",
    "hybrid_tool",
    "memory_poisoning",
    "multi_turn",
}


def split_multi_turn_payload(payload: str) -> list[str]:
    """Parse turn-marked payload text into executable turns."""
    pieces = MULTI_TURN_REGEX.split(payload)
    turns = [piece.strip(" .\n\t") for piece in pieces if piece and piece.strip(" .\n\t")]
    return turns or [payload.strip()]


def extract_multi_turn_steps(attack: dict) -> list[str]:
    """Extract explicit multi-turn steps from attack schema, fallback to payload parsing."""
    turns_value = attack.get("turns")
    if isinstance(turns_value, list):
        turns = [str(step).strip() for step in turns_value if str(step).strip()]
        if turns:
            return turns

    steps_value = attack.get("steps")
    if isinstance(steps_value, list):
        extracted: list[str] = []
        for step in steps_value:
            if isinstance(step, dict):
                text = str(step.get("payload") or step.get("message") or "").strip()
            else:
                text = str(step).strip()
            if text:
                extracted.append(text)
        if extracted:
            return extracted

    return split_multi_turn_payload(str(attack.get("payload", "")))


def compute_high_risk_block_rate(summary: dict) -> float:
    """Compute BLOCK rate limited to high-risk categories in summary.categories."""
    categories = summary.get("categories", {})
    totals = 0
    blocked = 0
    for name, row in categories.items():
        if str(name).strip().lower() not in HIGH_RISK_CATEGORIES:
            continue
        totals += int(row.get("total", 0))
        blocked += int(row.get("blocked", 0))
    return round(100.0 * blocked / totals, 1) if totals else 0.0


def build_api_regression_summary(current_summary: dict, baseline_summary: dict) -> dict:
    """Build API regression deltas with emphasis on high-risk category block rate."""
    current_high_risk = compute_high_risk_block_rate(current_summary)
    baseline_high_risk = compute_high_risk_block_rate(baseline_summary)
    drop = round(baseline_high_risk - current_high_risk, 1)

    return {
        "current_high_risk_block_rate": current_high_risk,
        "baseline_high_risk_block_rate": baseline_high_risk,
        "high_risk_block_rate_drop": drop,
        "regressed": drop > 0,
    }