from __future__ import annotations

import hashlib
from datetime import datetime, timezone


HIGH_IMPACT_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "policy_evasion",
    "tool_abuse",
    "data_exfiltration",
    "session_campaigns",
    "multi_turn",
}


def _severity_score(value: str | None) -> int:
    normalized = str(value or "").strip().upper()
    if normalized == "CRITICAL":
        return 40
    if normalized == "HIGH":
        return 30
    if normalized == "MEDIUM":
        return 20
    if normalized == "LOW":
        return 10
    return 0


def _selection_reason(row: dict, category_hints: set[str]) -> str:
    category = str(row.get("category", "")).strip().lower()
    source = str(row.get("source", "")).strip().lower()
    adapter = str(row.get("source_adapter", "")).strip().lower()

    if category_hints and category in category_hints:
        return "category_focus"
    if "threat_feed" in source:
        return "threat_feed_signal"
    if source.startswith("external_corpus:"):
        return "external_corpus_signal"
    if adapter and adapter != "none":
        return "adapter_signal"
    if category in HIGH_IMPACT_CATEGORIES:
        return "high_impact_category"
    return "baseline_coverage"


def _selection_score(row: dict, category_hints: set[str]) -> int:
    category = str(row.get("category", "")).strip().lower()
    source = str(row.get("source", "")).strip().lower()
    adapter = str(row.get("source_adapter", "")).strip().lower()
    score = _severity_score(str(row.get("severity", "")))

    if category in HIGH_IMPACT_CATEGORIES:
        score += 8
    if category_hints and category in category_hints:
        score += 12
    if "threat_feed" in source:
        score += 15
    if source.startswith("external_corpus:"):
        score += 10
    if adapter and adapter != "none":
        score += 6
    if str(row.get("category", "")).strip().lower() == "benign_controls":
        score -= 25
    return score


def _campaign_id(rows: list[dict], mode: str) -> str:
    joined = "|".join(sorted(str(row.get("id", "")) for row in rows))
    digest = hashlib.sha256((mode + "::" + joined).encode("utf-8")).hexdigest()[:12]
    return f"cmp-{digest}"


def build_campaign_plan(
    attacks: list[dict],
    *,
    mode: str,
    category_hints: set[str] | None = None,
    max_targets: int = 0,
) -> tuple[list[dict], dict]:
    normalized_mode = str(mode or "none").strip().lower()
    hints = set(category_hints or set())

    if normalized_mode == "none":
        return [dict(row) for row in attacks], {
            "enabled": False,
            "campaign_mode": "none",
            "selected": 0,
            "total": len(attacks),
            "campaign_id": None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    ranked = [dict(row) for row in attacks]
    ranked.sort(
        key=lambda row: (
            _selection_score(row, hints),
            str(row.get("id", "")),
        ),
        reverse=True,
    )

    limit = int(max_targets or 0)
    if limit > 0:
        selected = ranked[:limit]
    else:
        selected = ranked

    campaign_id = _campaign_id(selected, normalized_mode)
    reason_counts: dict[str, int] = {}
    annotated: list[dict] = []
    for row in selected:
        updated = dict(row)
        reason = _selection_reason(updated, hints)
        source_signal = "threat_feed" if "threat_feed" in str(updated.get("source", "")).lower() else "catalog"
        if str(updated.get("source", "")).lower().startswith("external_corpus:"):
            source_signal = "external_corpus"
        if str(updated.get("source_adapter", "")).strip().lower() not in {"", "none"}:
            source_signal = "adapter"

        updated["campaign_id"] = campaign_id
        updated["selection_reason"] = reason
        updated["source_signal"] = source_signal
        annotated.append(updated)
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    manifest = {
        "enabled": True,
        "campaign_mode": normalized_mode,
        "campaign_id": campaign_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selected": len(annotated),
        "total": len(attacks),
        "max_targets": int(max_targets or 0),
        "selection_reason_counts": reason_counts,
        "selected_attack_ids": [str(row.get("id", "")) for row in annotated],
    }
    return annotated, manifest
