from __future__ import annotations

from collections import defaultdict


UNKNOWN_TECHNIQUE = "unspecified"
TAXONOMY_VERSION = "custom-v1"


def _normalize_technique(value: object) -> str:
    if not isinstance(value, str):
        return UNKNOWN_TECHNIQUE
    technique = value.strip().lower()
    return technique or UNKNOWN_TECHNIQUE


def build_gap_report(results: list[dict]) -> dict:
    """Build a custom-technique bypass report from API attack results."""
    totals: dict[str, int] = defaultdict(int)
    misses: dict[str, int] = defaultdict(int)
    sample_ids: dict[str, list[str]] = defaultdict(list)

    for result in results:
        technique = _normalize_technique(result.get("technique"))
        totals[technique] += 1

        expected = str(result.get("expected_decision", ""))
        actual = str(result.get("actual_decision", ""))
        missed_block = expected == "DENIED" and actual == "PROCEED"
        if missed_block:
            misses[technique] += 1
            attack_id = str(result.get("id", "")).strip()
            if attack_id and len(sample_ids[technique]) < 5:
                sample_ids[technique].append(attack_id)

    techniques: dict[str, dict] = {}
    for technique in sorted(totals):
        total = totals[technique]
        missed = misses.get(technique, 0)
        bypass_rate = round((100 * missed / total), 1) if total else 0.0
        techniques[technique] = {
            "total": total,
            "missed_blocks": missed,
            "bypass_rate": bypass_rate,
            "sample_attack_ids": sample_ids.get(technique, []),
        }

    ranked = sorted(
        techniques.items(),
        key=lambda item: (
            item[1]["bypass_rate"],
            item[1]["missed_blocks"],
            item[1]["total"],
            item[0],
        ),
        reverse=True,
    )
    top_gaps = [
        {
            "technique": name,
            "bypass_rate": stats["bypass_rate"],
            "missed_blocks": stats["missed_blocks"],
            "total": stats["total"],
        }
        for name, stats in ranked[:5]
        if stats["missed_blocks"] > 0
    ]

    total_missed_blocks = sum(misses.values())
    return {
        "taxonomy": TAXONOMY_VERSION,
        "total_tests": len(results),
        "total_missed_blocks": total_missed_blocks,
        "techniques": techniques,
        "top_gaps": top_gaps,
    }


def build_category_gap_report(results: list[dict]) -> dict:
    """Build category-level missed-block report for summary output."""
    totals: dict[str, int] = defaultdict(int)
    missed: dict[str, int] = defaultdict(int)

    for result in results:
        category = str(result.get("category") or "unknown").strip().lower() or "unknown"
        totals[category] += 1

        expected = str(result.get("expected_decision", ""))
        actual = str(result.get("actual_decision", ""))
        if expected == "DENIED" and actual == "PROCEED":
            missed[category] += 1

    categories: dict[str, dict] = {}
    for category in sorted(totals):
        total = totals[category]
        missed_blocks = missed.get(category, 0)
        categories[category] = {
            "total": total,
            "missed_blocks": missed_blocks,
            "bypass_rate": round((100 * missed_blocks / total), 1) if total else 0.0,
        }

    ranked = sorted(
        categories.items(),
        key=lambda item: (item[1]["bypass_rate"], item[1]["missed_blocks"], item[1]["total"], item[0]),
        reverse=True,
    )
    top_gaps = [
        {
            "category": name,
            "bypass_rate": stats["bypass_rate"],
            "missed_blocks": stats["missed_blocks"],
            "total": stats["total"],
        }
        for name, stats in ranked[:5]
        if stats["missed_blocks"] > 0
    ]

    return {
        "total_tests": len(results),
        "categories": categories,
        "top_gaps": top_gaps,
    }
