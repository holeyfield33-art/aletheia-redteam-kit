"""
Run the full attack catalog against the Aletheia API.

Usage:
    python -m kit.runner                         # all categories
    python -m kit.runner --category prompt_injection
    python -m kit.runner --output results.json   # default: summary.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from kit.client import AletheiaClient

ATTACK_DIR = Path(__file__).parent.parent / "attacks"
DEFAULT_OUTPUT = Path("summary.json")


def load_attacks(category: str | None = None) -> list[dict]:
    """Load attacks from JSON catalog. category=None loads all."""
    files = [ATTACK_DIR / f"{category}.json"] if category else sorted(ATTACK_DIR.glob("*.json"))
    attacks: list[dict] = []
    for path in files:
        if not path.exists():
            raise FileNotFoundError(f"Attack catalog not found: {path}")
        attacks.extend(json.loads(path.read_text()))
    return attacks


def run_attack(client: AletheiaClient, attack: dict) -> dict:
    """Execute one attack, return a result record."""
    started = time.time()
    try:
        result = client.audit(
            payload=attack["payload"],
            action=attack.get("action", "fetch_data"),
            origin=attack.get("origin", "redteam-kit"),
        )
        latency_ms = (time.time() - started) * 1000
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "severity": attack.get("severity", "MEDIUM"),
            "expected_decision": attack["expected_decision"],
            "actual_decision": result.decision,
            "match": result.decision == attack["expected_decision"],
            "request_id": result.request_id,
            "latency_ms": round(latency_ms, 1),
            "receipt": result.receipt,
            "reason": result.reason,
            "error": None,
        }
    except Exception as exc:
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "severity": attack.get("severity", "MEDIUM"),
            "expected_decision": attack["expected_decision"],
            "actual_decision": "ERROR",
            "match": False,
            "request_id": None,
            "latency_ms": None,
            "receipt": None,
            "reason": None,
            "error": str(exc),
        }


def summarize(results: list[dict]) -> dict:
    """Aggregate per-category and total stats."""
    total = len(results)
    matches = sum(1 for r in results if r["match"])
    blocked = sum(1 for r in results if r["actual_decision"] == "DENIED")
    proceeded = sum(1 for r in results if r["actual_decision"] == "PROCEED")
    errors = sum(1 for r in results if r["actual_decision"] == "ERROR")

    by_cat: dict[str, dict] = {}
    for r in results:
        category = r["category"]
        if category not in by_cat:
            by_cat[category] = {"total": 0, "matches": 0, "blocked": 0, "proceeded": 0}
        by_cat[category]["total"] += 1
        by_cat[category]["matches"] += int(r["match"])
        if r["actual_decision"] == "DENIED":
            by_cat[category]["blocked"] += 1
        elif r["actual_decision"] == "PROCEED":
            by_cat[category]["proceeded"] += 1

    benign = by_cat.get("benign_controls", {"total": 0, "blocked": 0, "proceeded": 0})
    benign_total = benign["total"]
    benign_blocked = benign["blocked"]
    benign_proceeded = benign["proceeded"]
    trial_mode_suspected = benign_total > 0 and benign_blocked == benign_total and benign_proceeded == 0

    return {
        "attacks_total": total,
        "expectation_match": matches,
        "expectation_match_rate": round(100 * matches / total, 1) if total else 0.0,
        "blocked": blocked,
        "proceeded": proceeded,
        "errors": errors,
        "block_rate": round(100 * blocked / total, 1) if total else 0.0,
        "categories": by_cat,
        "trial_mode_suspected": trial_mode_suspected,
        "trial_mode_reason": (
            "All benign_controls payloads were denied; this can indicate trial-tier blanket blocking"
            if trial_mode_suspected
            else None
        ),
    }


def cli() -> int:
    parser = argparse.ArgumentParser(description="Aletheia red team kit")
    parser.add_argument("--category", help="Run only one category (filename without .json)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output path for summary JSON")
    parser.add_argument("--base-url", help="Override ALETHEIA_BASE_URL")
    args = parser.parse_args()

    attacks = load_attacks(args.category)
    print(f"Loaded {len(attacks)} attacks", file=sys.stderr)

    with AletheiaClient(base_url=args.base_url) as client:
        results = []
        for i, attack in enumerate(attacks, 1):
            result = run_attack(client, attack)
            status = "OK" if result["match"] else "NO"
            print(
                f"[{i}/{len(attacks)}] {status} {attack['id']:<12} "
                f"{attack['category']:<20} {result['actual_decision']}",
                file=sys.stderr,
            )
            results.append(result)

    summary = summarize(results)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_url": client.base_url,
        **summary,
        "results": results,
    }
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(
        f"\nDone. {summary['blocked']}/{summary['attacks_total']} blocked, "
        f"expectation match {summary['expectation_match_rate']}%. "
        f"Output: {args.output}",
        file=sys.stderr,
    )
    return 0 if summary["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(cli())