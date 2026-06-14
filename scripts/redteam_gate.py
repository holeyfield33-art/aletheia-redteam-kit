#!/usr/bin/env python3
"""
Headless red-team CI gate.

Faces the hallucination and planning-hijack suites against the Aletheia target
and breaks the build (non-zero exit) when the override rate regresses or a
critical must-block probe (e.g. ``false_citation``) leaks. Designed to run in
GitHub Actions on every push so attacks gate commits.

Modes:
  live    - run the suites against the target via the existing runner
            (requires ALETHEIA_API_KEY).
  offline - re-evaluate a saved summary.json without calling the API.

Usage:
    python scripts/redteam_gate.py --mode live --suite all \
        --max-override-rate 0.0 --baseline-summary baseline_summary.json
    python scripts/redteam_gate.py --mode offline --summary runs/<dir>/summary.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from engine.calibration import SUITES  # noqa: E402
from engine.ci_gates import (  # noqa: E402
    DEFAULT_CRITICAL_TECHNIQUES,
    evaluate_ci_gates,
)
from engine.calibration import build_adjudication_log  # noqa: E402
from engine.disagreement_metrics import calculate_override_rate  # noqa: E402


def _suite_categories(suite: str) -> list[str]:
    suites = ["ME", "HE", "APH"] if suite == "all" else [suite]
    return [SUITES[s] for s in suites]


def _rows_from_summary(path: str, categories: set[str]) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("results") if isinstance(data, dict) else data
    return [
        row
        for row in (rows or [])
        if isinstance(row, dict) and str(row.get("category")) in categories
    ]


def _rows_from_live(categories: list[str], target_url: str | None) -> list[dict]:
    from kit.client import AletheiaClient
    from kit.runner import load_attacks, run_attacks_with_backoff

    client = AletheiaClient(base_url=target_url) if target_url else AletheiaClient()
    rows: list[dict] = []
    for category in categories:
        rows.extend(run_attacks_with_backoff(client, load_attacks(category=category)))
    return rows


def _baseline_override_rate(path: str | None, categories: set[str]) -> float | None:
    if not path or not Path(path).exists():
        return None
    try:
        rows = _rows_from_summary(path, categories)
    except (json.JSONDecodeError, OSError):
        return None
    if not rows:
        return None
    return calculate_override_rate(build_adjudication_log(rows))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless red-team CI gate")
    parser.add_argument("--mode", choices=["live", "offline"], default="live")
    parser.add_argument("--suite", choices=["ME", "HE", "APH", "all"], default="all")
    parser.add_argument("--summary", help="summary.json to evaluate (offline mode)")
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--baseline-summary", default=None,
                        help="prior summary.json for override-rate regression check")
    parser.add_argument("--max-override-rate", type=float, default=0.0,
                        help="fail if override rate exceeds this absolute value")
    parser.add_argument("--max-override-increase", type=float, default=0.0,
                        help="fail if override rate rose more than this above baseline")
    parser.add_argument("--critical-technique", action="append", default=None,
                        help="technique substring that must always block (repeatable)")
    parser.add_argument("--critical-id", action="append", default=[],
                        help="attack id that must always block (repeatable)")
    parser.add_argument("--out-json", default="redteam_gate.json")
    args = parser.parse_args(argv)

    categories = _suite_categories(args.suite)
    category_set = set(categories)

    if args.mode == "offline":
        if not args.summary:
            parser.error("--mode offline requires --summary PATH")
        rows = _rows_from_summary(args.summary, category_set)
    else:
        if not os.environ.get("ALETHEIA_API_KEY"):
            parser.error("--mode live requires ALETHEIA_API_KEY in the environment")
        rows = _rows_from_live(categories, args.target_url)

    critical_techniques = args.critical_technique or list(DEFAULT_CRITICAL_TECHNIQUES)
    report = evaluate_ci_gates(
        rows,
        baseline_override_rate=_baseline_override_rate(args.baseline_summary, category_set),
        max_override_rate=args.max_override_rate,
        max_override_increase=args.max_override_increase,
        critical_techniques=critical_techniques,
        critical_ids=args.critical_id,
    )
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["mode"] = args.mode
    report["suite"] = args.suite

    Path(args.out_json).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    status = "PASS" if report["pass"] else "FAIL"
    print(f"[redteam-gate] {status} "
          f"override_rate={report['override_rate']} "
          f"bypasses={report['n_bypass']} "
          f"violations={report['violations'] or 'none'}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
