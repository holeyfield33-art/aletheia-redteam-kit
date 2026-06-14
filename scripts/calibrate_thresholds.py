#!/usr/bin/env python3
"""
CLI: calibrate analysis thresholds against red-team run results.

Loads ME / HE / APH suite results — offline from saved ``summary.json`` files,
or live by invoking the existing runner when ``ALETHEIA_API_KEY`` is set — and
writes a calibration report (JSON + Markdown) recommending a tuned
``flag_drift_violations`` threshold.

Usage:
    python scripts/calibrate_thresholds.py --mode offline --summary runs/<dir>/summary.json
    python scripts/calibrate_thresholds.py --mode live --target-url <url> --suite HE
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a plain script (`python scripts/calibrate_thresholds.py`).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from engine.calibration import (  # noqa: E402
    DEFAULT_TARGET_IDS,
    SUITES,
    calibrate,
)


def _build_catalog(suites: list[str]) -> dict[str, dict]:
    """Load attack definitions for the requested suites, keyed by id.

    Uses the dependency-light ``kit.catalog`` loader so offline calibration
    does not pull live-transport modules (httpx).
    """
    from kit.catalog import load_attacks

    catalog: dict[str, dict] = {}
    for suite in suites:
        category = SUITES[suite]
        for attack in load_attacks(category=category):
            if isinstance(attack, dict) and attack.get("id"):
                catalog[str(attack["id"])] = attack
    return catalog


def _rows_from_summaries(paths: list[str], suites: list[str]) -> dict[str, list[dict]]:
    """Partition saved summary.json results into the requested suites."""
    category_to_suite = {SUITES[s]: s for s in suites}
    results_by_suite: dict[str, list[dict]] = {s: [] for s in suites}
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rows = data.get("results") if isinstance(data, dict) else data
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            suite = category_to_suite.get(str(row.get("category")))
            if suite is not None:
                results_by_suite[suite].append(row)
    return results_by_suite


def _rows_from_live(suites: list[str], target_url: str | None) -> dict[str, list[dict]]:
    """Run each suite live via the existing runner (no re-implementation)."""
    from kit.client import AletheiaClient
    from kit.runner import load_attacks, run_attacks_with_backoff

    client = AletheiaClient(base_url=target_url) if target_url else AletheiaClient()
    results_by_suite: dict[str, list[dict]] = {}
    for suite in suites:
        attacks = load_attacks(category=SUITES[suite])
        results_by_suite[suite] = run_attacks_with_backoff(client, attacks)
    return results_by_suite


def _render_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Threshold Calibration Report")
    lines.append("")
    lines.append(f"- generated_at: {report.get('generated_at')}")
    lines.append(f"- mode: {report.get('mode')}")
    lines.append(f"- history_mode: {report.get('history_mode')}")
    lines.append(f"- current_threshold: {report.get('current_threshold')}")
    lines.append("")
    for suite, data in report.get("suites", {}).items():
        th = data["threshold"]
        lines.append(f"## {suite} ({data['category']})")
        lines.append("")
        lines.append(f"n={data['n']}  bypasses={data['n_bypass']}  "
                     f"disagreement={data['disagreement_score']}  "
                     f"override_rate={data['override_rate']}")
        lines.append("")
        lines.append("| id | drift | bypass | flagged@current | flagged@recommended |")
        lines.append("|----|-------|--------|-----------------|---------------------|")
        bypass_ids = {b["id"] for b in data["bypasses"]}
        for row_id, drift in data["drift"]["scores"].items():
            lines.append(
                f"| {row_id} | {drift} | {'yes' if row_id in bypass_ids else ''} "
                f"| {'x' if row_id in th['flagged_at_current'] else ''} "
                f"| {'x' if row_id in th['flagged_at_recommended'] else ''} |"
            )
        lines.append("")
        lines.append(f"**current {th['current']} -> recommended {th['recommended']}**")
        lines.append("")
        lines.append(f"_{th['rationale']}_")
        if th["newly_caught_bypasses"]:
            lines.append("")
            lines.append(f"Newly caught bypasses: {', '.join(th['newly_caught_bypasses'])}")
        if th["false_positive_risk_ids"]:
            lines.append(f"False-positive risk ids: {', '.join(th['false_positive_risk_ids'])}")
        lines.append("")
    glob = report.get("global_recommendation", {})
    lines.append("## Global recommendation")
    lines.append("")
    lines.append(f"Recommended threshold: **{glob.get('recommended_threshold')}** "
                 f"({glob.get('method')})")
    lines.append(f"- must_catch_satisfied: {glob.get('must_catch_satisfied')}")
    lines.append(f"- must_catch_missed: {glob.get('must_catch_missed')}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate drift/violation thresholds")
    parser.add_argument("--mode", choices=["live", "offline"], default="offline")
    parser.add_argument("--summary", action="append", default=[],
                        help="summary.json to re-process (offline; repeatable)")
    parser.add_argument("--suite", choices=["ME", "HE", "APH", "all"], default="all")
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--history-mode",
                        choices=["turn_trace", "payload_segments", "prompt_response"],
                        default="payload_segments")
    parser.add_argument("--current-threshold", type=float, default=0.7)
    parser.add_argument("--catch", nargs="*", default=list(DEFAULT_TARGET_IDS),
                        help="ids that must be flagged at the recommended threshold")
    parser.add_argument("--out-json", default="runs/calibration_report.json")
    parser.add_argument("--out-md", default="runs/calibration_report.md")
    args = parser.parse_args(argv)

    suites = ["ME", "HE", "APH"] if args.suite == "all" else [args.suite]

    if args.mode == "offline":
        if not args.summary:
            parser.error("--mode offline requires at least one --summary PATH")
        results_by_suite = _rows_from_summaries(args.summary, suites)
    else:
        if not os.environ.get("ALETHEIA_API_KEY"):
            parser.error("--mode live requires ALETHEIA_API_KEY in the environment")
        results_by_suite = _rows_from_live(suites, args.target_url)

    catalog = _build_catalog(suites)
    report = calibrate(
        results_by_suite,
        catalog,
        mode=args.history_mode,
        current_threshold=args.current_threshold,
        target_ids=args.catch,
    )
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["mode"] = args.mode
    report["inputs"] = {"summary_files": args.summary, "suites": suites}

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = _render_markdown(report)
    out_md.write_text(markdown + "\n", encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
