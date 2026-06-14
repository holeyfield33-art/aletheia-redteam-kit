#!/usr/bin/env python3
"""
Export adjudication logs + telemetry for the NIST-2025-0035 submission.

Produces a citable dataset (JSON + CSV + Markdown) focused on the agentic
techniques (tool_selection_override, recursive_self_improvement_bait, fabricated
precedent) showing how often agentic loops degrade — and correlating those
bypasses with unsigned / missing-signature receipts to motivate cryptographic
enforcement (Ed25519-signed manifests).

Modes:
  offline - read a saved summary.json (default).
  live    - run the APH + HE suites against the target (requires ALETHEIA_API_KEY).

Usage:
    python scripts/export_nist_telemetry.py --summary runs/<dir>/summary.json
    python scripts/export_nist_telemetry.py --mode live --suite APH HE
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from engine.calibration import SUITES  # noqa: E402
from engine.nist_export import (  # noqa: E402
    DEFAULT_FOCUS_TECHNIQUES,
    build_dataset,
    records_to_csv_rows,
)


def _rows_from_summary(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("results") if isinstance(data, dict) else data
        rows.extend(r for r in (items or []) if isinstance(r, dict))
    return rows


def _rows_from_live(suites: list[str], target_url: str | None) -> list[dict]:
    from kit.client import AletheiaClient
    from kit.runner import load_attacks, run_attacks_with_backoff

    client = AletheiaClient(base_url=target_url) if target_url else AletheiaClient()
    rows: list[dict] = []
    for suite in suites:
        rows.extend(run_attacks_with_backoff(client, load_attacks(category=SUITES[suite])))
    return rows


def _render_markdown(dataset: dict, *, generated_at: str) -> str:
    m = dataset["manifest"]
    corr = m["signature_correlation"]
    lines = [
        "# NIST-2025-0035 Telemetry Export",
        "",
        "Empirical telemetry for *Securing AI Agent Systems*: agentic bypass rates",
        "and their correlation with unsigned execution receipts.",
        "",
        f"- generated_at: {generated_at}",
        f"- dataset_sha256: `{m['dataset_sha256']}`",
        f"- records: {m['n_records']}  bypasses: {m['n_bypass']}",
        f"- overall override rate: {m['overall_override_rate']}",
        "",
        "## Cryptographic-enforcement correlation",
        "",
        f"- signed receipts: {corr['signed_n']} (bypass rate {corr['signed_bypass_rate']})",
        f"- unsigned/missing receipts: {corr['unsigned_or_missing_n']} "
        f"(bypass rate {corr['unsigned_or_missing_bypass_rate']})",
        "",
        "## Technique breakdown",
        "",
        "| technique | n | bypasses | override_rate | signed | unsigned_dev | missing |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for technique, b in sorted(m["technique_breakdown"].items()):
        lines.append(
            f"| {technique} | {b['n']} | {b['bypasses']} | {b['override_rate']} "
            f"| {b['signed']} | {b['unsigned_dev_mode']} | {b['missing']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export NIST-2025-0035 telemetry dataset")
    parser.add_argument("--mode", choices=["live", "offline"], default="offline")
    parser.add_argument("--summary", action="append", default=[],
                        help="summary.json to read (offline; repeatable)")
    parser.add_argument("--suite", nargs="*", choices=["ME", "HE", "APH"], default=["APH", "HE"])
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--focus-technique", action="append", default=None,
                        help="technique substring to focus on (repeatable)")
    parser.add_argument("--all-rows", action="store_true",
                        help="export every row, not just focus techniques")
    parser.add_argument("--out-json", default="runs/nist_telemetry.json")
    parser.add_argument("--out-csv", default="runs/nist_telemetry.csv")
    parser.add_argument("--out-md", default="runs/nist_telemetry.md")
    args = parser.parse_args(argv)

    if args.mode == "offline":
        if not args.summary:
            parser.error("--mode offline requires at least one --summary PATH")
        rows = _rows_from_summary(args.summary)
    else:
        if not os.environ.get("ALETHEIA_API_KEY"):
            parser.error("--mode live requires ALETHEIA_API_KEY in the environment")
        rows = _rows_from_live(args.suite, args.target_url)

    focus = args.focus_technique or list(DEFAULT_FOCUS_TECHNIQUES)
    dataset = build_dataset(rows, focus_techniques=focus, focus_only=not args.all_rows)
    generated_at = datetime.now(timezone.utc).isoformat()
    dataset["manifest"]["generated_at"] = generated_at
    dataset["manifest"]["mode"] = args.mode
    dataset["manifest"]["source_summaries"] = args.summary

    out_json = Path(args.out_json)
    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    for path in (out_json, out_csv, out_md):
        path.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(dataset, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with out_csv.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(records_to_csv_rows(dataset["records"]))
    markdown = _render_markdown(dataset, generated_at=generated_at)
    out_md.write_text(markdown + "\n", encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
