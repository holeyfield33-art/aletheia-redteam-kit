#!/usr/bin/env python3
"""
Generate auto-remediation proposals from red-team run results.

Reads a saved summary.json (offline) or runs the suites live, derives one
template-based remediation proposal per failing technique, and stores them under
``<artifact-dir>/remediation/proposals.json`` for review/approval (via the
dashboard or ``--approve``).

Usage:
    python scripts/generate_remediation.py --summary runs/<dir>/summary.json
    python scripts/generate_remediation.py --summary s.json --approve REM-1a2b3c4d
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from engine.remediation import generate_proposals  # noqa: E402
from kit.remediation_store import apply_proposal, load_proposals, save_proposals  # noqa: E402


def _rows_from_summary(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("results") if isinstance(data, dict) else data
        rows.extend(r for r in (items or []) if isinstance(r, dict))
    return rows


def _rows_from_live(target_url: str | None) -> list[dict]:
    from engine.calibration import SUITES
    from kit.client import AletheiaClient
    from kit.runner import load_attacks, run_attacks_with_backoff

    client = AletheiaClient(base_url=target_url) if target_url else AletheiaClient()
    rows: list[dict] = []
    for category in SUITES.values():
        rows.extend(run_attacks_with_backoff(client, load_attacks(category=category)))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate auto-remediation proposals")
    parser.add_argument("--mode", choices=["live", "offline"], default="offline")
    parser.add_argument("--summary", action="append", default=[])
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--focus-technique", action="append", default=None)
    parser.add_argument("--artifact-dir", default="runs")
    parser.add_argument("--approve", action="append", default=[],
                        help="proposal_id to approve+apply immediately (repeatable)")
    args = parser.parse_args(argv)

    artifact_dir = Path(args.artifact_dir)

    if args.mode == "offline":
        if not args.summary:
            parser.error("--mode offline requires at least one --summary PATH")
        rows = _rows_from_summary(args.summary)
    else:
        import os
        if not os.environ.get("ALETHEIA_API_KEY"):
            parser.error("--mode live requires ALETHEIA_API_KEY in the environment")
        rows = _rows_from_live(args.target_url)

    proposals = generate_proposals(rows, focus_techniques=args.focus_technique)
    save_proposals(artifact_dir, proposals)

    for proposal_id in args.approve:
        result = apply_proposal(artifact_dir, proposal_id)
        print(f"[remediation] approve {proposal_id}: {result.get('status') or result.get('reason')}")

    current = load_proposals(artifact_dir)
    print(f"[remediation] {len(current)} proposal(s) in {artifact_dir}/remediation/proposals.json")
    for p in current:
        print(f"  - {p['proposal_id']} {p['severity']:<8} {p['technique']:<32} "
              f"status={p['status']} triggers={','.join(p['trigger_ids'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
