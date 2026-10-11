"""Copy a finished attempt's workspace into RUNS/ and record its agent usage.

usage: collect_run.py <run_id> <total_tokens> <tool_uses> <duration_ms> <report_file>
The usage numbers are copied verbatim from the Agent tool's completion record.
The workspace snapshot excludes the frozen input files that were provided
(they are reproducible from TASKS/) except repo/, which is the deliverable.
"""

import json
import shutil
import sys
from pathlib import Path

from common import RUNS, write_json


def main(run_id, total_tokens, tool_uses, duration_ms, report_file):
    schedule = json.loads((RUNS / "schedule.json").read_text())
    entry = next(a for a in schedule["attempts"] if a["run_id"] == run_id)
    out = RUNS.parent / entry["run_dir"]
    ws = Path(entry["workspace"])
    if (out / "repo").exists():
        raise SystemExit(f"{run_id} already collected; failures are never replaced")
    shutil.copytree(ws / "repo", out / "repo", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
    if (ws / "scratch").exists():
        shutil.copytree(ws / "scratch", out / "agent_scratch",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
    extra = sorted(str(p.relative_to(ws)) for p in ws.rglob("*") if p.is_file()
                   and not str(p.relative_to(ws)).startswith(("repo", "scratch", "TASK_PROMPT.md")))
    shutil.copy(report_file, out / "agent_report.md")
    write_json(out / "usage.json", {"run_id": run_id, "total_tokens": int(total_tokens), "tool_uses": int(tool_uses),
                                    "duration_ms": int(duration_ms), "workspace_files_outside_repo_scratch": extra,
                                    "source": "Agent tool completion record (verbatim)"})
    print(f"collected {run_id} -> {entry['run_dir']}")


if __name__ == "__main__":
    main(*sys.argv[1:])
