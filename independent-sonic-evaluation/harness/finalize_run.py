"""Finalize one attempt: extract its report, collect the workspace, measure, grade.

usage: finalize_run.py <run_id> <transcript.jsonl> <subagent_tokens> <tool_uses> <duration_ms>
The three numbers are copied verbatim from the Agent tool's completion notice.
"""

import json
import sys
import tempfile
from pathlib import Path

import collect_run
import grade
import transcript_metrics
from common import RUNS


def final_report(transcript):
    report = ""
    for line in Path(transcript).read_text(encoding="utf-8").splitlines():
        message = (json.loads(line).get("message") or {}) if line.strip() else {}
        if message.get("role") != "assistant" or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if block.get("type") == "tool_use" and block.get("name") == "SubagentHandback":
                report = block["input"].get("message", "")
            elif block.get("type") == "text" and block.get("text", "").strip() and not report:
                last_text = block["text"]
                report = report or ""
                final_report.last_text = last_text
    return report or getattr(final_report, "last_text", "(no final report found in transcript)")


def main(run_id, transcript, tokens, tool_uses, duration_ms):
    schedule = json.loads((RUNS / "schedule.json").read_text())
    entry = next(a for a in schedule["attempts"] if a["run_id"] == run_id)
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as handle:
        handle.write(final_report(transcript) + "\n")
    collect_run.main(run_id, tokens, tool_uses, duration_ms, handle.name)
    run_dir = RUNS.parent / entry["run_dir"]
    transcript_metrics.main(transcript, entry["workspace"], str(run_dir))
    data = grade.grade(entry["task"], run_dir)
    print(f"{run_id} {entry['task']} {entry['condition']}-{entry['attempt']}: {data['tests_passed']}/{data['tests_total']} "
          f"sonic={data['sonic_conformance'].get('compliant')}")


if __name__ == "__main__":
    main(*sys.argv[1:])
