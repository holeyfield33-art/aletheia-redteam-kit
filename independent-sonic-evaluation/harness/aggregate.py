"""Aggregate every graded attempt into RESULTS.csv and RESULTS.json.

Per attempt: one CSV row. Per task x condition: means over attempts. Paired
comparisons: for each task, the per-task condition mean difference; summarised
by mean, a seeded bootstrap 95% CI over tasks, and an exact two-sided sign test.
Nothing is imputed: an attempt that is missing is reported as missing.
"""

import csv
import json
import math
import random
import re
from pathlib import Path
from statistics import mean, pstdev

from common import EVAL, RUNS, TASKS, write_json

CONDITIONS = "ABC"
SENSITIVITY = False  # set by main(sensitivity=True): keep only attempts served by the majority model
METRICS = ["pass_rate", "full_success", "security_pass_rate", "requirements_failed", "sonic_conformant",
           "interface_compliant", "input_tokens_sum", "context_growth_tokens", "prompt_chars", "generated_chars",
           "model_calls", "tool_calls", "bash_calls", "duration_s", "subagent_tokens"]


def sign_test(diffs):
    pos, neg = sum(d > 0 for d in diffs), sum(d < 0 for d in diffs)
    n = pos + neg
    if n == 0:
        return {"positive": 0, "negative": 0, "ties": len(diffs), "p_two_sided": 1.0}
    k = min(pos, neg)
    p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
    return {"positive": pos, "negative": neg, "ties": len(diffs) - n, "p_two_sided": round(p, 4)}


def bootstrap_ci(diffs, reps=10000, seed=7):
    if not diffs:
        return None
    rng = random.Random(seed)
    means = sorted(mean(rng.choice(diffs) for _ in diffs) for _ in range(reps))
    return [round(means[int(0.025 * reps)], 4), round(means[int(0.975 * reps) - 1], 4)]


def touched_audio(run_dir):
    text = (run_dir / "transcript.md").read_text(encoding="utf-8") if (run_dir / "transcript.md").exists() else ""
    calls = re.findall(r"### tool call: \w+\n\n```json\n(.*?)```", text, re.S)
    return {"template_wav": any("template.wav" in c for c in calls), "events_json": any("events.json" in c for c in calls),
            "score_or_spec_json_read": any(("score.json" in c or "spec.json" in c) for c in calls)}


def main(sensitivity=False):
    global SENSITIVITY
    SENSITIVITY = sensitivity
    schedule = json.loads((RUNS / "schedule.json").read_text())
    sizes = json.loads((TASKS / "_condition_sizes.json").read_text())
    rows = []
    for entry in schedule["attempts"]:
        run_dir = EVAL / entry["run_dir"]
        row = {"run_id": entry["run_id"], "task": entry["task"], "condition": entry["condition"],
               "attempt": entry["attempt"], "executed": (run_dir / "grade.json").exists()}
        if row["executed"]:
            g = json.loads((run_dir / "grade.json").read_text())
            t = json.loads((run_dir / "transcript_metrics.json").read_text())
            u = json.loads((run_dir / "usage.json").read_text())
            audio = touched_audio(run_dir)
            row.update({
                "tests_passed": g["tests_passed"], "tests_total": g["tests_total"], "pass_rate": g["pass_rate"],
                "full_success": int(g["full_success"]),
                "security_tests_passed": g["security_tests_passed"], "security_tests_total": g["security_tests_total"],
                "security_pass_rate": round(g["security_tests_passed"] / g["security_tests_total"], 4),
                "requirements_failed": len(g["requirements_failed"]),
                "requirements_failed_ids": " ".join(g["requirements_failed"]),
                "requirements_failed_high": len(g["requirements_failed_high"]),
                "syntax_errors": len(g["syntax_errors"]), "collection_error": int(g["collection_error"]),
                "runtime_error_tests": len(g["runtime_error_tests"]),
                "sonic_conformant": int(bool(g["sonic_conformance"].get("compliant"))),
                "sonic_issue_kinds": " ".join(g["sonic_conformance"].get("issue_kinds", [])),
                "interface_compliant": int(g["interface_compliant"]),
                "prompt_chars": entry["prompt_chars"],
                "materials_chars": sizes[entry["task"]][entry["condition"]]["materials_chars"],
                "workspace_text_bytes": sizes[entry["task"]][entry["condition"]]["workspace_text_bytes"],
                "input_tokens_sum": t["input_tokens_sum"], "first_call_input_tokens": t["first_call_input_tokens"],
                "context_growth_tokens": t["context_growth_tokens"],
                "output_tokens_logged_lower_bound": t["output_tokens_logged_lower_bound"],
                "generated_chars": t["generated_chars"], "model_calls": t["model_calls"],
                "tool_calls": t["tool_calls"], "bash_calls": t["tool_calls_by_name"].get("Bash", 0),
                "edit_write_calls": t["tool_calls_by_name"].get("Edit", 0) + t["tool_calls_by_name"].get("Write", 0),
                "isolation_violations": len(t["isolation_violations"]),
                "configured_model_digest": " ".join(t["configured_model_sha256"]),
                "served_model_digest": " ".join(t["served_model_sha256_by_call"]),
                "opened_template_wav": int(audio["template_wav"]), "opened_events_json": int(audio["events_json"]),
                "subagent_tokens": u["total_tokens"], "duration_s": round(u["duration_ms"] / 1000, 2),
                "agent_tool_uses_reported": u["tool_uses"],
            })
        rows.append(row)
    rows.sort(key=lambda r: (r["task"], r["condition"], r["attempt"]))
    fields = list(dict.fromkeys(k for r in rows for k in r))
    if not sensitivity:
        with open(EVAL / "RESULTS.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    done_all = [r for r in rows if r["executed"]]
    served_counts = {}
    for r in done_all:
        served_counts[r["served_model_digest"]] = served_counts.get(r["served_model_digest"], 0) + 1
    majority = max(served_counts, key=served_counts.get)
    done = done_all
    if SENSITIVITY:
        done = [r for r in done_all if r["served_model_digest"] == majority]
    tasks = sorted({r["task"] for r in rows})
    per_task = {}
    for task in tasks:
        per_task[task] = {}
        for cond in CONDITIONS:
            rs = [r for r in done if r["task"] == task and r["condition"] == cond]
            per_task[task][cond] = {"attempts": len(rs), **{m: round(mean(r[m] for r in rs), 4) if rs else None for m in METRICS},
                                    "pass_rate_range": [min(r["pass_rate"] for r in rs), max(r["pass_rate"] for r in rs)] if rs else None}
    paired = {}
    for a, b in (("B", "A"), ("C", "A"), ("C", "B")):
        paired[f"{a}_minus_{b}"] = {}
        for m in METRICS:
            diffs = [per_task[t][a][m] - per_task[t][b][m] for t in tasks
                     if per_task[t][a][m] is not None and per_task[t][b][m] is not None]
            paired[f"{a}_minus_{b}"][m] = {"tasks": len(diffs), "mean_diff": round(mean(diffs), 4) if diffs else None,
                                           "bootstrap95_over_tasks": bootstrap_ci(diffs), "sign_test": sign_test(diffs)}
    by_condition = {}
    for cond in CONDITIONS:
        rs = [r for r in done if r["condition"] == cond]
        by_condition[cond] = {"attempts": len(rs)}
        for m in METRICS:
            values = [r[m] for r in rs]
            by_condition[cond][m] = {"mean": round(mean(values), 4), "sd": round(pstdev(values), 4),
                                     "min": min(values), "max": max(values)} if values else None
        by_condition[cond]["full_successes"] = sum(r["full_success"] for r in rs)
        by_condition[cond]["isolation_violations"] = sum(r["isolation_violations"] for r in rs)
        by_condition[cond]["opened_template_wav"] = sum(r.get("opened_template_wav", 0) for r in rs)
        by_condition[cond]["syntax_or_collection_failures"] = sum(r["syntax_errors"] + r["collection_error"] for r in rs)
    challenge = json.loads((EVAL / "CHALLENGE" / "challenge_results.json").read_text())["summary"] \
        if (EVAL / "CHALLENGE" / "challenge_results.json").exists() else None
    music = json.loads((EVAL / "MUSIC" / "music_probe.json").read_text())["summary"] \
        if (EVAL / "MUSIC" / "music_probe.json").exists() else None
    validation = json.loads((TASKS / "_validation.json").read_text())
    result = {
        "planned_attempts": len(rows), "executed_attempts": len(done_all),
        "attempts_in_this_analysis": len(done),
        "served_model_digest_counts": served_counts,
        "analysis": "majority-served-model attempts only (sensitivity)" if sensitivity else "all executed attempts (primary)",
        "unexecuted": [r["run_id"] for r in rows if not r["executed"]],
        "by_condition": by_condition, "per_task": per_task, "paired_per_task": paired,
        "unfilled_scaffold_hidden_tests_passed": {t: f'{v["unfilled_scaffold_tests_passed"]}/{v["hidden_tests"]}'
                                                  for t, v in validation.items()},
        "fixed_material_chars_by_condition": {c: sum(s[c]["materials_chars"] for s in sizes.values()) for c in CONDITIONS},
        "challenge_summary": challenge, "music_probe_summary": music,
        "notes": ["Token figures are API usage fields recorded in sub-agent transcripts; input tokens include a fixed agent "
                  "harness overhead (first_call_input_tokens) identical across conditions.",
                  "Logged output_tokens are mid-stream snapshots and only a lower bound; generated_chars is the exact size "
                  "of text and tool-call inputs the agent produced.",
                  "p-values are exact two-sided sign tests over 10 tasks; no correction for multiple comparisons."],
    }
    if sensitivity:
        return result
    result["sensitivity_majority_served_model_only"] = {
        k: v for k, v in main(sensitivity=True).items()
        if k in ("attempts_in_this_analysis", "by_condition", "paired_per_task", "analysis")}
    SENSITIVITY = False
    write_json(EVAL / "RESULTS.json", result)
    for cond in CONDITIONS:
        bc = result["by_condition"][cond]
        if bc["attempts"]:
            print(cond, bc["attempts"], "full", bc["full_successes"], "pass", bc["pass_rate"]["mean"],
                  "in_tok", bc["input_tokens_sum"]["mean"], "growth", bc["context_growth_tokens"]["mean"],
                  "dur", bc["duration_s"]["mean"], "tools", bc["tool_calls"]["mean"], "wav", bc["opened_template_wav"])


if __name__ == "__main__":
    main()
