"""Pre-freeze validation of the benchmark (run before any coding attempt).

For each task: the score must pass the ORIGINAL Sonic grammar validation and
compile; the reference solution must be structurally conformant with the score
and pass every hidden test; the unfilled Sonic scaffold must fail some hidden
tests (so the tests discriminate). Output: TASKS/_validation.json
"""

import json
import sys
import tempfile
from pathlib import Path

from common import HIDDEN, TASK_IDS, TASKS, load_score, run_hidden_tests, sonic, write_json


def main():
    s = sonic()
    results, ok = {}, True
    for task in TASK_IDS:
        score = load_score(task)
        sources = s["compiler"].compile_score(score)
        reference = HIDDEN / task / "reference"
        conformance = s["conformance"].compare_score(score, reference)
        ref_tests = run_hidden_tests(task, reference)
        with tempfile.TemporaryDirectory() as tmp:
            for rel, src in sources.items():
                (Path(tmp) / rel).write_text(src, encoding="utf-8")
            scaffold_tests = run_hidden_tests(task, Path(tmp))
        ref_pass = sum(t["status"] == "passed" for t in ref_tests["tests"].values())
        scaffold_pass = sum(t["status"] == "passed" for t in scaffold_tests["tests"].values())
        entry = {
            "modules": list(sources),
            "score_elements": len(s["audio"].flatten_events(score)),
            "holes": sum(1 for e in s["audio"].flatten_events(score) if e["kind"] == "hole"),
            "hidden_tests": len(ref_tests["tests"]),
            "reference_conformant": conformance["compliant"],
            "reference_conformance_issues": conformance["issues"],
            "reference_tests_passed": ref_pass,
            "unfilled_scaffold_tests_passed": scaffold_pass,
        }
        entry["valid"] = (conformance["compliant"] and ref_pass == len(ref_tests["tests"]) > 0
                          and scaffold_pass < len(ref_tests["tests"]))
        if not entry["valid"]:
            ok = False
            entry["reference_output"] = ref_tests["output"]
        results[task] = entry
        print(task, json.dumps({k: v for k, v in entry.items() if k not in ("reference_conformance_issues", "reference_output")}))
    write_json(TASKS / "_validation.json", results)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
