"""Section 8: security and structure challenge.

Each mutation edits a structurally conformant reference implementation. For
every mutant we record:
  - whether the ORIGINAL Sonic checker (compare_score) flags it, and which issue kinds
  - hidden-test outcome (did behavior actually change?)
  - SHA-256 of the checker's deviations.wav (written by the original write_report)
  - SHA-256 of template.wav rendered from the score (the plan audio; code edits cannot reach it)
Output: CHALLENGE/challenge_results.json and per-mutant reports under CHALLENGE/reports/.
"""

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from common import EVAL, HIDDEN, load_score, run_hidden_tests, sonic, write_json

OUT = EVAL / "CHALLENGE"

# (id, task, file, old, new, description, location)
MUTATIONS = [
    ("control_comment", "T02_inventory", "inventory.py", "def reserve(", "# reviewed\ndef reserve(",
     "Cosmetic: add a comment", "control"),
    ("boundary_le_to_lt_fixed", "T02_inventory", "inventory.py", "if qty <= 0:", "if qty < 0:",
     "Replace qty <= 0 with qty < 0 in planned validation", "planned structure"),
    ("boundary_in_hole", "T06_ratelimit", "limiter.py", "if t > now - window", "if t >= now - window",
     "Replace > with >= in the window boundary, inside a hole", "hole"),
    ("remove_authorization", "T03_rbac", "access.py",
     "    if not is_allowed(user, action, owner):\n        raise PermissionError('denied')\n", "",
     "Remove the authorization check before the protected operation", "planned structure"),
    ("authorization_bypass_in_hole", "T03_rbac", "access.py",
     "granted = action in permissions_for(user.get('role', '')) or (user.get('name') == owner and action in ('read', 'write'))",
     "granted = True", "Grant every active user every action, inside a hole", "hole"),
    ("validation_gutted_in_hole", "T07_orders", "validation.py",
     "ok = isinstance(item, dict) and isinstance(item.get('sku'), str) and item.get('sku') != '' and isinstance(item.get('qty'), int) and not isinstance(item.get('qty'), bool) and item.get('qty') > 0",
     "ok = isinstance(item, dict)", "Weaken item validation to a dict check, inside a hole", "hole"),
    ("wrong_call_order", "T07_orders", "orders.py",
     "    validate_items(items)\n    sub = subtotal(items, catalog)\n",
     "    sub = subtotal(items, catalog)\n    validate_items(items)\n",
     "Price items before validating them", "planned structure"),
    ("swap_branches", "T06_ratelimit", "limiter.py",
     "        recent.append(now)\n        state[client] = recent\n        return True\n    else:\n        state[client] = recent\n        return False",
     "        state[client] = recent\n        return False\n    else:\n        recent.append(now)\n        state[client] = recent\n        return True",
     "Swap the allow/deny branch bodies", "planned structure"),
    ("return_before_validation", "T01_pricing", "pricing.py",
     "    if not isinstance(subtotal_cents, int)", "    return subtotal_cents\n    if not isinstance(subtotal_cents, int)",
     "Return before any validation", "planned structure"),
    ("unexpected_import", "T08_tokens", "tokens.py", "import hmac\n", "import hmac\nimport os\n",
     "Introduce an unexpected dependency (import os)", "planned structure"),
    ("unlisted_call_in_hole", "T09_grades", "grades.py", "result[name] = letter_for(scores[name])",
     "result[name] = letter_for(int(scores[name]))", "Call an unlisted function (int) inside a hole", "hole"),
    ("overdraft_in_hole", "T10_ledger", "ledger.py", "elif amount <= current:", "elif True:",
     "Allow overdrafts, inside a hole", "hole"),
    ("signature_check_swapped_args", "T08_tokens", "tokens.py",
     "expected = expected_token.split('.')[2]", "expected = provided",
     "Compare the provided signature with itself (auth bypass); would need expected_token.split only", "hole"),
    ("multiply_in_hole", "T07_orders", "tax.py", "(cents * rates[region] + 50) // 100", "(cents * rates[region] + 49) // 100",
     "Change tax rounding constant inside a hole", "hole"),
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    s = sonic()
    from sonic_templates.report import write_report

    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "reports").mkdir(parents=True)
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        baseline_by_task = {}
        for mid, task, filename, old, new, description, location in MUTATIONS:
            score = load_score(task)
            if task not in baseline_by_task:
                ref = HIDDEN / task / "reference"
                plan_wav = tmp / f"{task}-template.wav"
                s["audio"].render_score(score, plan_wav)
                clean_report = s["conformance"].compare_score(score, ref)
                write_report(clean_report, tmp / f"{task}-clean")
                baseline_by_task[task] = {"template_wav": sha(plan_wav),
                                          "deviations_wav": sha(tmp / f"{task}-clean" / "deviations.wav"),
                                          "tests": run_hidden_tests(task, ref)}
            repo = tmp / mid / "repo"
            shutil.copytree(HIDDEN / task / "reference", repo)
            source = (repo / filename).read_text(encoding="utf-8")
            if source.count(old) != 1:
                raise SystemExit(f"{mid}: anchor not found exactly once")
            (repo / filename).write_text(source.replace(old, new), encoding="utf-8")
            report = s["conformance"].compare_score(score, repo)
            write_report(report, OUT / "reports" / mid)
            plan_wav = tmp / f"{mid}-template.wav"
            s["audio"].render_score(score, plan_wav)
            tests = run_hidden_tests(task, repo)
            failed = sorted(n for n, r in tests["tests"].items() if r["status"] != "passed")
            base = baseline_by_task[task]
            results.append({
                "id": mid, "task": task, "file": filename, "description": description, "location": location,
                "checker_flags": not report["compliant"],
                "checker_issue_kinds": sorted({i["kind"] for i in report["issues"]}),
                "behavior_changed": bool(failed),
                "hidden_tests_failed": failed,
                "security_tests_failed": [n for n in failed if n.startswith("test_sec_")],
                "template_wav_sha256": sha(plan_wav),
                "template_wav_changed_vs_clean": sha(plan_wav) != base["template_wav"],
                "deviations_wav_sha256": sha(OUT / "reports" / mid / "deviations.wav"),
                "deviations_wav_differs_from_clean": sha(OUT / "reports" / mid / "deviations.wav") != base["deviations_wav"],
            })
    # Can the deviation audio distinguish different kinds of flagged change?
    flagged = [r for r in results if r["checker_flags"]]
    groups = {}
    for r in flagged:
        groups.setdefault(r["deviations_wav_sha256"], []).append(r["id"])
    summary = {
        "mutants": len(results),
        "behavior_changing_mutants": sum(r["behavior_changed"] for r in results),
        "flagged_by_checker": sum(r["checker_flags"] for r in results),
        "behavior_changing_but_not_flagged": [r["id"] for r in results if r["behavior_changed"] and not r["checker_flags"]],
        "flagged_planned_structure_changes": f'{sum(r["checker_flags"] for r in results if r["location"] == "planned structure")}'
                                             f'/{sum(r["location"] == "planned structure" for r in results)}',
        "flagged_hole_changes": f'{sum(r["checker_flags"] for r in results if r["location"] == "hole")}'
                                f'/{sum(r["location"] == "hole" for r in results)}',
        "template_wav_changed_by_any_code_mutation": any(r["template_wav_changed_vs_clean"] for r in results),
        "distinct_deviation_wavs_among_flagged": len(groups),
        "flagged_mutants_grouped_by_identical_deviation_wav": list(groups.values()),
    }
    write_json(OUT / "challenge_results.json", {"summary": summary, "mutants": results})
    print(json.dumps(summary, indent=2))
    for r in results:
        print(f'{r["id"]:32s} flags={r["checker_flags"]!s:5s} behavior_changed={r["behavior_changed"]!s:5s} '
              f'kinds={r["checker_issue_kinds"]} dev_wav={r["deviations_wav_sha256"][:10]}')


if __name__ == "__main__":
    main()
