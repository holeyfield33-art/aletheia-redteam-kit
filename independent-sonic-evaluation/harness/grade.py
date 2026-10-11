"""Grade one or all attempts in RUNS/ against the frozen hidden tests.

Per attempt (RUNS/<task>/<label>/repo):
  - hidden behavioral tests (fresh process, temp copy)
  - invalid code: syntax errors, import/collection failures, runtime-error failures
  - requirement omissions: a requirement fails if any of its tests fails
  - security correctness: pass rate of test_sec_* tests
  - Sonic structural conformance (original checker, non-executing)
  - independent interface compliance (declared modules/functions/parameters present, no extra files)
Writes grade.json next to repo/.
"""

import ast
import json
import re
import sys
from pathlib import Path

from common import RUNS, TASKS, load_score, run_hidden_tests, sonic, write_json

RUNTIME_MARKERS = ("NotImplementedError", "NameError", "AttributeError", "ImportError", "ModuleNotFoundError",
                   "UnboundLocalError", "RecursionError")


def requirement_severity(score):
    result = {}
    for text in score["requirements"]:
        match = re.match(r"(R\d+)", text)
        if match:
            result[match.group(1)] = "high" if "(security/" in text else "medium"
    return result


def interface_check(score, repo):
    problems = []
    declared = {m["path"] for m in score["modules"]}
    present = {str(p.relative_to(repo)) for p in repo.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    for extra in sorted(present - declared):
        problems.append(f"unexpected file {extra}")
    for module in score["modules"]:
        path = repo / module["path"]
        if not path.exists():
            problems.append(f"missing module {module['path']}")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeError, ValueError) as exc:
            problems.append(f"syntax error in {module['path']}: {exc}")
            continue
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        for function in module["functions"]:
            node = functions.get(function["name"])
            if node is None:
                problems.append(f"missing function {module['path']}:{function['name']}")
                continue
            wanted = [p["name"] for p in function["parameters"]]
            actual = [a.arg for a in node.args.args]
            if actual != wanted or node.args.vararg or node.args.kwarg or node.args.kwonlyargs:
                problems.append(f"parameters differ {function['name']}: {actual} != {wanted}")
    return problems


def syntax_errors(repo):
    errors = []
    for path in sorted(repo.rglob("*.py")):
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except (SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"{path.name}: {exc}")
    return errors


def grade(task, run_dir):
    s = sonic()
    score = load_score(task)
    repo = Path(run_dir) / "repo"
    severity = requirement_severity(score)
    tests = run_hidden_tests(task, repo)
    results = tests["tests"]
    # Denominator is the frozen hidden-test count, so a collection failure scores 0/N, not 0/0.
    total = json.loads((TASKS / "_validation.json").read_text())[task]["hidden_tests"]
    passed = sum(1 for n, r in results.items() if n.startswith("test_") and r["status"] == "passed")
    failed_tests = {n: r for n, r in results.items() if r["status"] != "passed"}
    req_status = {}
    for name, result in results.items():
        for req in set(re.findall(r"R\d+", name)):
            req_status.setdefault(req, True)
            if result["status"] != "passed":
                req_status[req] = False
    omitted = sorted(r for r, ok in req_status.items() if not ok)
    sec = {n: r for n, r in results.items() if n.startswith("test_sec_")}
    runtime_errors = sorted(n for n, r in failed_tests.items() if any(m in r["detail"] for m in RUNTIME_MARKERS))
    try:
        report = s["conformance"].compare_score(score, repo)
        conformance = {"compliant": report["compliant"], "issue_kinds": sorted({i["kind"] for i in report["issues"]}),
                       "issues": len(report["issues"]), "unresolved_holes": len(report["unresolved_holes"])}
    except Exception as exc:  # the checker itself failing is recorded, not hidden
        conformance = {"compliant": False, "error": f"{type(exc).__name__}: {exc}"}
    interface = interface_check(score, repo)
    data = {
        "task": task,
        "tests_total": total,
        "tests_passed": passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "full_success": total > 0 and passed == total,
        "failed_tests": failed_tests,
        "requirements_failed": omitted,
        "requirements_failed_high": [r for r in omitted if severity.get(r) == "high"],
        "requirements_failed_medium": [r for r in omitted if severity.get(r) != "high"],
        "security_tests_total": len(sec),
        "security_tests_passed": sum(1 for r in sec.values() if r["status"] == "passed"),
        "syntax_errors": syntax_errors(repo),
        "collection_error": tests["collection_error"] or not any(n.startswith("test_") for n in results),
        "timeout": tests["timeout"],
        "runtime_error_tests": runtime_errors,
        "sonic_conformance": conformance,
        "interface_problems": interface,
        "interface_compliant": not interface,
        "pytest_tail": tests["output"][-3000:],
    }
    write_json(Path(run_dir) / "grade.json", data)
    return data


def main(argv):
    targets = []
    if argv:
        targets = [Path(a) for a in argv]
    else:
        targets = sorted(p for p in RUNS.glob("T*/*") if (p / "repo").is_dir())
    for run_dir in targets:
        task = run_dir.parent.name
        data = grade(task, run_dir)
        print(f"{task}/{run_dir.name}: {data['tests_passed']}/{data['tests_total']} "
              f"sonic={data['sonic_conformance'].get('compliant')} iface={data['interface_compliant']}")


if __name__ == "__main__":
    main(sys.argv[1:])
