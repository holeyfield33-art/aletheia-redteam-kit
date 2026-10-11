"""Shared paths and helpers for the independent Sonic Code Studio evaluation.

The original prototype is imported read-only from the frozen extraction
directory (SONIC_REF). Nothing in this harness modifies it.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1]
TASKS = Path(os.environ.get("EVAL_TASKS_DIR", str(EVAL / "TASKS")))
TESTS = EVAL / "TESTS"
RUNS = Path(os.environ.get("EVAL_RUNS_DIR", str(EVAL / "RUNS")))

# Frozen, read-only extraction of the supplied archive.
SONIC_REF = Path(os.environ.get("SONIC_REF", ""))
# Hidden tests stay outside the repository until every attempt has been collected.
HIDDEN = Path(os.environ.get("SONIC_HIDDEN", str(TESTS)))
PYTHON = os.environ.get("EVAL_PYTHON", sys.executable)

TASK_IDS = sorted(p.name for p in TASKS.iterdir() if p.is_dir() and p.name[0] in "TP" and p.name[1:3].isdigit())


def sonic():
    """Import the original sonic_templates package from the frozen reference copy."""
    if not SONIC_REF.is_dir():
        raise SystemExit("Set SONIC_REF to the read-only extracted sonic-code-studio directory")
    sys.dont_write_bytecode = True  # keep the reference tree byte-identical
    if str(SONIC_REF) not in sys.path:
        sys.path.insert(0, str(SONIC_REF))
    import sonic_templates.audio as audio
    import sonic_templates.compiler as compiler
    import sonic_templates.conformance as conformance
    import sonic_templates.schema as schema
    return {"schema": schema, "compiler": compiler, "conformance": conformance, "audio": audio}


def load_score(task):
    return sonic()["schema"].load_score(TASKS / task / "score.json")


def run_hidden_tests(task, repo_dir, timeout=120):
    """Run the frozen hidden tests against repo_dir in a fresh process and temp copy."""
    test_file = HIDDEN / task / "test_hidden.py"
    with tempfile.TemporaryDirectory(prefix="grade-") as tmp:
        tmp = Path(tmp)
        code = tmp / "code"
        shutil.copytree(repo_dir, code, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy(test_file, tmp / "test_hidden.py")
        junit = tmp / "junit.xml"
        env = dict(os.environ, PYTHONPATH=str(code), PYTHONDONTWRITEBYTECODE="1")
        try:
            proc = subprocess.run([PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tmp),
                                   f"--junitxml={junit}", str(tmp / "test_hidden.py")],
                                  cwd=tmp, env=env, capture_output=True, text=True, timeout=timeout)
            output, returncode = proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            return {"timeout": True, "output": str(exc), "tests": {}, "returncode": None, "collection_error": False}
        tests = {}
        collection_error = False
        if junit.exists():
            root = ET.parse(junit).getroot()
            for case in root.iter("testcase"):
                name = case.get("name")
                status, detail = "passed", ""
                for child in case:
                    if child.tag in ("failure", "error"):
                        status = "failed" if child.tag == "failure" else "error"
                        detail = (child.get("message") or "")[:500]
                    elif child.tag == "skipped":
                        status = "skipped"
                if case.get("classname", "") == "" and status == "error":
                    collection_error = True
                tests[name] = {"status": status, "detail": detail}
        if not tests or any(t == "test_hidden" for t in tests):
            collection_error = collection_error or returncode not in (0, 1)
        return {"timeout": False, "returncode": returncode, "output": output[-6000:], "tests": tests,
                "collection_error": collection_error}


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
