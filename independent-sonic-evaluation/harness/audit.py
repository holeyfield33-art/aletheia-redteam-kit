"""Section 3: freeze and independently validate the supplied prototype.

usage: audit.py <archive.zip> <read-only extracted sonic-code-studio dir> <python-with-deps>
Writes AUDIT_DATA/: source hashes, manifest verification, environment,
original test-suite output, CLI exercise logs and the pitch-encoding check.
The extracted tree is never modified; tests run on a disposable copy.
"""

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from common import EVAL, write_json

OUT = EVAL / "AUDIT_DATA"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(cmd, cwd, env=None):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return {"cmd": " ".join(str(c) for c in cmd), "returncode": proc.returncode,
            "stdout": proc.stdout[-20000:], "stderr": proc.stderr[-20000:]}


def main(archive, ref, python):
    ref, OUT_ = Path(ref), OUT
    OUT_.mkdir(exist_ok=True)
    files = sorted(p for p in ref.rglob("*") if p.is_file())
    hashes = {str(p.relative_to(ref)): sha(p) for p in files}
    source = {k: v for k, v in hashes.items() if k.endswith((".py", ".cjs", ".html", ".md", ".toml", ".ps1", ".in"))
              and "/cases/" not in k}
    manifest = json.loads((ref / "BUNDLE_MANIFEST.json").read_text())
    listed = {f["path"]: f["sha256"] for f in manifest["files"]}
    mismatched = sorted(p for p, h in listed.items() if p in hashes and hashes[p] != h)
    missing = sorted(p for p in listed if p not in hashes)
    unlisted = sorted(p for p in hashes if p not in listed and p != "BUNDLE_MANIFEST.json")
    write_json(OUT_ / "source_hashes.json", {"archive_sha256": sha(archive), "files_in_archive": len(files),
                                              "source_and_doc_files": source})
    write_json(OUT_ / "manifest_check.json", {"manifest_entries": len(listed), "hash_mismatches": mismatched,
                                               "listed_but_missing": missing, "present_but_unlisted": unlisted})
    reported = ["demos/templates/composer.html", "demos/templates/index.html", "sonic_templates", "README.md",
                "TEMPLATES.md", "SONAR.md", "demos/templates/scaffold/AGENT_HANDOFF.md"]
    presence = {r: (ref / r).exists() for r in reported}
    freeze = run([python, "-m", "pip", "freeze"], cwd=ref)
    node = shutil.which("node")
    env_info = {"python": run([python, "--version"], cwd=ref)["stdout"].strip(), "platform": platform.platform(),
                "pip_freeze": freeze["stdout"].split(), "node": run([node, "--version"], cwd=ref)["stdout"].strip() if node else None,
                "declared_runtime_dependency": "cryptography>=42,<51", "declared_dev": "pytest>=8,<10, ruff>=0.6,<1"}
    write_json(OUT_ / "environment.json", {**env_info, "reported_files_present": presence})

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "sonic-code-studio"
        shutil.copytree(ref, work)
        for p in work.rglob("*"):
            p.chmod(p.stat().st_mode | 0o200)
        tests = run([python, "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider", "--basetemp", str(Path(tmp) / "bt")], cwd=work)
        ruff = run([python, "-m", "ruff", "check", "s2", "sonic_templates", "tests", "--select", "E4,E7,E9,F,I",
                    "--no-cache"], cwd=work)
        (OUT_ / "original_pytest.txt").write_text(tests["cmd"] + "\n\n" + tests["stdout"] + tests["stderr"], encoding="utf-8")
        (OUT_ / "original_ruff.txt").write_text(ruff["cmd"] + "\n\n" + ruff["stdout"] + ruff["stderr"], encoding="utf-8")
        summary_line = [l for l in tests["stdout"].splitlines() if " passed" in l or " failed" in l][-1:]
        counts = {"passed": tests["stdout"].count("\nPASSED "), "failed": tests["stdout"].count("\nFAILED "),
                  "skipped": tests["stdout"].count("\nSKIPPED "), "error": tests["stdout"].count("\nERROR ")}

        # CLI exercise: help, demo, build a benchmark score, check scaffold (expect 1) and reference (expect 0).
        cli = []
        cli.append(run([python, "-m", "sonic_templates", "--help"], cwd=work))
        cli.append(run([python, "-m", "sonic_templates", "demo", "--out", str(Path(tmp) / "demo")], cwd=work))
        score = EVAL / "TASKS" / "T03_rbac" / "score.json"
        cli.append(run([python, "-m", "sonic_templates", "build", str(score), "--out", str(Path(tmp) / "build")], cwd=work))
        cli.append(run([python, "-m", "sonic_templates", "check", str(Path(tmp) / "build" / "score.json"),
                        str(Path(tmp) / "build" / "repo"), "--out", str(Path(tmp) / "check1")], cwd=work))
        cli.append(run([python, "-m", "sonic_templates", "build", str(score), "--out", str(Path(tmp) / "build")], cwd=work))
        bad = Path(tmp) / "bad.json"
        bad.write_text(json.dumps({"format": "sonic-template-v1", "modules": [{"path": "../x.py", "functions": []}]}))
        cli.append(run([python, "-m", "sonic_templates", "build", str(bad), "--out", str(Path(tmp) / "bad")], cwd=work))
        expected = [0, 0, 0, 1, 2, 2]
        demo_results = json.loads((Path(tmp) / "demo" / "results.json").read_text()) if (Path(tmp) / "demo" / "results.json").exists() else None
        build = Path(tmp) / "build"
        score_json = json.loads((build / "score.json").read_text())
        events = json.loads((build / "events.json").read_text())

        def has_pitch(value):
            if isinstance(value, dict):
                return any(k in ("note", "pitch", "midi", "frequency") or has_pitch(v) for k, v in value.items())
            if isinstance(value, list):
                return any(has_pitch(v) for v in value)
            return False
        pitch_check = {
            "exported_score_contains_pitch_fields": has_pitch(score_json),
            "composer_export_code": "download handler serialises JSON.stringify(score) (demos/templates/composer.html line 59); "
                                    "pitches come from a fixed kind->MIDI table (line 31)",
            "events_json_contains_notes": all("note" in e for e in events),
            "distinct_notes_in_events": sorted({e["note"] for e in events}),
            "note_is_function_of_kind_only": all(e["note"] == {"function": 60, "validate": 62, "branch": 64, "loop": 65,
                                                               "call": 67, "raise": 69, "return": 71, "hole": 72,
                                                               "assign": 74}[e["kind"]] for e in events),
        }
    write_json(OUT_ / "cli_exercise.json", {"runs": [{**c, "expected_returncode": e, "ok": c["returncode"] == e}
                                                      for c, e in zip(cli, expected)],
                                             "demo_results": demo_results})
    write_json(OUT_ / "pitch_encoding.json", pitch_check)
    write_json(OUT_ / "original_tests_summary.json", {"counts_from_-rA": counts, "summary_line": summary_line,
                                                       "ruff_returncode": ruff["returncode"],
                                                       "creator_reported": "88 passed, 2 skipped (Windows)"})
    print(json.dumps({"tests": counts, "summary": summary_line, "manifest_mismatches": len(mismatched),
                      "missing": missing, "unlisted": unlisted[:10], "presence": presence,
                      "cli_ok": [c["returncode"] == e for c, e in zip(cli, expected)], "pitch": pitch_check}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
