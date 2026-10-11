# Reproducing this evaluation

All commands run from `independent-sonic-evaluation/harness/`. They use these paths:

```bash
export ZIP=/path/to/sonic-code-studio.zip            # SHA-256 ac93b7cc…ce01ad49
export WORK=/path/to/scratch                         # anywhere outside the repository
export SONIC_REF=$WORK/ref/sonic-code-studio         # frozen original prototype
export SONIC_HIDDEN=$(pwd)/../TESTS                  # hidden tests (published after collection)
export EVAL_PYTHON=$WORK/venv/bin/python
```

## 1. Freeze the prototype and build the environment

```bash
sha256sum "$ZIP"
mkdir -p $WORK/ref && (cd $WORK/ref && python3 -I -m zipfile -e "$ZIP" .) && chmod -R a-w $WORK/ref
python3 -m venv $WORK/venv
$EVAL_PYTHON -m pip install "cryptography>=42,<51" "pytest>=8,<10" "ruff>=0.6,<1"
```

## 2. Audit: original tests, CLI, hashes and pitch encoding

This writes `AUDIT_DATA/`. The extracted tree is not modified, because tests run on a disposable
copy.

```bash
$EVAL_PYTHON audit.py "$ZIP" $SONIC_REF $EVAL_PYTHON
```

## 3. Validate the benchmark and rebuild the condition materials

```bash
$EVAL_PYTHON validate_tasks.py          # scores valid; references conform and pass 116/116
$EVAL_PYTHON build_conditions.py        # regenerates TASKS/*/conditions/ (deterministic)
git diff --stat ../TASKS                # expect no changes against the committed, frozen materials
```

The frozen hashes are in `FREEZE.json`. To verify them:

```bash
python3 - <<'PY'
import hashlib, json, pathlib
e = pathlib.Path('..'); f = json.load(open(e / 'FREEZE.json'))
bad = [r for r, h in f['tasks'].items() if hashlib.sha256((e / r).read_bytes()).hexdigest() != h]
bad += [r for r, h in f['hidden_tests_and_references'].items()
        if not r.startswith('P00') and hashlib.sha256((e / 'TESTS' / r).read_bytes()).hexdigest() != h]
print('mismatches:', bad)
PY
```

## 4. Re-grade the recorded attempts

No model calls are needed for this step.

```bash
$EVAL_PYTHON grade.py                   # rewrites RUNS/*/*/grade.json from RUNS/*/*/repo
$EVAL_PYTHON aggregate.py               # rewrites RESULTS.csv and RESULTS.json
```

The token, timing and model-call fields come from the original transcripts and the agent
completion records, which are already saved in each run's `transcript_metrics.json` and
`usage.json`. Re-grading leaves them untouched.

## 5. Challenge and music probes (deterministic)

```bash
$EVAL_PYTHON challenge.py               # writes CHALLENGE/
$EVAL_PYTHON music_probe.py             # writes MUSIC/
```

## 6. Re-running the coding attempts (new data; it will not reproduce identical outputs)

```bash
$EVAL_PYTHON prepare_runs.py $WORK/ws $EVAL_PYTHON   # needs an empty RUNS/ (move the old one aside)
```

1. Launch each attempt as a fresh sub-agent with an empty context. Give it exactly the launcher
   text: `Your complete instructions are in the file <ws>/TASK_PROMPT.md. Read that file first and
   follow it exactly.` This evaluation used Claude Code `general-purpose` sub-agents, 15 at a time,
   in `RUNS/schedule.json` order.
2. When an attempt finishes, record its `subagent_tokens`, `tool_uses` and `duration_ms` from the
   completion record, then run:

   ```bash
   $EVAL_PYTHON finalize_run.py <run_id> <transcript.jsonl> <subagent_tokens> <tool_uses> <duration_ms>
   ```

   This collects the workspace, extracts the final report and the sanitized transcript, computes the
   usage metrics and the isolation audit, and grades the attempt.
3. Run `aggregate.py`.

Never replace a failed attempt; `collect_run.py` refuses to overwrite one.

## Pilot

To run the pilot instead, set `EVAL_TASKS_DIR=../PILOT` and `EVAL_RUNS_DIR=../PILOT/RUNS`, and set
`SONIC_HIDDEN` to `../PILOT/TESTS`.
