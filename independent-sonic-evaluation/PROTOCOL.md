# Experimental protocol and frozen conditions

## Hypotheses (evaluated separately)

| ID | Hypothesis | How it is tested |
|---|---|---|
| H1 (primary) | A deterministic structural score plus a generated template lets a coding agent implement Python programs more accurately than ordinary instructions. | Condition C versus A, and B versus A, on hidden behavioral tests |
| H2 (secondary) | The score reduces the context and specification overhead of a task. | Measured input-token usage, context growth, material size, calls and time |
| H3 (exploratory) | Musical notation adds benefit beyond an equivalent nonmusical structured spec. | C versus B (identical information), plus the music-layer probes |

## Benchmark (`TASKS/`, `TESTS/`)

There are 10 previously unseen tasks, all authored for this evaluation and all expressible in
`sonic-template-v1`. None is derived from the supplied ten-case demo.

| Task | Modules | Topics covered |
|---|---|---|
| T01_pricing | 1 | input validation, conditional business logic, boundary at 5000 |
| T02_inventory | 1 (3 functions) | validation helper and dependencies, state update in place, invalid input leaves state unchanged |
| T03_rbac | 2 | authentication and authorization decisions, ownership, audit log, cross-module import |
| T04_stats | 1 | iteration, type validation, empty-input handling |
| T05_password | 1 (2 functions) | validation rules in a fixed order, delegation |
| T06_ratelimit | 1 | sliding-window state, boundary conditions, authorization-like allow/deny |
| T07_orders | 4 | cooperating modules, required call order, authorization before validation |
| T08_tokens | 1 | HMAC token authentication, compare_digest, expiry, check order |
| T09_grades | 1 (3 functions) | bands, loops, propagation, counting |
| T10_ledger | 1 | iterative state, rejection versus exception semantics, no overdraft |

Each task directory contains the following:
- `score.json`: the exact Sonic score. It holds the requirement bullets `R1…Rn`, and requirements
  tagged `(security/…)` count as high severity.
- `interface.md`: the English description of the modules and signatures, used in condition A.
- `conditions/{A,B,C}/`: the frozen materials (`materials.md`, inlined into the prompt) and the
  `workspace/` that is copied into each attempt.

Each task has 9 to 15 hidden behavioral tests, 116 in total, in `TESTS/<task>/test_hidden.py`. Test
names encode requirement IDs, and the `test_sec_` prefix marks validation and authorization tests
(63 of the 116). `TESTS/<task>/reference/` holds my reference solution. Before any attempt ran, it
had to pass every hidden test and conform to the score under the original checker
(`TASKS/_validation.json`).

The **implementation budget** was at most 25 tool calls per attempt, one attempt each, with no
external retries.

### Freeze

The tasks, condition materials, harness, run schedule and hidden-test hashes were recorded in
`FREEZE.json`. That file was committed to git (commit `6ea9f08`) **before the first benchmark
attempt ran**. Until all 60 attempts had been collected, the hidden tests and references were kept
outside the repository, and agents were told not to read outside their workspace. After collection
all 28 hidden-test and reference files were copied into `TESTS/`. They are byte-identical to the
frozen hashes, and no task file changed after the freeze. Nothing in a test was changed at any
point.

Post-freeze harness changes were limited to measurement and analysis; none touches tasks, prompts
or grading:
- `transcript_metrics.py` was changed to skip the agent's prose report in the isolation scan and to
  record the served-model digest.
- `audit.py`, `challenge.py`, `music_probe.py` and `aggregate.py` were added.

## Conditions

All three conditions receive the **same requirement bullets, verbatim**. They are generated from
`score.json["requirements"]`.

| | A: natural language | B: conventional structured | C: Sonic Code Studio |
|---|---|---|---|
| Specification | `interface.md` (modules and signatures in English) plus the requirement bullets | `spec.json`: the score with `format: structured-spec-v1` and element kind `todo` in place of `hole`; otherwise identical | `score.json` exactly as validated by Sonic |
| Scaffold | none (empty `repo/`) | the compiler's Python output, with the docstring "Scaffold. Verify…" and markers `TODO:` in place of `__SONIC_HOLE__:` | `repo/` from the original `write_project()` |
| Handoff | none | `HANDOFF.md`: the same instructions as Sonic's handoff minus the audio sentence, with "score" renamed to "spec" | `AGENT_HANDOFF.md` from the original `compiler.handoff()` |
| Extra files | none | none | `template.wav` and `events.json`, as produced by the build |
| Inline material (10 tasks) | 12,605 chars | 68,401 chars | 70,785 chars |

B is generated mechanically from the same score (`harness/build_conditions.py`), so **B and C carry
identical structural information**. They differ in four ways only:
- Sonic's wording ("audible template", "score", `__SONIC_HOLE__`);
- 238 extra characters per prompt on average;
- the `format` field value and the hole/todo kind label;
- the presence of the WAV and event metadata.

That is the critical control: the audit established that Sonic's "score" is itself a nonmusical
JSON spec, so the only musical artifact is the audio file.

Neither B nor C was given the Sonic checker or any structural-check tool during implementation. All
three conditions got the same instruction to write and run their own behavioral checks.

### Common wrapper (identical across conditions)

`harness/prepare_runs.py` → `WRAPPER`. It sets the workspace-only rule and says that deliverables
go in `repo/` and self-checks in `scratch/`. It names the same Python interpreter, sets the
25-tool-call budget with no second attempt, and sets the same final-report request. Every agent was
launched with the identical one-line launcher, "Your complete instructions are in the file
…/TASK_PROMPT.md. Read that file first and follow it exactly." The full prompt is preserved in
`RUNS/<task>/<cond>-<k>/prompt.txt`.

## Execution

- 10 tasks × 3 conditions × 2 attempts gave **60 attempts, all executed**. The schedule was shuffled
  with seed 20261011 and given opaque run IDs (`RUNS/schedule.json`). It ran in 4 batches of 15
  concurrent agents, in schedule order.
- **Pilot:** 3 attempts (A, B, C) ran on the creator's own demo example (`PILOT/`), not on the
  benchmark. They verified the harness: collection, transcript metrics, grading, and the isolation
  audit. Two harness fixes followed the pilot, both before the freeze:
  - The transcript's logged `output_tokens` were found to be mid-stream snapshots, so they are now
    reported only as a lower bound, and an exact `generated_chars` measure was added.
  - The prompts were moved into a per-workspace file.
- Each attempt ran as a fresh sub-agent with an empty context and a clean copy of its condition's
  workspace. The agent type, tool set and limits were the same throughout. No result from one
  attempt was shown to another.
- **Model:** every sub-agent inherited the session's configured model, and the configured-model
  digest is identical in all 63 transcripts. The *served* model reported by the API matched one
  digest in 57 of 60 attempts. In 3 attempts it reported a different model string: run-22
  (T10 B-2), run-26 (T09 A-2) and run-39 (T01 A-2). This is a deviation from the "same model"
  control and is reported, not hidden. `RESULTS.json` includes a sensitivity analysis that excludes
  those 3 attempts. Model identifiers are stored only as SHA-256 prefixes because repository policy
  forbids writing model names into artifacts.
- No model settings (temperature and so on) were controllable through the sub-agent interface.
- **Isolation audit:** every tool call in every transcript was scanned for paths outside the
  attempt's workspace and for markers of the evaluation files. Result: 0 violations in 60 attempts.
  One early false positive came from the word "hidden" in an agent's prose report; the final-report
  tool was then excluded from the scan.

## Metrics (per attempt, `RESULTS.csv`)

| Metric | Definition |
|---|---|
| Functional correctness | Fraction of hidden tests passed. The denominator is fixed, so a collection failure counts as 0/N. |
| Full success | All hidden tests pass |
| Security correctness | Fraction of `test_sec_*` tests passed |
| Requirement omissions | A requirement fails if any of its tests fails, counted by severity (high = `security/…`) |
| Invalid code | Syntax errors, import or collection failures, and failing tests whose message shows a runtime error (`NameError`, `NotImplementedError`, …) |
| Structural compliance | (1) the ORIGINAL Sonic checker against the task score; (2) an independent interface check that all declared modules, functions and exact parameter lists exist and no extra files are present. Sonic conformance is only meaningful for B and C, because A never saw the plan. |
| Context cost | `input_tokens_sum` is the API-reported input tokens summed over all model calls, including the fixed agent-harness overhead of about 50.6k tokens per call. `context_growth_tokens` is last-call input minus first-call input, i.e. the task-specific context the agent accumulated. Also recorded: `prompt_chars` and the size of the fixed material. |
| Output | `generated_chars` is the exact size of the agent's text and tool inputs. `output_tokens_logged_lower_bound` is a lower bound only. |
| Completion efficiency | Wall-clock duration from the Agent completion record, the number of model calls from the transcript, and `subagent_tokens` from the completion record |
| Repair effort | Tool calls, shell runs (self-checks), and edit or write calls |

Analysis is done per task × condition first (mean of 2 attempts). Paired per-task differences
(B−A, C−A, C−B) are summarised by their mean, a seeded bootstrap 95% CI over the 10 tasks, and an
exact two-sided sign test. There is no multiple-comparison correction. With 10 tasks the minimum
attainable sign-test p is 0.002.

## Security and structure challenge (`CHALLENGE/`), music probe (`MUSIC/`)

These are separate from the coding attempts. See `FINAL_REPORT.md` §5 and §6.
- The challenge applies 14 mutations to conformant reference code. Each is run through the original
  checker and the hidden tests, and both audio outputs are compared.
- The probe renders score variants with the original renderer and blind-decodes every benchmark
  `template.wav`.

## Untested or excluded

- No audio-capable model condition was run. The agents were text-only, so the WAV could not be
  "heard", and it was not treated as heard.
- No human study was run.
- No condition gave agents the Sonic checker as a feedback loop.
