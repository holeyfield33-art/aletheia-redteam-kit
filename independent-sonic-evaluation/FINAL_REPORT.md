# Sonic Code Studio: independent evaluation, final report

**Evaluator:** independent evaluation engineer (Claude Code session), 2026-10-11
**Subject:** Sonic Code Studio 0.1.0 by Astra (archive SHA-256 `ac93b7cc…ce01ad49`)
**Scope:** 60 of 60 planned coding attempts executed, a 14-mutation security and structure
challenge, and a 6-probe analysis of the music layer.

This report separates three kinds of statement. **Observed** results are measured directly.
**Calculated** comparisons are derived from those measurements. **Untested** statements are
hypotheses this evaluation did not test.

---

## 1. Summary

| Claim | Verdict | One-line basis |
|---|---|---|
| A: template reliability | **SUPPORTED** (structural scope only) | 10/10 independent scores validated, compiled and built into bundles (used by 20 C attempts). The checker flagged 6/6 planned-structure mutations and judged 20/20 filled C attempts conformant. |
| B: coding advantage | **NOT SUPPORTED** | 60/60 attempts passed every hidden test. Difference between conditions: 0.0 in all 10 tasks (C vs B, C vs A, B vs A). |
| C: context advantage | **NOT SUPPORTED** (the opposite was observed) | Against plain English, C used +2,941 context-growth tokens per attempt (+45%), +62k summed input tokens, +1.1 tool calls and +7.2 s. Against B, C used slightly more. |
| D: musical advantage | **NOT SUPPORTED** | No agent opened `template.wav` (0/20). The audio encodes only the element-kind sequence, and 5/5 meaning-changing score edits produced byte-identical WAVs. An audio-capable model was NOT TESTED. |
| E: product potential (agent-facing) | **NOT SUPPORTED** | The verified value is a structured plan plus a syntactic conformance checker. Neither depends on music, and neither improved agent correctness or cost here. |

The benchmark hit a **ceiling**: every condition was correct every time. With 10 small tasks and
one capable model, this experiment cannot detect correctness gains below that ceiling. These are
preliminary results, not proof of absence.

---

## 2. What the prototype actually is (observed; see AUDIT.md)

- It installs cleanly. The original test suite gave **90 passed, 0 failed, 0 skipped** on Linux.
  The creator reported 88 passed and 2 skipped on Windows; the 2 skipped are symlink tests that run
  on Linux.
- The exported "score" is a **nonmusical JSON programming specification**: modules, imports,
  signatures, and an AST-like body with exact Python expressions. The composer exports
  `JSON.stringify(score)`; no pitch is stored. Pitch is a fixed function of element kind (C4 =
  function … D5 = assign). The WAV is rendered from that kind sequence.
- The generated scaffold is close to finished code. Every guard, branch condition, raise and call
  is written out, and only the *holes* are left. On this benchmark the **unfilled** Sonic scaffolds
  already passed **45 of 116** hidden tests (39%) before any agent touched them
  (`TASKS/_validation.json`).

These facts shaped the design. Condition B is the same plan with neutral naming and no audio, so
**B versus C isolates everything Sonic adds beyond an ordinary structured spec**.

---

## 3. Coding experiment results

### 3.1 Correctness, observed per attempt (`RESULTS.csv`)

| | A: English | B: structured spec + TODO scaffold | C: Sonic score + Sonic scaffold |
|---|---|---|---|
| Attempts executed | 20 | 20 | 20 |
| Full success (all hidden tests) | **20/20** | **20/20** | **20/20** |
| Hidden tests passed | 232/232 | 232/232 | 232/232 |
| Security tests (`test_sec_*`) passed | 126/126 | 126/126 | 126/126 |
| Requirement omissions (any severity) | 0 | 0 | 0 |
| Syntax, import or runtime failures | 0 | 0 | 0 |
| Interface compliance (independent check) | 20/20 | 20/20 | 20/20 |
| Sonic structural conformance | 0/20 (A never saw the plan, so this is expected and not a defect) | 20/20 | 20/20 |
| Isolation violations | 0 | 0 | 0 |
| Opened `template.wav` | n/a | n/a | **0/20** |

Per task, every condition scored 1.0 on both attempts, so the variance across repeats is zero for
correctness. No retry was used; there was one attempt per slot. The 25-tool-call budget was never
approached: the maximum was 8.

### 3.2 Cost and effort, observed means (sd) over 20 attempts per condition

| Metric | A | B | C |
|---|---|---|---|
| Inline prompt size (chars) | 2,573 (288) | 8,152 (1,509) | 8,391 (1,534) |
| Task-specific context growth (tokens, last call − first call) | **6,569** (635) | 9,141 (1,340) | **9,511** (1,427) |
| Summed input tokens across calls (incl. ~50.6k fixed harness overhead per call) | 245,451 (53,126) | 289,191 (50,183) | 307,717 (64,123) |
| Model calls | 4.45 | 5.05 | 5.35 |
| Tool calls | 4.55 | 5.05 | 5.65 |
| Self-check shell runs | 1.15 | 1.20 | 1.20 |
| Agent-generated chars (text + tool inputs) | 3,779 | 3,892 | 4,148 |
| Wall-clock seconds | 31.5 (4.8) | 35.8 (10.1) | 38.7 (8.9) |
| Final context size reported by the agent tool (tokens) | 57,716 | 60,332 | 60,751 |

All token figures are API usage fields from the transcripts, as observed. The logged output-token
counts are mid-stream snapshots and are kept only as a lower bound (`RESULTS.csv`), so output size
is measured in characters instead.

### 3.3 Paired comparisons, calculated per task (n = 10 tasks, mean of 2 attempts each)

| Difference | Pass rate | Context growth (tokens) | Summed input tokens | Tool calls | Seconds |
|---|---|---|---|---|---|
| B − A | 0.0 [0, 0] | +2,571 [2,031, 3,151], p=0.002 | +43,740 [15,183, 75,109], p=0.021 | +0.5 [0.05, 0.95], p=0.07 | +4.3 [0.9, 8.2], p=0.34 |
| C − A | 0.0 [0, 0] | +2,941 [2,362, 3,587], p=0.002 | +62,266 [7,104, 114,378], p=0.021 | +1.1 [0.6, 1.65], p=0.008 | +7.2 [4.0, 10.9], p=0.021 |
| C − B | 0.0 [0, 0] | +370 [65, 645], p=0.34 | +18,526 [−20,208, 60,129], p=0.34 | +0.6 [0.05, 1.2], p=0.11 | +2.9 [0.8, 4.9], p=0.11 |

Brackets are seeded bootstrap 95% CIs over tasks. Each p is an exact two-sided sign test over the
10 tasks, with no multiple-comparison correction.

**Sensitivity analysis.** In 3 attempts the API reported a different served model (see §7). Without
them (57 attempts), the conclusions are unchanged: C−A context growth +3,047 (p=0.002); C−B +416
(p=0.11); every pass-rate difference is 0.0 (`RESULTS.json → sensitivity_majority_served_model_only`).

**Interpretation (calculated):**
- Giving the agent the full structured plan and scaffold, whether Sonic's (C) or a neutral
  equivalent (B), cost more context, more calls and more time than plain English requirements.
  Correctness did not change.
- The structured material is about 5.5 times larger than the English task: 68–71k characters
  against 12.6k over the 10 tasks. The agent reads all of it, and that shows up as more context.
- C against B differs by a small amount. It is consistent with C's slightly longer prompt (+238
  characters per task) and is not significant. No difference attributable to Sonic-specific content
  was found.

---

## 4. Claim A: template reliability (observed)

- **Grammar and compilation.** All 10 independently authored scores passed the original
  `validate_score`, compiled to Python, and produced 10/10 condition-C bundles (copied into 20 attempt workspaces). They span 9 to 26
  elements, 1 to 4 modules, and 1 to 3 holes each.
- **Conformance.** All 10 reference solutions and all 40 B and C attempts were judged conformant.
  Unfilled scaffolds were correctly flagged with `unresolved_hole`.
- **Rejecting invalid input.** A `../` module path and a build into an existing directory were both
  rejected with exit code 2.
- **Limits, observed during authoring.**
  - Holes may contain only listed calls, and call names are syntactic (`ch.isdigit`,
    `expected_token.split`). The score author therefore has to predict the implementer's variable
    names and, for chained calls, the intermediate assignments. Two scores (T05, T08) needed labels
    such as "first assign `mac = …`, then `mac.hexdigest()`".
  - `call_name` returns `None` for calls on call results or f-strings. As a result,
    `hmac.new(...).hexdigest()` can never be allowed inside a hole.
  - One agent (run-22) correctly noted that R3's "exactly 'deposit'" cannot be enforced within the
    plan. The score fixes the expression `kind not in (...)`, which uses `==`, and `type` is not an
    allowed call.

Structural conformance is not behavioral correctness, as the project itself documents. §5 shows
this concretely.

## 5. Security and structure challenge (observed; `CHALLENGE/challenge_results.json`)

There were 14 mutations of conformant reference code. Each was run through the original checker and
the hidden tests.

| Mutation | Where | Checker flags? | Behavior changed (hidden tests)? |
|---|---|---|---|
| Comment only (control) | — | no | no |
| `qty <= 0` → `qty < 0` | planned guard | **yes** | yes |
| Remove the authorization check before `audit.append` | planned | **yes** | yes |
| Validate after pricing (wrong call order) | planned | **yes** | yes |
| Swap the allow/deny branch bodies | planned | **yes** | yes |
| `return` before any validation | planned | **yes** | yes |
| `import os` (unexpected dependency) | planned imports | **yes** | no |
| Call an unlisted function (`int`) in a hole | hole | **yes** | yes |
| Window boundary `>` → `>=` | hole | **no** | **yes** (security test failed) |
| `granted = True` (authorization bypass) | hole | **no** | **yes** |
| Item validation weakened to `isinstance(item, dict)` | hole | **no** | **yes** |
| Withdrawals allowed past the balance (overdraft) | hole | **no** | **yes** |
| Token signature compared with itself (authentication bypass) | hole | **no** | **yes** |
| Tax rounding constant `+50` → `+49` | hole | no | not detected by hidden tests (a test-coverage gap, reported as is) |

**Findings:**
- **Checker:** it flagged **6/6 planned-structure mutations** but only **1/7 hole mutations**.
  **5 behavior-changing, security-relevant mutations passed as conformant.** Two of them, the
  authorization bypass and the signature self-comparison, are complete security failures that the
  checker reports as "Structure matches".
- **Deviation audio** (`deviations.wav`): all 7 flagged mutants produced **byte-identical**
  deviation audio, even though the issue kinds differ. The audio says *that* something deviated, not
  *what*. Conformant mutants were silent, the same as clean code.
- **Plan audio** (`template.wav`): it is rendered from the score, so no code change can reach it.
  It was identical for all 14 mutants.

Structural compliance is therefore not evidence of security. No security certification is implied
by this evaluation.

## 6. Claim D: the musical layer (observed; `MUSIC/music_probe.json`)

| Probe | Result |
|---|---|
| Change a guard condition in the score (`qty <= 0` → `qty < 0`) | identical WAV |
| Rename a function, neutralise its guard, change the exception type | identical WAV |
| `if x<0: raise` versus `if x<0: pass` followed by an unconditional `raise` (nesting) | identical WAV |
| Raise in the `body` versus in `otherwise` (inverted logic) | identical WAV |
| Authorization check replaced by `if False:` | identical WAV |
| Blind decoding of all 10 benchmark WAVs | the element-kind sequence was recovered exactly 10/10; nothing else is recoverable |

Answers to the questions this evaluation was asked:

1. *Does notation preserve executable meaning?* No. At most log2(27) ≈ 4.75 bits per element. For
   example, T07's 3,910-byte score maps to at most about 124 bits of audio.
2. *Can different structures sound the same?* Yes; 5 of 5 constructed pairs did.
3. *Does changing a condition change the sound?* No.
4. *Can the structure be reconstructed from audio alone?* Only the ordered list of element kinds,
   plus one of 3 harmonic classes per module. Names, expressions, nesting, branch sides and
   requirements cannot.
5. *Does audio help an AI model?* No text-only agent used it: 0 of 20 C agents opened the WAV, and
   no B agent had one. Results were indistinguishable with and without it. Whether it would help an
   audio-capable model is NOT TESTED. Given points 1 to 4, such a model could recover at most the
   kind sequence, which is already in the score. Audio is at most a human-facing interface; its
   value to humans was not tested.

## 7. Limitations and threats to validity

- **Ceiling effect.** Every condition reached 100%. The tasks are small, at 1 to 4 modules each.
  The English requirements for A were also very precise: they came from the same requirement list
  as the score and spell out check order and boundaries. Under vaguer specifications, or on larger
  tasks, a structured scaffold might help. This evaluation cannot show that, nor rule it out.
- **Single author.** I wrote the tasks, scores, references and hidden tests. Score design is a
  judgment call: more logic in the score means more pre-solved code for B and C.
- **One model, 2 attempts per cell, no control over sampling settings.** The configured model was
  identical for all 63 sub-agents. The **served** model reported by the API differed in 3 of 60
  attempts (run-22, run-26, run-39). They are kept as recorded, never replaced, and the sensitivity
  analysis excludes them. Model names appear only as SHA-256 digests in this repository.
- **Concurrency.** Attempts ran 15 at a time, so wall-clock time includes queueing noise. The
  schedule was randomized, so this noise is not confounded with condition.
- **Isolation by instruction.** The audit found no out-of-workspace access, but isolation was not
  enforced by the sandbox.
- **No checker in the loop.** B and C could not run the Sonic checker during implementation. A
  product that does give agents the checker as feedback was not evaluated.
- **Hidden-test gap.** One challenge mutant (tax `+49`) changed no tested behavior, which shows the
  hidden tests are not exhaustive.

## 8. Final verdicts

**Claim A: template reliability. SUPPORTED** (for structure, not behavior). The generator turned
every independently written score into valid, compilable scaffolds. The checker reliably detects
changes to planned structure, imports, files and hole call-lists. It does not detect semantic
changes inside holes (5/7 behavior-changing hole mutations missed), and it constrains hole contents
syntactically in ways that leak implementation choices into the score.

**Claim B: coding advantage. NOT SUPPORTED.** Sonic templates gave the same correctness as a
neutral structured scaffold carrying identical information (C−B = 0.0 in 10/10 tasks), and the same
as plain English (C−A = 0.0). Because of the ceiling, this is weak evidence about harder settings.

**Claim C: context advantage. NOT SUPPORTED.** The structured conditions increased context and
effort. C against A: +45% task context, +1.1 tool calls, +7.2 s (all significant over tasks). C
against B: no significant difference, and C was slightly higher. The scaffold does not remove
specification overhead; it moves the specification into a larger artifact that the agent still
reads.

**Claim D: musical advantage. NOT SUPPORTED.** The musical layer carries only the element-kind
sequence. Semantically opposite plans sound identical, and deviation pings are identical across
issue types. No agent used the audio. An audio-capable model was NOT TESTED.

**Claim E: product potential (agent-facing). NOT SUPPORTED** on this evidence. What works (a
structured JSON plan, a scaffold compiler and a syntactic plan-conformance checker) is useful but
independent of music, and an ordinary structured spec reproduced it fully (condition B). No
measured agent benefit justifies developing the audible layer as an agent-facing tool. This
evaluation does not recommend architectural expansion. If development continues, these are the
next experiments to run before any expansion:
- harder or less precisely specified tasks, so results fall below the ceiling;
- a condition where the agent gets the conformance checker as a feedback loop;
- a separate human study of the audio interface.
