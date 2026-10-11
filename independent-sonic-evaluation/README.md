# independent-sonic-evaluation

This is an independent evaluation of Sonic Code Studio 0.1.0, an audible Python template system by
Astra. It asks whether the system improves AI-assisted coding.

**Start with [FINAL_REPORT.md](FINAL_REPORT.md).**

| File or directory | Contents |
|---|---|
| [AUDIT.md](AUDIT.md) | Inspected source, hashes, environment, original test results (90 passed), and the pitch-encoding finding |
| [PROTOCOL.md](PROTOCOL.md) | Hypotheses, the frozen benchmark, conditions A/B/C, metrics, execution, and deviations from plan |
| [TASKS/](TASKS/) | 10 task specifications: `score.json`, `interface.md`, frozen per-condition materials |
| [TESTS/](TESTS/) | 116 hidden behavioral tests (63 security tests) and reference solutions |
| [RUNS/](RUNS/) | 60 attempts: prompt, final `repo/`, agent scratch checks, sanitized transcript, report, usage, grade |
| [RESULTS.csv](RESULTS.csv) | One row per attempt |
| [RESULTS.json](RESULTS.json) | Aggregates, per-task results, paired comparisons, sensitivity analysis |
| [CHALLENGE/](CHALLENGE/) | Security and structure challenge: 14 mutants, checker reports, deviation audio |
| [MUSIC/](MUSIC/) | Probes of the music layer: what the audio encodes |
| [PILOT/](PILOT/) | 3-attempt harness pilot on the creator's demo example (not benchmark data) |
| [FREEZE.json](FREEZE.json) | SHA-256 hashes of everything frozen before the benchmark ran |
| [REPRODUCE.md](REPRODUCE.md) | Exact commands |
| [harness/](harness/) | All evaluation code. The original prototype is never modified. |

The supplied archive itself is not committed. Its SHA-256 and per-file hashes are recorded in
`AUDIT_DATA/`.
