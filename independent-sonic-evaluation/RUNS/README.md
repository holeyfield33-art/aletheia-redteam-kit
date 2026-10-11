# Attempt records

`<task>/<condition>-<attempt>/` holds one attempt. `schedule.json` maps the opaque run IDs and gives
the execution order.

| File | Contents |
|---|---|
| `prompt.txt` | Exact instructions given (the agent read them from `TASK_PROMPT.md`) |
| `repo/` | Delivered code, exactly as the agent left it |
| `agent_scratch/` | The agent's own checks |
| `agent_report.md` | The agent's final report, verbatim |
| `transcript.md` | Sanitized transcript: assistant text, tool calls, truncated tool results |
| `transcript_metrics.json` | Per-call API input-token usage, call counts, model digests, isolation audit |
| `usage.json` | Agent completion record: total tokens, tool uses, duration |
| `grade.json` | Hidden-test results, requirement omissions, Sonic conformance, interface check |

All 60 attempts are preserved. No attempt was rerun or replaced.
