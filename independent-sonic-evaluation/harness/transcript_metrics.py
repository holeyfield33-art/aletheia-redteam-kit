"""Extract measured usage and an isolation audit from a sub-agent JSONL transcript.

usage: transcript_metrics.py <transcript.jsonl> <workspace> <run_dir>

Writes into run_dir:
  transcript_metrics.json  per-call input-token usage (as reported by the API in the transcript;
                           logged output_tokens are mid-stream snapshots, kept only as a lower
                           bound; generated_chars counts the agent's text and tool-call inputs),
                           model-call count, tool calls by name, isolation audit
  transcript.md            sanitized transcript: the launcher message, assistant text,
                           tool calls and (truncated) tool results. System prompts and
                           environment attachments are omitted.
The model identifier is checked for consistency across attempts but stored only as a
SHA-256 digest (repository policy forbids writing model identifiers into artifacts).
"""

import hashlib
import json
import re
import sys
from pathlib import Path

SUSPICIOUS = ("hidden", "independent-sonic-evaluation", "/TASKS", "/RUNS", "/ws/run-", "pilot-ws/run-",
              "sonic-code-studio", "test_hidden", "reference")


def text_of(content):
    if isinstance(content, str):
        return content
    parts = []
    for block in content or []:
        if block.get("type") == "text":
            parts.append(block.get("text", ""))
        elif block.get("type") == "tool_result":
            inner = block.get("content")
            parts.append(text_of(inner) if isinstance(inner, list) else str(inner))
    return "\n".join(parts)


def main(transcript, workspace, run_dir):
    lines = [json.loads(line) for line in Path(transcript).read_text(encoding="utf-8").splitlines() if line.strip()]
    workspace = str(Path(workspace))
    calls, tool_calls, out_lines, model_ids = {}, [], [], set()
    configured, served = set(), {}
    generated_chars = [0]
    for entry in lines:
        attachment = entry.get("attachment") or {}
        if attachment.get("type") and isinstance(attachment.get("identity"), dict):
            model_ids.add(attachment["identity"].get("modelId", ""))
            configured.add(attachment["identity"].get("modelId", ""))
        message = entry.get("message") or {}
        role = message.get("role")
        if role == "assistant":
            mid = message.get("id") or entry.get("uuid")
            if message.get("model"):
                model_ids.add(message["model"])
                served.setdefault(mid, message["model"])
            usage = message.get("usage") or {}
            # Streamed fragments of one call share an id. Input fields are fixed per call;
            # output_tokens is logged mid-stream, so keep the maximum seen (a lower bound).
            previous = calls.get(mid) or {}
            merged = dict(usage)
            merged["output_tokens"] = max(previous.get("output_tokens", 0), usage.get("output_tokens", 0))
            calls[mid] = merged
            for block in message.get("content") or []:
                if block.get("type") == "text":
                    generated_chars[0] += len(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    generated_chars[0] += len(json.dumps(block.get("input"), ensure_ascii=False))
                if block.get("type") == "text" and block.get("text", "").strip():
                    out_lines.append("### assistant\n\n" + block["text"].strip() + "\n")
                elif block.get("type") == "tool_use":
                    tool_calls.append({"name": block.get("name"), "input": block.get("input")})
                    out_lines.append(f"### tool call: {block.get('name')}\n\n```json\n"
                                     + json.dumps(block.get("input"), indent=2)[:4000] + "\n```\n")
        elif role == "user" and not entry.get("isMeta"):
            content = message.get("content")
            body = text_of(content)
            is_result = isinstance(content, list) and any(b.get("type") == "tool_result" for b in content)
            label = "tool result" if is_result else "user (launcher)"
            if body.strip():
                out_lines.append(f"### {label}\n\n```\n" + body[:3000] + ("\n...[truncated]" if len(body) > 3000 else "") + "\n```\n")
    per_call = []
    for usage in calls.values():
        if not usage:
            continue
        inp = (usage.get("input_tokens", 0) + usage.get("cache_creation_input_tokens", 0)
               + usage.get("cache_read_input_tokens", 0))
        per_call.append({"input_total": inp, "input_uncached": usage.get("input_tokens", 0),
                         "cache_creation": usage.get("cache_creation_input_tokens", 0),
                         "cache_read": usage.get("cache_read_input_tokens", 0),
                         "output": usage.get("output_tokens", 0)})
    # Isolation audit: any absolute path in a tool input that is not inside this workspace.
    violations = []
    for call in tool_calls:
        if call["name"] == "SubagentHandback":  # the final prose report, not a file/shell access
            continue
        blob = json.dumps(call["input"])
        for path in re.findall(r"/(?:tmp|root|home)[^\s\"'`;|&<>)]*", blob):
            if not path.startswith(workspace) and not workspace.startswith(path.rstrip("/")):
                if not path.startswith("/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/venv"):
                    violations.append({"tool": call["name"], "path": path})
        for marker in SUSPICIOUS:
            if marker in blob and marker not in workspace:
                for hit in re.findall(r"[^\s\"']*" + re.escape(marker) + r"[^\s\"']*", blob):
                    if not hit.startswith(workspace) and workspace not in hit:
                        violations.append({"tool": call["name"], "marker": marker, "text": hit[:200]})
    by_name = {}
    for call in tool_calls:
        by_name[call["name"]] = by_name.get(call["name"], 0) + 1
    metrics = {
        "model_calls": len(per_call),
        "tool_calls": len(tool_calls),
        "tool_calls_by_name": by_name,
        "input_tokens_sum": sum(c["input_total"] for c in per_call),
        "output_tokens_logged_lower_bound": sum(c["output"] for c in per_call),
        "generated_chars": generated_chars[0],
        "first_call_input_tokens": per_call[0]["input_total"] if per_call else None,
        "last_call_input_tokens": per_call[-1]["input_total"] if per_call else None,
        "context_growth_tokens": (per_call[-1]["input_total"] - per_call[0]["input_total"]) if per_call else None,
        "per_call": per_call,
        "model_id_sha256": sorted(hashlib.sha256(m.encode()).hexdigest()[:16] for m in model_ids if m),
        "configured_model_sha256": sorted(hashlib.sha256(m.encode()).hexdigest()[:16] for m in configured if m),
        "served_model_sha256_by_call": sorted({hashlib.sha256(m.encode()).hexdigest()[:16] for m in served.values()}),
        "isolation_violations": violations,
        "source": "API usage fields recorded in the sub-agent transcript",
    }
    Path(run_dir, "transcript_metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    Path(run_dir, "transcript.md").write_text("# Sanitized transcript\n\n" + "\n".join(out_lines), encoding="utf-8")
    print(json.dumps({k: metrics[k] for k in ("model_calls", "tool_calls", "input_tokens_sum", "generated_chars",
                                              "first_call_input_tokens", "context_growth_tokens")}),
          "violations:", len(violations))


if __name__ == "__main__":
    main(*sys.argv[1:])
