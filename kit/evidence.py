from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json


@dataclass(frozen=True)
class EvidenceTrace:
    case_id: str
    request_payload: str
    request_sha256: str
    retrieved_docs: list[str]
    tool_calls: list[dict[str, object]]
    raw_output: str
    output_sha256: str
    gate_decision: str
    owasp_id: str
    nist_controls: list[str]
    timestamp_utc: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def write_trace_jsonl(trace: EvidenceTrace, *, evidence_root: Path, run_id: str) -> Path:
    run_dir = evidence_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "evidence.jsonl"
    with out_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(trace), sort_keys=True) + "\n")
    return out_path