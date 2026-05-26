from __future__ import annotations

from dataclasses import asdict, dataclass, field

from kit.evidence import EvidenceTrace


@dataclass(frozen=True)
class ProbeCase:
    case_id: str
    name: str
    family: str
    payload: str
    expected_block: bool
    owasp_id: str
    nist_controls: tuple[str, ...]
    target_surface: str = "prompt"
    action: str = "fetch_data"
    risk_class: str | None = None
    tool_name: str | None = None
    arguments: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProbeResult:
    case: ProbeCase
    actual_decision: str
    gate_decision: str
    evidence: EvidenceTrace
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["evidence"] = asdict(self.evidence)
        return row