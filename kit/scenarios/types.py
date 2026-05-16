from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ScenarioStage:
    stage_id: str
    name: str
    kind: str
    payload_template: str
    expected_block: bool
    owasp_id: str
    nist_controls: tuple[str, ...]
    risk_class: str = "read"
    action: str = "fetch_data"


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str
    name: str
    description: str
    stages: tuple[ScenarioStage, ...]


@dataclass(frozen=True)
class ScenarioStageResult:
    stage: ScenarioStage
    request_payload: str
    actual_decision: str
    gate_decision: str
    evidence: dict[str, object]
    not_implemented: bool = False
    error: str | None = None


@dataclass(frozen=True)
class BlastRadius:
    stages_reached: int
    highest_risk_class: str
    score: int


@dataclass(frozen=True)
class ScenarioRunResult:
    scenario: ScenarioDefinition
    stages: tuple[ScenarioStageResult, ...]
    blast_radius: BlastRadius
    chain_completed: bool
    finding_type: str
    severity: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)