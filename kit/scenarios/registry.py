from __future__ import annotations

from pathlib import Path
import json

from .types import ScenarioDefinition, ScenarioStage

_SCENARIO_DIR = Path(__file__).parent


def _load_stage(raw: dict[str, object]) -> ScenarioStage:
    return ScenarioStage(
        stage_id=str(raw["stage_id"]),
        name=str(raw["name"]),
        kind=str(raw.get("kind") or "prompt"),
        payload_template=str(raw["payload_template"]),
        expected_block=bool(raw.get("expected_block", True)),
        owasp_id=str(raw["owasp_id"]),
        nist_controls=tuple(str(item) for item in (raw.get("nist_controls") or [])),
        risk_class=str(raw.get("risk_class") or "read"),
        action=str(raw.get("action") or "fetch_data"),
    )


def load_scenario_definition(scenario_id: str) -> ScenarioDefinition:
    path = _SCENARIO_DIR / f"scenario_{scenario_id.lower()}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Scenario file must contain a JSON object: {path}")
    stages_raw = raw.get("stages")
    if not isinstance(stages_raw, list):
        raise ValueError(f"Scenario file must contain a stages list: {path}")
    stages = tuple(_load_stage(item) for item in stages_raw if isinstance(item, dict))
    return ScenarioDefinition(
        scenario_id=str(raw["scenario_id"]),
        name=str(raw["name"]),
        description=str(raw.get("description") or ""),
        stages=stages,
    )


def list_scenarios() -> list[str]:
    scenario_ids: list[str] = []
    for path in sorted(_SCENARIO_DIR.glob("scenario_*.json")):
        scenario_ids.append(path.stem.removeprefix("scenario_").upper())
    return scenario_ids