from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json

from kit.client import AletheiaClient
from kit.evidence import EvidenceTrace, now_utc, write_trace_jsonl

from .registry import load_scenario_definition
from .types import BlastRadius, ScenarioDefinition, ScenarioRunResult, ScenarioStage, ScenarioStageResult

_RISK_ORDER = {"read": 1, "write": 2, "network": 3, "exec": 4}


def _render_payload(template: str, *, previous_output: str, previous_payload: str, scenario_id: str, stage_id: str) -> str:
    return template.format(
        previous_output=previous_output,
        previous_payload=previous_payload,
        scenario_id=scenario_id,
        stage_id=stage_id,
    )


def _gate_decision(decision: str) -> str:
    normalized = str(decision or "").strip().upper()
    if normalized == "DENIED":
        return "blocked"
    if normalized == "PROCEED":
        return "leaked"
    return "error"


def _highest_risk_class(stages: list[ScenarioStageResult]) -> str:
    risk_class = "read"
    for stage_result in stages:
        candidate = str(stage_result.stage.risk_class or "read").strip().lower()
        if _RISK_ORDER.get(candidate, 0) >= _RISK_ORDER.get(risk_class, 0):
            risk_class = candidate
    return risk_class


def _blast_radius(stages: list[ScenarioStageResult]) -> BlastRadius:
    reached = len(stages)
    highest = _highest_risk_class(stages)
    score = reached + _RISK_ORDER.get(highest, 0)
    return BlastRadius(stages_reached=reached, highest_risk_class=highest, score=score)


def execute_scenario_definition(
    client: AletheiaClient,
    scenario: ScenarioDefinition,
    *,
    evidence_root: Path = Path("evidence"),
    run_id: str | None = None,
) -> ScenarioRunResult:
    chosen_run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stage_results: list[ScenarioStageResult] = []
    previous_output = ""
    previous_payload = ""

    for stage in scenario.stages:
        started_at = now_utc()
        request_payload = _render_payload(
            stage.payload_template,
            previous_output=previous_output,
            previous_payload=previous_payload,
            scenario_id=scenario.scenario_id,
            stage_id=stage.stage_id,
        )
        previous_payload = request_payload

        if stage.kind == "not_implemented":
            trace = EvidenceTrace(
                case_id=stage.stage_id,
                request_payload=request_payload,
                request_sha256=sha256(request_payload.encode("utf-8")).hexdigest(),
                retrieved_docs=[],
                tool_calls=[],
                raw_output="NOT_IMPLEMENTED",
                output_sha256=sha256(b"NOT_IMPLEMENTED").hexdigest(),
                gate_decision="error",
                owasp_id=stage.owasp_id,
                nist_controls=list(stage.nist_controls),
                timestamp_utc=started_at,
            )
            write_trace_jsonl(trace, evidence_root=evidence_root, run_id=chosen_run_id)
            stage_results.append(
                ScenarioStageResult(
                    stage=stage,
                    request_payload=request_payload,
                    actual_decision="NOT_IMPLEMENTED",
                    gate_decision="error",
                    evidence={"trace": trace.__dict__},
                    not_implemented=True,
                    error="multimodal_stage_not_implemented",
                )
            )
            previous_output = "NOT_IMPLEMENTED"
            continue

        try:
            response = client.audit(payload=request_payload, action=stage.action, origin="redteam-kit")
            raw_output = json.dumps(response.raw, sort_keys=True, ensure_ascii=True)
            trace = EvidenceTrace(
                case_id=stage.stage_id,
                request_payload=request_payload,
                request_sha256=sha256(request_payload.encode("utf-8")).hexdigest(),
                retrieved_docs=[],
                tool_calls=[],
                raw_output=raw_output,
                output_sha256=sha256(raw_output.encode("utf-8")).hexdigest(),
                gate_decision=_gate_decision(response.decision),
                owasp_id=stage.owasp_id,
                nist_controls=list(stage.nist_controls),
                timestamp_utc=started_at,
            )
            write_trace_jsonl(trace, evidence_root=evidence_root, run_id=chosen_run_id)
            stage_results.append(
                ScenarioStageResult(
                    stage=stage,
                    request_payload=request_payload,
                    actual_decision=response.decision,
                    gate_decision=trace.gate_decision,
                    evidence={"trace": trace.__dict__},
                    error=None,
                )
            )
            previous_output = raw_output
        except Exception as exc:
            raw_output = str(exc)
            trace = EvidenceTrace(
                case_id=stage.stage_id,
                request_payload=request_payload,
                request_sha256=sha256(request_payload.encode("utf-8")).hexdigest(),
                retrieved_docs=[],
                tool_calls=[],
                raw_output=raw_output,
                output_sha256=sha256(raw_output.encode("utf-8")).hexdigest(),
                gate_decision="error",
                owasp_id=stage.owasp_id,
                nist_controls=list(stage.nist_controls),
                timestamp_utc=started_at,
            )
            write_trace_jsonl(trace, evidence_root=evidence_root, run_id=chosen_run_id)
            stage_results.append(
                ScenarioStageResult(
                    stage=stage,
                    request_payload=request_payload,
                    actual_decision="ERROR",
                    gate_decision="error",
                    evidence={"trace": trace.__dict__},
                    error=str(exc),
                )
            )
            previous_output = raw_output

    blast_radius = _blast_radius(stage_results)
    chain_completed = len(stage_results) == len(scenario.stages) and all(result.gate_decision != "error" for result in stage_results)
    if chain_completed:
        finding_type = "chain_complete"
        severity = "CRITICAL"
    elif any(result.gate_decision == "leaked" for result in stage_results):
        finding_type = "chain_partial_leak"
        severity = "HIGH"
    else:
        finding_type = "chain_blocked"
        severity = "MEDIUM"

    return ScenarioRunResult(
        scenario=scenario,
        stages=tuple(stage_results),
        blast_radius=blast_radius,
        chain_completed=chain_completed,
        finding_type=finding_type,
        severity=severity,
    )


def run_scenario(
    client: AletheiaClient,
    scenario_id: str,
    *,
    evidence_root: Path = Path("evidence"),
    run_id: str | None = None,
) -> ScenarioRunResult:
    scenario = load_scenario_definition(scenario_id)
    return execute_scenario_definition(client, scenario, evidence_root=evidence_root, run_id=run_id)