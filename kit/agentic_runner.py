from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import time

from engine.mutation import build_mutation_variants
from kit.cloaking import CLOAKING_TECHNIQUES, fuzz_payload, generate_hard_negatives


@dataclass(frozen=True)
class AgenticRunnerConfig:
    objective: str
    max_iterations: int = 10
    variants_per_round: int = 1
    mutation_strategies: list[str] | None = None
    output_path: Path = Path("runs/agentic_results.json")
    max_time_seconds: int | None = None
    risk_budget: float | None = None
    success_budget: int | None = None
    diminishing_window: int = 3
    diminishing_min_delta: int = 1


class AgenticRunner:
    def __init__(self, client, attacks: list[dict], run_attack_fn, config: AgenticRunnerConfig) -> None:
        self.client = client
        self.attacks = list(attacks)
        self.run_attack_fn = run_attack_fn
        self.config = config

    def _should_record_success(self, attack: dict, result: dict) -> bool:
        return result.get("actual_decision") == "PROCEED" and attack.get("expected_decision") == "DENIED"

    def _should_mutate(self, attack: dict, result: dict) -> bool:
        if str(attack.get("category") or "").strip().lower() == "benign_controls":
            return False
        return result.get("actual_decision") == "DENIED" and attack.get("expected_decision") == "DENIED"

    def _build_requeue_variants(self, attack: dict, round_index: int) -> list[dict]:
        return build_mutation_variants(
            [attack],
            objective=self.config.objective,
            round_index=round_index,
            limit=max(self.config.variants_per_round, 1),
            strategies=self.config.mutation_strategies,
        )

    def _apply_cloaking(self, variants: list[dict]) -> list[dict]:
        cloaked: list[dict] = []
        for variant in variants:
            cloaking_technique = random.choice(CLOAKING_TECHNIQUES)
            updated = dict(variant)
            updated["payload"] = fuzz_payload(str(variant.get("payload", "")), cloaking_technique)
            updated["cloaking_technique"] = cloaking_technique
            cloaked.append(updated)
        return cloaked

    def _risk_score(self, attack: dict, result: dict) -> float:
        if not self._should_record_success(attack, result):
            return 0.0
        severity = str(attack.get("severity", "MEDIUM")).strip().upper()
        if severity == "CRITICAL":
            return 5.0
        if severity == "HIGH":
            return 3.0
        if severity == "MEDIUM":
            return 2.0
        return 1.0

    def _build_learning_snapshot(
        self,
        *,
        successful_payloads: list[dict],
        blocked_payloads: list[dict],
        iteration_summaries: list[dict],
        mutation_effectiveness: dict[str, dict[str, int]],
        stop_reason: str,
        elapsed_seconds: float,
        accumulated_risk: float,
    ) -> dict:
        successful_by_category: dict[str, int] = {}
        blocked_by_category: dict[str, int] = {}
        for row in successful_payloads:
            category = str(row.get("category") or "unknown")
            successful_by_category[category] = successful_by_category.get(category, 0) + 1
        for row in blocked_payloads:
            category = str(row.get("category") or "unknown")
            blocked_by_category[category] = blocked_by_category.get(category, 0) + 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stop_reason": stop_reason,
            "elapsed_seconds": round(float(elapsed_seconds), 3),
            "accumulated_risk": round(float(accumulated_risk), 3),
            "successful_by_category": successful_by_category,
            "blocked_by_category": blocked_by_category,
            "mutation_effectiveness": mutation_effectiveness,
            "iterations": iteration_summaries,
        }

    def run(self) -> dict:
        started_at = time.monotonic()
        queue = list(self.attacks)
        blocked_payloads: list[dict] = []
        successful_payloads: list[dict] = []
        hard_negative_payloads: list[dict] = []
        results: list[dict] = []
        iteration_summaries: list[dict] = []
        interrupted = False
        stop_reason = "max_iterations_reached"
        accumulated_risk = 0.0
        mutation_effectiveness: dict[str, dict[str, int]] = {}

        try:
            for iteration in range(1, max(self.config.max_iterations, 1) + 1):
                if not queue:
                    stop_reason = "queue_exhausted"
                    break

                elapsed_seconds = time.monotonic() - started_at
                if self.config.max_time_seconds is not None and elapsed_seconds >= float(self.config.max_time_seconds):
                    stop_reason = "time_budget_exceeded"
                    break
                if self.config.success_budget is not None and len(successful_payloads) >= int(self.config.success_budget):
                    stop_reason = "success_budget_reached"
                    break
                if self.config.risk_budget is not None and accumulated_risk >= float(self.config.risk_budget):
                    stop_reason = "risk_budget_reached"
                    break

                current_batch = queue
                queue = []
                blocked_this_round = 0
                successes_this_round = 0

                for attack in current_batch:
                    result = self.run_attack_fn(self.client, attack)
                    row = {
                        "iteration": iteration,
                        "id": attack.get("id"),
                        "name": attack.get("name"),
                        "category": attack.get("category"),
                        "payload": attack.get("payload"),
                        "expected_decision": attack.get("expected_decision"),
                        "actual_decision": result.get("actual_decision"),
                        "request_id": result.get("request_id"),
                        "error": result.get("error"),
                        "mutation_strategy": attack.get("mutation_strategy"),
                        "cloaking_technique": attack.get("cloaking_technique"),
                    }
                    results.append(row)

                    if self._should_record_success(attack, result):
                        successful_payloads.append(row)
                        successes_this_round += 1
                        strategy = str(attack.get("mutation_strategy") or "seed")
                        stats = mutation_effectiveness.setdefault(strategy, {"success": 0, "blocked": 0})
                        stats["success"] += 1
                        accumulated_risk += self._risk_score(attack, result)
                        continue

                    if self._should_mutate(attack, result):
                        blocked_payloads.append(row)
                        blocked_this_round += 1
                        strategy = str(attack.get("mutation_strategy") or "seed")
                        stats = mutation_effectiveness.setdefault(strategy, {"success": 0, "blocked": 0})
                        stats["blocked"] += 1
                        queue.extend(self._apply_cloaking(self._build_requeue_variants(attack, iteration + 1)))

                fresh_hard_negatives = generate_hard_negatives(successful_payloads, blocked_payloads)
                if fresh_hard_negatives:
                    hard_negative_payloads.extend(fresh_hard_negatives)
                    queue.extend(fresh_hard_negatives)

                iteration_summaries.append(
                    {
                        "iteration": iteration,
                        "processed": len(current_batch),
                        "blocked": blocked_this_round,
                        "successful": successes_this_round,
                        "hard_negatives": len(fresh_hard_negatives),
                        "requeued": len(queue),
                    }
                )

                window = max(1, int(self.config.diminishing_window or 1))
                if len(iteration_summaries) >= window:
                    recent_successes = [item.get("successful", 0) for item in iteration_summaries[-window:]]
                    if sum(recent_successes) < max(0, int(self.config.diminishing_min_delta or 0)):
                        stop_reason = "diminishing_returns"
                        break
        except KeyboardInterrupt:
            interrupted = True
            stop_reason = "interrupted"

        elapsed_seconds = time.monotonic() - started_at
        learning_snapshot = self._build_learning_snapshot(
            successful_payloads=successful_payloads,
            blocked_payloads=blocked_payloads,
            iteration_summaries=iteration_summaries,
            mutation_effectiveness=mutation_effectiveness,
            stop_reason=stop_reason,
            elapsed_seconds=elapsed_seconds,
            accumulated_risk=accumulated_risk,
        )
        learning_snapshot_path = self.config.output_path.with_name("learning_snapshot.json")
        mutation_effectiveness_path = self.config.output_path.with_name("mutation_effectiveness.json")

        output = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "agentic",
            "objective": self.config.objective,
            "max_iterations": self.config.max_iterations,
            "iterations_executed": len(iteration_summaries),
            "interrupted": interrupted,
            "stop_reason": stop_reason,
            "elapsed_seconds": round(float(elapsed_seconds), 3),
            "risk_consumed": round(float(accumulated_risk), 3),
            "initial_payloads": len(self.attacks),
            "successful_payloads": successful_payloads,
            "blocked_payloads": blocked_payloads,
            "hard_negative_payloads": hard_negative_payloads,
            "results": results,
            "iteration_summaries": iteration_summaries,
            "learning_snapshot_path": str(learning_snapshot_path),
            "mutation_effectiveness_path": str(mutation_effectiveness_path),
        }

        self.config.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        learning_snapshot_path.write_text(json.dumps(learning_snapshot, indent=2), encoding="utf-8")
        mutation_effectiveness_path.write_text(json.dumps(mutation_effectiveness, indent=2), encoding="utf-8")
        return output