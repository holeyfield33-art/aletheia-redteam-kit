from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from engine.mutation import build_mutation_variants
from kit.cloaking import CLOAKING_TECHNIQUES, fuzz_payload, generate_hard_negatives


@dataclass(frozen=True)
class AgenticRunnerConfig:
    objective: str
    max_iterations: int = 10
    variants_per_round: int = 1
    mutation_strategies: list[str] | None = None
    output_path: Path = Path("runs/agentic_results.json")


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

    def run(self) -> dict:
        queue = list(self.attacks)
        blocked_payloads: list[dict] = []
        successful_payloads: list[dict] = []
        hard_negative_payloads: list[dict] = []
        results: list[dict] = []
        iteration_summaries: list[dict] = []
        interrupted = False

        try:
            for iteration in range(1, max(self.config.max_iterations, 1) + 1):
                if not queue:
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
                        continue

                    if self._should_mutate(attack, result):
                        blocked_payloads.append(row)
                        blocked_this_round += 1
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
        except KeyboardInterrupt:
            interrupted = True

        output = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "agentic",
            "objective": self.config.objective,
            "max_iterations": self.config.max_iterations,
            "iterations_executed": len(iteration_summaries),
            "interrupted": interrupted,
            "initial_payloads": len(self.attacks),
            "successful_payloads": successful_payloads,
            "blocked_payloads": blocked_payloads,
            "hard_negative_payloads": hard_negative_payloads,
            "results": results,
            "iteration_summaries": iteration_summaries,
        }

        self.config.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        return output