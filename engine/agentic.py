"""Autonomous red-team optimization loop utilities."""
from __future__ import annotations

from dataclasses import dataclass

from engine.mutation import build_mutation_variants


@dataclass(frozen=True)
class AgenticConfig:
    """Configuration for iterative attack optimization."""

    objective: str
    iterations: int = 4
    seed_size: int = 10
    variants_per_round: int = 6
    stop_on_first_bypass: bool = True
    mutation_strategies: list[str] | None = None


def _severity_weight(severity: str) -> float:
    weights = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.25,
    }
    return weights.get(str(severity).upper(), 0.4)


def _fitness(candidate: dict, result: dict) -> float:
    # For offensive optimization, a bypass is a PROCEED where DENIED was expected.
    bypass = result.get("actual_decision") == "PROCEED" and candidate.get("expected_decision") == "DENIED"
    if bypass:
        return 1.0 + _severity_weight(candidate.get("severity", "MEDIUM"))
    if result.get("actual_decision") == "ERROR":
        return -0.5
    return 0.0


def _select_seed_attacks(attacks: list[dict], seed_size: int) -> list[dict]:
    # Start from highest-risk, non-benign attacks to optimize bypass discovery signal.
    filtered = [a for a in attacks if str(a.get("category", "")).strip().lower() != "benign_controls"]
    ranked = sorted(filtered, key=lambda a: _severity_weight(a.get("severity", "MEDIUM")), reverse=True)
    return ranked[: max(seed_size, 1)]


def run_agentic_loop(
    client,
    attacks: list[dict],
    run_attack_fn,
    config: AgenticConfig,
) -> dict:
    """Run an iterative optimization loop and return traceable artifacts."""
    seeds = _select_seed_attacks(attacks, config.seed_size)
    if not seeds:
        return {
            "objective": config.objective,
            "iterations_requested": config.iterations,
            "iterations_executed": 0,
            "seed_count": 0,
            "execution_errors": 0,
            "best_result": None,
            "iteration_summaries": [],
        }

    population = list(seeds)
    iteration_summaries: list[dict] = []
    best_candidate: dict | None = None
    best_result: dict | None = None
    best_score = float("-inf")
    execution_errors = 0

    strategy_stats: dict[str, dict[str, float | int]] = {}

    for iteration in range(1, max(config.iterations, 1) + 1):
        evaluated: list[dict] = []
        for candidate in population[: max(config.variants_per_round, 1)]:
            result = run_attack_fn(client, candidate)
            score = _fitness(candidate, result)
            strategy = str(candidate.get("mutation_strategy") or "seed")
            bypass = result.get("actual_decision") == "PROCEED" and candidate.get("expected_decision") == "DENIED"

            current = strategy_stats.setdefault(strategy, {"attempts": 0, "bypasses": 0, "bypass_rate": 0.0})
            current["attempts"] = int(current["attempts"]) + 1
            if bypass:
                current["bypasses"] = int(current["bypasses"]) + 1
            attempts = int(current["attempts"])
            bypasses = int(current["bypasses"])
            current["bypass_rate"] = round(100.0 * bypasses / attempts, 1) if attempts else 0.0

            if result.get("actual_decision") == "ERROR":
                execution_errors += 1
            evaluated.append(
                {
                    "candidate_id": candidate.get("id"),
                    "parent_id": candidate.get("parent_id"),
                    "mutation_strategy": strategy,
                    "category": candidate.get("category"),
                    "severity": candidate.get("severity", "MEDIUM"),
                    "payload": candidate.get("payload"),
                    "expected_decision": candidate.get("expected_decision"),
                    "actual_decision": result.get("actual_decision"),
                    "fitness": round(score, 4),
                    "request_id": result.get("request_id"),
                    "error": result.get("error"),
                }
            )

            if score > best_score:
                best_score = score
                best_candidate = dict(candidate)
                best_result = dict(result)

        evaluated_sorted = sorted(evaluated, key=lambda item: item["fitness"], reverse=True)
        top_two = evaluated_sorted[:2]
        iteration_summaries.append(
            {
                "iteration": iteration,
                "evaluated": len(evaluated),
                "top_candidates": top_two,
            }
        )

        bypass_found = any(
            item["actual_decision"] == "PROCEED" and item["expected_decision"] == "DENIED" for item in evaluated
        )
        if bypass_found and config.stop_on_first_bypass:
            break

        top_for_mutation: list[dict] = []
        for item in top_two:
            matched = next((candidate for candidate in population if candidate.get("id") == item["candidate_id"]), None)
            if matched is not None:
                top_for_mutation.append(matched)

        if not top_for_mutation:
            break

        population = build_mutation_variants(
            top_for_mutation,
            objective=config.objective,
            round_index=iteration + 1,
            limit=max(config.variants_per_round, 1),
            strategies=config.mutation_strategies,
        )
        if not population:
            break

    return {
        "objective": config.objective,
        "iterations_requested": config.iterations,
        "iterations_executed": len(iteration_summaries),
        "seed_count": len(seeds),
        "execution_errors": execution_errors,
        "best_score": round(best_score, 4) if best_result is not None else None,
        "best_candidate": best_candidate,
        "best_result": best_result,
        "mutation_analytics": strategy_stats,
        "iteration_summaries": iteration_summaries,
    }