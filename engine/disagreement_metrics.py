"""
Metrics for agent disagreement, override rate, confidence collapse, veto instability.
"""
from __future__ import annotations

import re
from collections import Counter


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"\w+", text.lower()))


def calculate_disagreement_score(agent_outputs: list[str]) -> float:
    """Compute Jaccard dissimilarity across all pairs of agent outputs.

    0.0 = perfect consensus (identical vocabulary), 1.0 = total disagreement.
    Returns 0.0 for fewer than 2 outputs.
    """
    if len(agent_outputs) < 2:
        return 0.0
    token_sets = [_tokenize(o) for o in agent_outputs]
    pair_scores: list[float] = []
    for i in range(len(token_sets)):
        for j in range(i + 1, len(token_sets)):
            a, b = token_sets[i], token_sets[j]
            union = a | b
            if not union:
                pair_scores.append(0.0)
                continue
            intersection = a & b
            pair_scores.append(1.0 - len(intersection) / len(union))
    return round(sum(pair_scores) / len(pair_scores), 4)


def calculate_override_rate(adjudication_log: list[dict]) -> float:
    """Compute fraction of log entries where the adjudicated decision differs from the subsystem decision.

    Each entry must have 'adjudicated_decision' and 'subsystem_decision' keys.
    Returns 0.0 for an empty log.
    """
    if not adjudication_log:
        return 0.0
    overrides = sum(
        1
        for entry in adjudication_log
        if str(entry.get("adjudicated_decision", "")).upper()
        != str(entry.get("subsystem_decision", "")).upper()
    )
    return round(overrides / len(adjudication_log), 4)
