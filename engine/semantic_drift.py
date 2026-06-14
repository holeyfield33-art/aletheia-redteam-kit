"""
Track semantic drift and escalation slope over long-horizon interactions.

Uses term-frequency cosine similarity (stdlib only, no external deps).
"""
from __future__ import annotations

import math
import re
from collections import Counter


def _tokenize(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _tf_vector(tokens: list[str]) -> Counter:
    return Counter(tokens)


def _cosine_similarity(a: Counter, b: Counter) -> float:
    shared = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in shared)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def _cosine_distance(a: Counter, b: Counter) -> float:
    return 1.0 - _cosine_similarity(a, b)


def compute_semantic_drift(history: list[str]) -> float:
    """Return the max pairwise cosine distance across consecutive turn pairs.

    0.0 = identical turns, 1.0 = orthogonal (no shared vocabulary).
    Returns 0.0 when history has fewer than 2 turns.
    """
    if len(history) < 2:
        return 0.0
    vectors = [_tf_vector(_tokenize(turn)) for turn in history]
    max_drift = 0.0
    for i in range(len(vectors) - 1):
        d = _cosine_distance(vectors[i], vectors[i + 1])
        if d > max_drift:
            max_drift = d
    return round(max_drift, 4)


def flag_drift_violations(history: list[str], threshold: float = 0.7) -> list[int]:
    """Return turn indices (1-based, pointing to the *later* turn) where drift exceeds threshold."""
    if len(history) < 2:
        return []
    vectors = [_tf_vector(_tokenize(turn)) for turn in history]
    violations: list[int] = []
    for i in range(len(vectors) - 1):
        d = _cosine_distance(vectors[i], vectors[i + 1])
        if d >= threshold:
            violations.append(i + 1)
    return violations
