from __future__ import annotations

import re

_WORD_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(value: str) -> set[str]:
    return set(_WORD_RE.findall(str(value).lower()))


def _jaccard_similarity(tokens_a: set[str], tokens_b: set[str]) -> float:
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a.intersection(tokens_b))
    union = len(tokens_a.union(tokens_b))
    return float(intersection) / float(union) if union else 0.0


def dedupe_attacks_semantic(attacks: list[dict], threshold: float = 0.92) -> list[dict]:
    normalized_threshold = max(0.0, min(1.0, float(threshold)))
    if not attacks:
        return []

    unique: list[dict] = []
    seen_exact: set[str] = set()
    seen_tokens: list[set[str]] = []

    for attack in attacks:
        row = dict(attack)
        payload = str(row.get("payload", ""))
        exact_key = " ".join(payload.split()).strip().lower()
        if exact_key in seen_exact:
            continue

        tokens = _tokenize(payload)
        is_duplicate = False
        if normalized_threshold > 0.0:
            for prior in seen_tokens:
                if _jaccard_similarity(tokens, prior) >= normalized_threshold:
                    is_duplicate = True
                    break
        if is_duplicate:
            continue

        unique.append(row)
        seen_exact.add(exact_key)
        seen_tokens.append(tokens)

    return unique


def limit_attacks_with_benign_ratio(attacks: list[dict], *, max_attacks: int, benign_ratio: float = 0.2) -> list[dict]:
    limit = max(0, int(max_attacks))
    if limit <= 0 or len(attacks) <= limit:
        return [dict(attack) for attack in attacks]

    ratio = max(0.0, min(1.0, float(benign_ratio)))
    benign = [dict(attack) for attack in attacks if str(attack.get("category", "")).strip().lower() == "benign_controls"]
    non_benign = [dict(attack) for attack in attacks if str(attack.get("category", "")).strip().lower() != "benign_controls"]

    desired_benign = min(len(benign), int(round(limit * ratio)))
    selected = benign[:desired_benign]

    remaining = max(0, limit - len(selected))
    selected.extend(non_benign[:remaining])

    if len(selected) < limit:
        residual_benign = benign[desired_benign:desired_benign + (limit - len(selected))]
        selected.extend(residual_benign)

    return selected[:limit]
