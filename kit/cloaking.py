from __future__ import annotations

import random


CLOAKING_TECHNIQUES = [
    "synonym_substitution",
    "whitespace_variation",
    "unicode_homoglyphs",
    "encoding_wrap",
]


def fuzz_payload(payload: str, technique: str) -> str:
    text = str(payload)
    normalized = str(technique or "").strip().lower()

    if normalized == "synonym_substitution":
        replacements = {
            "ignore": "disregard",
            "reveal": "surface",
            "bypass": "sidestep",
            "instructions": "guidelines",
        }
        words = [replacements.get(word.lower(), word) for word in text.split()]
        return " ".join(words)

    if normalized == "whitespace_variation":
        return "  ".join(text.split())

    if normalized == "unicode_homoglyphs":
        mapping = str.maketrans({"a": "а", "e": "е", "i": "і", "o": "ο", "p": "р", "c": "с"})
        return text.translate(mapping)

    if normalized == "encoding_wrap":
        return '{"wrapped_payload": %r}' % text

    return text


def generate_hard_negatives(successful_payloads: list[dict], blocked_payloads: list[dict], n: int = 5) -> list[dict]:
    if n <= 0:
        return []

    successful_examples = [item for item in successful_payloads if item.get("payload")]
    blocked_examples = [item for item in blocked_payloads if item.get("payload")]
    seed_examples = successful_examples or blocked_examples
    if not seed_examples:
        return []

    generated: list[dict] = []
    for index in range(1, n + 1):
        base = seed_examples[(index - 1) % len(seed_examples)]
        blocked = blocked_examples[(index - 1) % len(blocked_examples)] if blocked_examples else base
        payload = (
            f"Variant probe {index}: preserve successful framing '{base.get('payload')}' "
            f"while adapting blocked pattern '{blocked.get('payload')}'."
        )
        generated.append(
            {
                "id": f"HN_{index:03d}",
                "name": f"Hard negative {index}",
                "category": base.get("category") or blocked.get("category") or "prompt_injection",
                "payload": payload,
                "action": base.get("action") or blocked.get("action") or "fetch_data",
                "origin": base.get("origin") or blocked.get("origin") or "redteam-kit",
                "expected_decision": "DENIED",
                "severity": base.get("severity") or blocked.get("severity") or "HIGH",
                "mutation_strategy": "hard_negative",
            }
        )
    return generated