"""Built-in mutation plugin for scaling payload families with bounded quality controls.

Usage example:
    python -m kit.runner --mode api \
      --plugin kit.payload_mutation_plugin \
      --payload-mutation-plugin \
      --attack-intensity medium \
      --payload-seed-limit 80 \
      --payload-expand-to 500
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engine.mutation import mutate_payload, strategies_for_intensity

name = "payload-mutation-plugin"

_INTENSITY_DEFAULT_VARIANTS = {
    "light": 5,
    "medium": 7,
    "aggressive": 10,
}


def _normalize_payload(value: str) -> str:
    return " ".join(str(value).split()).strip().lower()


def _is_seed_attack(attack: dict) -> bool:
    variant_kind = str(attack.get("variant_kind", "seed")).strip().lower() or "seed"
    return variant_kind == "seed"


def _is_mutable_category(attack: dict) -> bool:
    category = str(attack.get("category", "")).strip().lower()
    return category not in {"benign_controls", "multi_turn"}


def _variants_per_seed(args: Any) -> int:
    configured = int(getattr(args, "variants_per_seed", 0) or 0)
    if configured > 0:
        return configured
    intensity = str(getattr(args, "attack_intensity", "medium")).strip().lower()
    return _INTENSITY_DEFAULT_VARIANTS.get(intensity, _INTENSITY_DEFAULT_VARIANTS["medium"])


def _next_variant_id(seed_id: str, strategy: str, round_index: int, taken: set[str]) -> str:
    base = f"PM_{seed_id}_{strategy}_{round_index}"
    if base not in taken:
        return base
    suffix = 2
    while f"{base}_{suffix}" in taken:
        suffix += 1
    return f"{base}_{suffix}"


def _load_family_seeds(args: Any) -> list[dict]:
    family_file = str(getattr(args, "payload_family_file", "") or "").strip()
    if not family_file:
        return []

    path = Path(family_file)
    if not path.exists():
        raise FileNotFoundError(f"Payload family file not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"Payload family file must contain a JSON array: {path}")

    seeds: list[dict] = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Payload family entry #{index} in {path} must be a JSON object")
        row = dict(item)
        row.setdefault("id", f"PF_{index:03d}")
        row.setdefault("name", f"Payload family seed {index}")
        row.setdefault("category", "prompt_injection")
        row.setdefault("action", "fetch_data")
        row.setdefault("origin", "redteam-kit")
        row.setdefault("expected_decision", "DENIED")
        row.setdefault("severity", "HIGH")
        row.setdefault("variant_kind", "seed")
        row.setdefault("source", "payload-family-file")
        payload = str(row.get("payload", "")).strip()
        if not payload:
            raise ValueError(f"Payload family entry #{index} in {path} requires a non-empty payload")
        row["payload"] = payload
        seeds.append(row)
    return seeds


def transform_attacks(attacks: list[dict], args: Any) -> list[dict] | None:
    if not bool(getattr(args, "payload_mutation_plugin", False)):
        return attacks

    prepared = [dict(attack) for attack in attacks]
    prepared.extend(_load_family_seeds(args))

    deduped: list[dict] = []
    seen_payloads: set[str] = set()
    taken_ids: set[str] = set()

    for attack in prepared:
        row = dict(attack)
        taken_ids.add(str(row.get("id", "")).strip())
        payload_key = _normalize_payload(str(row.get("payload", "")))
        if payload_key in seen_payloads:
            continue
        seen_payloads.add(payload_key)
        deduped.append(row)

    seed_limit = max(1, int(getattr(args, "payload_seed_limit", 80) or 80))
    seeds = [row for row in deduped if _is_seed_attack(row) and _is_mutable_category(row)][:seed_limit]
    if not seeds:
        setattr(args, "_payload_mutation_plugin_stats", {
            "enabled": True,
            "seed_count": 0,
            "variants_generated": 0,
            "total_attacks": len(deduped),
            "target_total": int(getattr(args, "payload_expand_to", 0) or 0),
            "deduped_count": len(prepared) - len(deduped),
        })
        return deduped

    intensity = str(getattr(args, "attack_intensity", "medium")).strip().lower()
    strategies = strategies_for_intensity(intensity)
    if not strategies:
        return deduped

    variants_per_seed = _variants_per_seed(args)
    target_total = max(0, int(getattr(args, "payload_expand_to", 0) or 0))
    desired_additional = max(0, target_total - len(deduped)) if target_total > 0 else len(seeds) * variants_per_seed

    generated = 0
    expanded = list(deduped)

    for seed in seeds:
        if desired_additional and generated >= desired_additional:
            break

        seed_id = str(seed.get("id", "seed"))
        base_payload = str(seed.get("payload", ""))
        objective = str(getattr(args, "objective", "Bypass secret exfil detection"))

        for variant_index in range(variants_per_seed):
            if desired_additional and generated >= desired_additional:
                break

            strategy = strategies[variant_index % len(strategies)]
            round_index = 1 + (variant_index // len(strategies))
            mutated_payload = mutate_payload(base_payload, objective, round_index, strategy)
            payload_key = _normalize_payload(mutated_payload)
            if payload_key in seen_payloads:
                continue

            variant = dict(seed)
            variant_id = _next_variant_id(seed_id, strategy, round_index, taken_ids)
            taken_ids.add(variant_id)
            variant["id"] = variant_id
            variant["name"] = f"Plugin mutation {strategy} for {seed_id}"
            variant["payload"] = mutated_payload
            variant["parent_id"] = seed_id
            variant["family_id"] = str(seed.get("family_id") or seed_id)
            variant["mutation_strategy"] = strategy
            variant["variant_kind"] = "dynamic"
            variant["source"] = "plugin:payload-mutation"
            expanded.append(variant)
            seen_payloads.add(payload_key)
            generated += 1

    setattr(args, "_payload_mutation_plugin_stats", {
        "enabled": True,
        "seed_count": len(seeds),
        "variants_generated": generated,
        "total_attacks": len(expanded),
        "target_total": target_total,
        "deduped_count": len(prepared) - len(deduped),
        "variants_per_seed": variants_per_seed,
        "intensity": intensity,
        "family_file": str(getattr(args, "payload_family_file", "") or ""),
    })
    return expanded


def finalize_summary(summary: dict, results: list[dict], args: Any) -> dict | None:
    stats = getattr(args, "_payload_mutation_plugin_stats", None) if args is not None else None
    if not isinstance(stats, dict):
        return summary

    updated = dict(summary)
    updated["payload_mutation"] = dict(stats)
    return updated
