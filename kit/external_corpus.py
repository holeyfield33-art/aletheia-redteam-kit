from __future__ import annotations

import json
from pathlib import Path


def _read_json_rows(path: Path) -> list:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        rows = raw.get("attacks") or raw.get("items") or raw.get("data") or raw.get("prompts") or [raw]
    else:
        rows = raw
    if not isinstance(rows, list):
        raise ValueError(f"External corpus must contain a JSON list or object with attacks/items/data/prompts: {path}")
    return rows


def _pick_payload(item: dict) -> str:
    for key in ("payload", "prompt", "text", "question", "input", "content", "query", "goal"):
        value = item.get(key)
        if value is None:
            continue
        payload = str(value).strip()
        if payload:
            return payload
    return ""


def _infer_category(item: dict, default_category: str) -> str:
    direct = str(item.get("category") or "").strip().lower()
    if direct:
        return direct

    tags = item.get("tags")
    if isinstance(tags, list):
        normalized_tags = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
        if "benign_controls" in normalized_tags or "benign" in normalized_tags:
            return "benign_controls"
        if "tool_abuse" in normalized_tags:
            return "tool_abuse"
        if "jailbreak" in normalized_tags:
            return "jailbreak"
        if "policy_evasion" in normalized_tags:
            return "policy_evasion"

    attack_type = str(item.get("attack_type") or item.get("technique") or "").strip().lower()
    if "jailbreak" in attack_type:
        return "jailbreak"
    if "tool" in attack_type:
        return "tool_abuse"
    if "exfil" in attack_type:
        return "data_exfiltration"

    return default_category


def _infer_expected_decision(item: dict, category: str) -> str:
    explicit = str(item.get("expected_decision") or item.get("expected_verdict") or "").strip().upper()
    if explicit in {"DENIED", "PROCEED", "ERROR"}:
        return explicit

    label = str(item.get("label") or item.get("outcome") or "").strip().lower()
    if label in {"benign", "allow", "allowed", "proceed", "safe"}:
        return "PROCEED"
    if category == "benign_controls":
        return "PROCEED"
    return "DENIED"


def _infer_severity(item: dict, expected_decision: str) -> str:
    explicit = str(item.get("severity") or "").strip().upper()
    if explicit in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return explicit
    return "LOW" if expected_decision == "PROCEED" else "HIGH"


def load_external_corpus_attacks(paths: list[str] | None, *, default_category: str = "prompt_injection") -> list[dict]:
    attacks: list[dict] = []
    seen_payloads: set[str] = set()

    for path_raw in paths or []:
        path = Path(str(path_raw).strip())
        if not path.exists():
            raise FileNotFoundError(f"External corpus file not found: {path}")

        rows = _read_json_rows(path)
        source_name = path.stem

        for index, row in enumerate(rows, 1):
            if isinstance(row, str):
                item = {"payload": row}
            elif isinstance(row, dict):
                item = row
            else:
                continue

            payload = _pick_payload(item)
            if not payload:
                continue

            payload_key = " ".join(payload.split()).strip().lower()
            if payload_key in seen_payloads:
                continue
            seen_payloads.add(payload_key)

            category = _infer_category(item, default_category)
            expected_decision = _infer_expected_decision(item, category)
            severity = _infer_severity(item, expected_decision)

            attacks.append(
                {
                    "id": str(item.get("id") or f"EXT_{source_name.upper()}_{index:04d}"),
                    "name": str(item.get("name") or item.get("title") or f"External corpus attack {index}"),
                    "category": category,
                    "payload": payload,
                    "action": str(item.get("action") or "fetch_data"),
                    "origin": str(item.get("origin") or "external-corpus"),
                    "expected_decision": expected_decision,
                    "severity": severity,
                    "technique": item.get("technique") or item.get("attack_type"),
                    "difficulty": item.get("difficulty") or item.get("level"),
                    "source": f"external_corpus:{source_name}",
                    "variant_kind": str(item.get("variant_kind") or "seed"),
                }
            )

    return attacks
