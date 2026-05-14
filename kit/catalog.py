"""Attack catalog models and providers."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ATTACK_DIR = Path(__file__).parent.parent / "attacks"
_VALID_EXPECTED_DECISIONS = {"DENIED", "PROCEED", "ERROR"}


@dataclass(frozen=True)
class AttackSpec:
    """Canonical attack record with backward-compatible fields."""

    id: str
    name: str
    category: str
    payload: str
    action: str
    origin: str
    expected_decision: str
    severity: str
    notes: str | None = None
    expected_verdict: str | None = None
    risk_category: str | None = None
    technique: str | None = None
    difficulty: str | None = None
    source: str | None = None

    @classmethod
    def from_dict(cls, item: dict, *, default_category: str | None = None) -> "AttackSpec":
        required = ["id", "name", "payload"]
        missing = [field for field in required if not item.get(field)]
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"Attack is missing required fields: {joined}")

        category = str(item.get("category") or default_category or "").strip()
        if not category:
            raise ValueError("Attack is missing required field: category")

        expected_decision = str(item.get("expected_decision") or item.get("expected_verdict") or "").strip().upper()
        if expected_decision not in _VALID_EXPECTED_DECISIONS:
            allowed = ", ".join(sorted(_VALID_EXPECTED_DECISIONS))
            raise ValueError(f"Attack '{item.get('id', '<unknown>')}' expected decision must be one of: {allowed}")

        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            category=category,
            payload=str(item["payload"]),
            action=str(item.get("action", "fetch_data")),
            origin=str(item.get("origin", "redteam-kit")),
            expected_decision=expected_decision,
            severity=str(item.get("severity", "MEDIUM")),
            notes=item.get("notes"),
            expected_verdict=item.get("expected_verdict"),
            risk_category=item.get("risk_category"),
            technique=item.get("technique"),
            difficulty=item.get("difficulty"),
            source=item.get("source"),
        )

    def to_dict(self) -> dict:
        """Serialize to dict preserving legacy expected_decision for runner compatibility."""
        out = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "payload": self.payload,
            "action": self.action,
            "origin": self.origin,
            "expected_decision": self.expected_decision,
            "severity": self.severity,
        }
        if self.notes is not None:
            out["notes"] = self.notes
        if self.expected_verdict is not None:
            out["expected_verdict"] = self.expected_verdict
        if self.risk_category is not None:
            out["risk_category"] = self.risk_category
        if self.technique is not None:
            out["technique"] = self.technique
        if self.difficulty is not None:
            out["difficulty"] = self.difficulty
        if self.source is not None:
            out["source"] = self.source
        return out


class CatalogProvider(ABC):
    """Provider interface for fetching attacks from different backends."""

    @abstractmethod
    def fetch_attacks(self, category: str | None = None) -> list[AttackSpec]:
        raise NotImplementedError


class FileSystemCatalogProvider(CatalogProvider):
    """Load attacks from local JSON files in attacks/ directory."""

    def __init__(self, attack_dir: Path = DEFAULT_ATTACK_DIR) -> None:
        self.attack_dir = attack_dir

    def _resolve_files(self, category: str | None = None) -> list[Path]:
        if category:
            matches = sorted(self.attack_dir.glob(f"**/{category}.json"))
            if not matches:
                raise FileNotFoundError(f"Attack catalog not found for category: {category}")
            return matches
        return sorted(path for path in self.attack_dir.glob("**/*.json") if path.is_file())

    def fetch_attacks(self, category: str | None = None) -> list[AttackSpec]:
        files = self._resolve_files(category)
        attacks: list[AttackSpec] = []

        for path in files:
            category_name = path.stem
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError(f"Attack catalog must contain a JSON array: {path}")

            for idx, item in enumerate(raw, 1):
                if not isinstance(item, dict):
                    raise ValueError(f"Attack #{idx} in {path} must be a JSON object")
                attacks.append(AttackSpec.from_dict(item, default_category=category_name))

        return attacks


def _load_feed_attacks(path: Path) -> list[AttackSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"Threat feed payload catalog must contain a JSON array: {path}")

    attacks: list[AttackSpec] = []
    for idx, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Threat feed attack #{idx} in {path} must be a JSON object")
        attacks.append(AttackSpec.from_dict(item, default_category="threat_feed"))
    return attacks


def load_attacks(
    category: str | None = None,
    provider: CatalogProvider | None = None,
    threat_feed_file: str | None = None,
) -> list[dict]:
    """Backwards-compatible helper returning dict records for existing runner flow."""
    chosen_provider = provider or FileSystemCatalogProvider()
    attacks = chosen_provider.fetch_attacks(category)

    if threat_feed_file:
        attacks.extend(_load_feed_attacks(Path(threat_feed_file)))

    return [attack.to_dict() for attack in attacks]