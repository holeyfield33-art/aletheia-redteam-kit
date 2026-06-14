"""
Persistence + apply layer for auto-remediation proposals.

Stores proposals under ``<artifact_dir>/remediation/`` and, on approval, writes
the approved artifacts into reviewable patch files:

  - proposals.json          : proposal state (status: pending|approved)
  - system_prompt_patch.md  : appended guardrail clauses
  - manifest_rules.json     : signed-manifest rule set
  - zero_trust_policy.json   : expected_block contracts for run_security_gates

No live config is mutated — these are new artifact files for human review and
for feeding back into the next gate run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from engine.remediation import (
    merge_manifest,
    merge_zero_trust_policy,
    render_system_prompt_clause,
)

REMEDIATION_DIRNAME = "remediation"
PROPOSALS_FILE = "proposals.json"
SYSTEM_PROMPT_FILE = "system_prompt_patch.md"
MANIFEST_FILE = "manifest_rules.json"
ZERO_TRUST_FILE = "zero_trust_policy.json"


def remediation_dir(artifact_dir: Path) -> Path:
    return Path(artifact_dir) / REMEDIATION_DIRNAME


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_proposals(artifact_dir: Path) -> list[dict]:
    data = _read_json(remediation_dir(artifact_dir) / PROPOSALS_FILE, {"proposals": []})
    proposals = data.get("proposals") if isinstance(data, dict) else data
    return list(proposals or [])


def save_proposals(artifact_dir: Path, proposals: list[dict]) -> Path:
    """Persist proposals, preserving status of any already-approved entries."""
    existing = {p["proposal_id"]: p for p in load_proposals(artifact_dir)}
    merged: list[dict] = []
    for proposal in proposals:
        prior = existing.get(proposal["proposal_id"])
        if prior and prior.get("status") == "approved":
            entry = dict(proposal)
            entry["status"] = "approved"
            entry["approved_at"] = prior.get("approved_at")
            merged.append(entry)
        else:
            merged.append(proposal)
    out = remediation_dir(artifact_dir) / PROPOSALS_FILE
    _write_json(out, {"proposals": merged, "generated_at": datetime.now(timezone.utc).isoformat()})
    return out


def _append_system_prompt_clause(rdir: Path, proposal: dict) -> None:
    path = rdir / SYSTEM_PROMPT_FILE
    clause = render_system_prompt_clause(proposal)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if clause in existing:
            return
        body = existing.rstrip("\n") + "\n" + clause + "\n"
    else:
        body = "# Remediation system-prompt constraints\n\n" + clause + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def apply_proposal(artifact_dir: Path, proposal_id: str) -> dict:
    """Mark a proposal approved and write its three artifacts. Idempotent."""
    proposals = load_proposals(artifact_dir)
    target = next((p for p in proposals if p["proposal_id"] == proposal_id), None)
    if target is None:
        return {"ok": False, "reason": "proposal_not_found", "proposal_id": proposal_id}

    rdir = remediation_dir(artifact_dir)

    # System-prompt patch (append).
    _append_system_prompt_clause(rdir, target)

    # Manifest rules (merge, idempotent by rule_id).
    manifest = _read_json(rdir / MANIFEST_FILE, {"rules": []})
    _write_json(rdir / MANIFEST_FILE, merge_manifest(manifest, target))

    # Zero-trust policy (merge, idempotent by technique).
    policy = _read_json(rdir / ZERO_TRUST_FILE, {"probes": []})
    _write_json(rdir / ZERO_TRUST_FILE, merge_zero_trust_policy(policy, target))

    # Update proposal status.
    target["status"] = "approved"
    target["approved_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(
        rdir / PROPOSALS_FILE,
        {"proposals": proposals, "generated_at": datetime.now(timezone.utc).isoformat()},
    )

    return {
        "ok": True,
        "proposal_id": proposal_id,
        "status": "approved",
        "artifacts_written": [SYSTEM_PROMPT_FILE, MANIFEST_FILE, ZERO_TRUST_FILE],
    }
