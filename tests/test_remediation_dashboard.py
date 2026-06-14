from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from engine.remediation import generate_proposals
from kit.dashboard_server import DashboardServerConfig, create_dashboard_handler
from kit.remediation_store import (
    MANIFEST_FILE,
    SYSTEM_PROMPT_FILE,
    ZERO_TRUST_FILE,
    load_proposals,
    save_proposals,
)


def _bypass_row(rid, technique):
    return {
        "id": rid,
        "technique": technique,
        "category": "agentic_planning_hijack",
        "severity": "CRITICAL",
        "expected_decision": "DENIED",
        "actual_decision": "PROCEED",
    }


@contextmanager
def _running_dashboard(tmp_path: Path):
    artifact_dir = tmp_path / "runs"
    artifact_dir.mkdir()
    dashboard_file = tmp_path / "dashboard.html"
    dashboard_file.write_text("<html><body>dashboard</body></html>", encoding="utf-8")
    handler = create_dashboard_handler(
        DashboardServerConfig(
            repo_root=tmp_path,
            artifact_dir=artifact_dir,
            dashboard_file=dashboard_file,
            host="127.0.0.1",
            port=0,
            auth_mode="disabled",
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", artifact_dir
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_proposals_endpoint_returns_empty_when_none(tmp_path: Path) -> None:
    with _running_dashboard(tmp_path) as (base_url, _artifact_dir):
        response = httpx.get(f"{base_url}/api/remediation/proposals")
    assert response.status_code == 200
    assert response.json() == {"proposals": []}


def test_proposals_endpoint_lists_seeded_proposals(tmp_path: Path) -> None:
    with _running_dashboard(tmp_path) as (base_url, artifact_dir):
        proposals = generate_proposals([_bypass_row("APH_002", "tool_selection_override")])
        save_proposals(artifact_dir, proposals)

        response = httpx.get(f"{base_url}/api/remediation/proposals")
    assert response.status_code == 200
    body = response.json()
    assert len(body["proposals"]) == 1
    assert body["proposals"][0]["technique"] == "tool_selection_override"
    assert body["proposals"][0]["status"] == "pending"


def test_approve_endpoint_applies_and_persists(tmp_path: Path) -> None:
    with _running_dashboard(tmp_path) as (base_url, artifact_dir):
        proposals = generate_proposals([_bypass_row("APH_002", "tool_selection_override")])
        save_proposals(artifact_dir, proposals)
        pid = proposals[0]["proposal_id"]

        response = httpx.post(
            f"{base_url}/api/remediation/approve",
            json={"proposal_id": pid},
        )
        assert response.status_code == 202
        result = response.json()
        assert result["ok"] is True
        assert result["status"] == "approved"

        rdir = artifact_dir / "remediation"
        assert (rdir / SYSTEM_PROMPT_FILE).exists()
        assert (rdir / MANIFEST_FILE).exists()
        assert (rdir / ZERO_TRUST_FILE).exists()
        assert load_proposals(artifact_dir)[0]["status"] == "approved"

        # The follow-up GET reflects the approved status (one-click flow refresh).
        listed = httpx.get(f"{base_url}/api/remediation/proposals").json()
        assert listed["proposals"][0]["status"] == "approved"


def test_approve_endpoint_rejects_missing_proposal_id(tmp_path: Path) -> None:
    with _running_dashboard(tmp_path) as (base_url, _artifact_dir):
        response = httpx.post(f"{base_url}/api/remediation/approve", json={})
    assert response.status_code == 400


def test_approve_endpoint_unknown_proposal_returns_404(tmp_path: Path) -> None:
    with _running_dashboard(tmp_path) as (base_url, _artifact_dir):
        response = httpx.post(
            f"{base_url}/api/remediation/approve",
            json={"proposal_id": "REM-deadbeef"},
        )
    assert response.status_code == 404
