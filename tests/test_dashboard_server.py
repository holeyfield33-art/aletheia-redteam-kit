from __future__ import annotations

import base64
import json
import os
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

import bcrypt
import httpx

from kit.auth import DashboardAuthConfig, DashboardAuthManager
from kit.dashboard_server import (
    DashboardServerConfig,
    _launch_public_repo_audit,
    _normalize_run_entries,
    _parse_basic_auth_header,
    create_dashboard_handler,
)
from tests.test_fixtures import TEST_DASHBOARD_SESSION_SECRET, TEST_PASSWORD, TEST_USERNAME


def test_parse_basic_auth_header_round_trips_credentials() -> None:
    token = base64.b64encode(b"aletheia:secret").decode("ascii")
    assert _parse_basic_auth_header(f"Basic {token}") == ("aletheia", "secret")


def test_launch_public_repo_audit_builds_runner_command(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    class FakeProcess:
        pid = 4242

    def _fake_popen(command, cwd, stdout, stderr):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["stdout_name"] = getattr(stdout, "name", "")
        captured["stderr"] = stderr
        return FakeProcess()

    monkeypatch.setattr("kit.dashboard_server.subprocess.Popen", _fake_popen)

    config = DashboardServerConfig(
        repo_root=tmp_path,
        artifact_dir=tmp_path / "runs",
        dashboard_file=tmp_path / "dashboard/index.html",
    )

    result = _launch_public_repo_audit(config, "https://github.com/example/public-repo")

    assert result["status"] == "started"
    assert result["resolved_repo_url"] == "https://github.com/example/public-repo.git"
    assert result["pid"] == 4242
    assert "--repo-url" in captured["command"]
    assert captured["cwd"] == str(tmp_path.resolve())
    assert (tmp_path / "runs" / ".launches").exists()


def test_normalize_run_entries_emits_hosted_artifact_urls(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "runs"
    artifact_dir.mkdir()
    (artifact_dir / "index.json").write_text(
        json.dumps(
            [
                {
                    "generated_at": "2026-05-07T00:00:00+00:00",
                    "mode": "combined",
                    "summary": "run-combined-1/summary.json",
                    "command_center": "run-combined-1/command_center.json",
                    "sqlite": "run-combined-1/command_center.sqlite",
                }
            ]
        ),
        encoding="utf-8",
    )

    entries = _normalize_run_entries(
        DashboardServerConfig(
            repo_root=tmp_path,
            artifact_dir=artifact_dir,
            dashboard_file=tmp_path / "dashboard/index.html",
        )
    )

    assert entries == [
        {
            "generated_at": "2026-05-07T00:00:00+00:00",
            "mode": "combined",
            "summary": "/runs/run-combined-1/summary.json",
            "command_center": "/runs/run-combined-1/command_center.json",
            "sqlite": "/runs/run-combined-1/command_center.sqlite",
        }
    ]


@contextmanager
def _env_vars(values: dict[str, str | None]):
    previous = {key: os.environ.get(key) for key in values}
    try:
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def _running_dashboard(tmp_path: Path, *, auth_mode: str = "auto"):
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
            auth_mode=auth_mode,
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        yield base_url
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_dashboard_health_endpoint_is_exempt_from_auth(tmp_path: Path) -> None:
    with _env_vars(
        {
            "ALETHEIA_DASHBOARD_PASSWORD": TEST_PASSWORD,
            "ALETHEIA_DASHBOARD_USERNAME": TEST_USERNAME,
        }
    ):
        with _running_dashboard(tmp_path, auth_mode="basic") as base_url:
            response = httpx.get(f"{base_url}/api/health")

    assert response.status_code == 200
    assert response.json()["auth_mode"] == "basic"


def test_dashboard_basic_login_sets_session_and_protects_routes(tmp_path: Path) -> None:
    with _env_vars(
        {
            "ALETHEIA_DASHBOARD_PASSWORD": TEST_PASSWORD,
            "ALETHEIA_DASHBOARD_USERNAME": TEST_USERNAME,
            "ALETHEIA_DASHBOARD_SESSION_SECRET": TEST_DASHBOARD_SESSION_SECRET,
        }
    ):
        with _running_dashboard(tmp_path, auth_mode="basic") as base_url:
            with httpx.Client(base_url=base_url, follow_redirects=False) as client:
                response = client.get("/dashboard/")
                assert response.status_code == 303
                assert response.headers["location"].startswith("/login")

                login_page = client.get("/login")
                assert login_page.status_code == 200
                assert "Operator Login" in login_page.text

                login = client.post(
                    "/login",
                    data={"username": TEST_USERNAME, "password": TEST_PASSWORD, "next": "/dashboard/"},
                )
                assert login.status_code == 303
                assert login.headers["location"] == "/dashboard/"
                assert "aletheia_dashboard_session" in login.headers.get("set-cookie", "")

                protected_response = client.get("/api/runs")
                assert protected_response.status_code == 200

                logout = client.post("/logout")
                assert logout.status_code == 303
                assert logout.headers["location"] == "/login"


def test_dashboard_api_key_mode_requires_header(tmp_path: Path) -> None:
    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            unauthorized = httpx.get(f"{base_url}/api/runs")
            authorized = httpx.get(f"{base_url}/api/runs", headers={"X-API-Key": "op-key"})

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_dashboard_api_rate_limit_applies_to_authenticated_requests(tmp_path: Path) -> None:
    with _env_vars(
        {
            "ALETHEIA_DASHBOARD_API_KEY": "op-key",
            "ALETHEIA_DASHBOARD_RATE_LIMIT_PER_MINUTE": "2",
        }
    ):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            headers = {"X-API-Key": "op-key"}
            first = httpx.get(f"{base_url}/api/runs", headers=headers)
            second = httpx.get(f"{base_url}/api/runs", headers=headers)
            third = httpx.get(f"{base_url}/api/runs", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error"] == "rate_limit_exceeded"


def test_dashboard_rejects_runs_path_traversal(tmp_path: Path) -> None:
    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            response = httpx.get(
                f"{base_url}/runs/%2e%2e/README.md",
                headers={"X-API-Key": "op-key"},
            )

    assert response.status_code in {403, 404}


def test_auth_manager_locks_after_repeated_login_failures() -> None:
    current_time = {"value": 0.0}
    manager = DashboardAuthManager(
        DashboardAuthConfig(
            mode="basic",
            username=TEST_USERNAME,
            password_hash=bcrypt.hashpw(TEST_PASSWORD.encode("utf-8"), bcrypt.gensalt(rounds=12)),
            api_key_header="X-API-Key",
            api_key_hash=None,
            session_secret="secret",
            session_cookie_name="aletheia_dashboard_session",
            session_ttl_seconds=3600,
            secure_cookies=False,
            trust_proxy_headers=False,
            proxy_user_header="X-Forwarded-User",
            proxy_authorization_header="Authorization",
            rate_limit_attempts=2,
            rate_limit_window_seconds=900,
            lockout_seconds=600,
        ),
        now_fn=lambda: current_time["value"],
    )

    first = manager.authenticate_login(username=TEST_USERNAME, password="wrong", client_ip="127.0.0.1")
    second = manager.authenticate_login(username=TEST_USERNAME, password="wrong", client_ip="127.0.0.1")
    third = manager.authenticate_login(username=TEST_USERNAME, password="wrong", client_ip="127.0.0.1")

    assert first.status == 401
    assert second.status == 429
    assert third.status == 429
    assert third.retry_after == 600


def test_auth_manager_accepts_proxy_identity_headers() -> None:
    manager = DashboardAuthManager(
        DashboardAuthConfig(
            mode="proxy",
            username=None,
            password_hash=None,
            api_key_header="X-API-Key",
            api_key_hash=None,
            session_secret="",
            session_cookie_name="aletheia_dashboard_session",
            session_ttl_seconds=3600,
            secure_cookies=True,
            trust_proxy_headers=True,
            proxy_user_header="X-Forwarded-User",
            proxy_authorization_header="Authorization",
            rate_limit_attempts=5,
            rate_limit_window_seconds=900,
            lockout_seconds=900,
        )
    )

    outcome = manager.authenticate_request(headers={"X-Forwarded-User": "operator@example.com"}, client_ip="127.0.0.1")

    assert outcome.allowed is True
    assert outcome.principal == "operator@example.com"