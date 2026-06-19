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
import pytest

from kit.auth import DashboardAuthConfig, DashboardAuthManager
from kit.dashboard_server import (
    DashboardServerConfig,
    _MODE_STRING_ARGS,
    _build_mode_command,
    _launch_audit,
    _launch_public_repo_audit,
    _normalize_run_entries,
    _parse_basic_auth_header,
    _sanitize_launch_value,
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
    assert "run" not in captured["command"]
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
            "campaign_manifest": None,
            "learning_snapshot": None,
            "mutation_effectiveness": None,
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


def test_dashboard_launch_logs_endpoint_uses_specific_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launch_id = "repo-20260516T010203Z-abcd1234"

    def _fake_launch(config, repo_url, tracker=None):
        launch_root = config.artifact_dir / ".launches" / launch_id
        launch_root.mkdir(parents=True, exist_ok=True)
        (launch_root / "launch.log").write_text("audit started\naudit done\n", encoding="utf-8")
        payload = {
            "ok": True,
            "status": "started",
            "launch_id": launch_id,
            "repo_url": repo_url,
            "resolved_repo_url": "https://github.com/example/public-repo.git",
            "output_path": f".launches/{launch_id}/summary.json",
            "log_path": f".launches/{launch_id}/launch.log",
            "pid": 99999,
            "dashboard": "/dashboard/",
        }
        if tracker is not None:
            tracker.register(launch_id, payload)
        return payload

    monkeypatch.setattr("kit.dashboard_server._launch_public_repo_audit", _fake_launch)

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            headers = {"X-API-Key": "op-key"}
            launch = httpx.post(
                f"{base_url}/api/repo-audit",
                json={"repo_url": "https://github.com/example/public-repo"},
                headers=headers,
            )
            assert launch.status_code == 202

            logs = httpx.get(f"{base_url}/api/launches/{launch_id}/logs", headers=headers)

    assert logs.status_code == 200
    payload = logs.json()
    assert payload["launch_id"] == launch_id
    assert "audit done" in payload["logs"]


def test_dashboard_launch_logs_tail_lines_query(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launch_id = "repo-20260516T010203Z-lines123"

    def _fake_launch(config, repo_url, tracker=None):
        launch_root = config.artifact_dir / ".launches" / launch_id
        launch_root.mkdir(parents=True, exist_ok=True)
        (launch_root / "launch.log").write_text(
            "line-1\nline-2\nline-3\nline-4\nline-5\n",
            encoding="utf-8",
        )
        payload = {
            "ok": True,
            "status": "started",
            "launch_id": launch_id,
            "repo_url": repo_url,
            "resolved_repo_url": "https://github.com/example/public-repo.git",
            "output_path": f".launches/{launch_id}/summary.json",
            "log_path": f".launches/{launch_id}/launch.log",
            "pid": 99999,
            "dashboard": "/dashboard/",
        }
        if tracker is not None:
            tracker.register(launch_id, payload)
        return payload

    monkeypatch.setattr("kit.dashboard_server._launch_public_repo_audit", _fake_launch)

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            headers = {"X-API-Key": "op-key"}
            launch = httpx.post(
                f"{base_url}/api/repo-audit",
                json={"repo_url": "https://github.com/example/public-repo"},
                headers=headers,
            )
            assert launch.status_code == 202

            logs = httpx.get(f"{base_url}/api/launches/{launch_id}/logs?tail_lines=2", headers=headers)

    assert logs.status_code == 200
    payload = logs.json()
    assert payload["tail_lines"] == 2
    assert payload["total_lines"] == 5
    assert payload["truncated"] is True
    assert payload["logs"] == "line-4\nline-5\n"


def test_dashboard_launch_logs_rejects_invalid_tail_lines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launch_id = "repo-20260516T010203Z-badquery"

    def _fake_launch(config, repo_url, tracker=None):
        launch_root = config.artifact_dir / ".launches" / launch_id
        launch_root.mkdir(parents=True, exist_ok=True)
        (launch_root / "launch.log").write_text("audit started\n", encoding="utf-8")
        payload = {
            "ok": True,
            "status": "started",
            "launch_id": launch_id,
            "repo_url": repo_url,
            "resolved_repo_url": "https://github.com/example/public-repo.git",
            "output_path": f".launches/{launch_id}/summary.json",
            "log_path": f".launches/{launch_id}/launch.log",
            "pid": 99999,
            "dashboard": "/dashboard/",
        }
        if tracker is not None:
            tracker.register(launch_id, payload)
        return payload

    monkeypatch.setattr("kit.dashboard_server._launch_public_repo_audit", _fake_launch)

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            headers = {"X-API-Key": "op-key"}
            launch = httpx.post(
                f"{base_url}/api/repo-audit",
                json={"repo_url": "https://github.com/example/public-repo"},
                headers=headers,
            )
            assert launch.status_code == 202

            logs = httpx.get(f"{base_url}/api/launches/{launch_id}/logs?tail_lines=abc", headers=headers)

    assert logs.status_code == 400


def test_dashboard_list_launches_hydrates_from_artifact_directories(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    launch_id = "repo-20260516T010203Z-persisted1"

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(workspace_root, auth_mode="api-key") as base_url:
            launch_root = workspace_root / "runs" / ".launches" / launch_id
            launch_root.mkdir(parents=True, exist_ok=True)
            (launch_root / "launch.log").write_text("line-1\n", encoding="utf-8")
            response = httpx.get(f"{base_url}/api/launches", headers={"X-API-Key": "op-key"})

    assert response.status_code == 200
    payload = response.json()
    launches = payload.get("launches") or []
    launch = next((item for item in launches if item.get("launch_id") == launch_id), None)
    assert launch is not None
    assert launch["mode"] == "repo"
    assert launch["log_path"] == f".launches/{launch_id}/launch.log"


def test_dashboard_launch_status_hydrates_from_artifact_directories(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    launch_id = "repo-20260516T010203Z-persisted2"

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(workspace_root, auth_mode="api-key") as base_url:
            launch_root = workspace_root / "runs" / ".launches" / launch_id
            launch_root.mkdir(parents=True, exist_ok=True)
            (launch_root / "summary.json").write_text("{}", encoding="utf-8")
            response = httpx.get(f"{base_url}/api/launches/{launch_id}", headers={"X-API-Key": "op-key"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["launch_id"] == launch_id
    assert payload["status"] == "completed"
    assert payload["running"] is False


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


# ---------------------------------------------------------------------------
# Multi-mode launch: unit tests
# ---------------------------------------------------------------------------


def test_sanitize_launch_value_rejects_unsafe_input() -> None:
    from kit.dashboard_server import _sanitize_launch_value

    # Valid values pass through unchanged
    assert _sanitize_launch_value("https://example.com") == "https://example.com"
    assert _sanitize_launch_value("medium") == "medium"
    assert _sanitize_launch_value("10") == "10"
    assert _sanitize_launch_value(".") == "."
    assert _sanitize_launch_value("/workspace/repo") == "/workspace/repo"

    # Leading dash → rejected (flag injection)
    assert _sanitize_launch_value("-flag-inject") is None
    assert _sanitize_launch_value("--another-flag") is None

    # Shell metacharacters that are NOT in the allowlist → rejected.
    # (Popen is invoked with a list so the OS never passes values through a
    # shell; however the sanitiser still blocks anything outside the
    # conservative allowlist to provide defence-in-depth.)
    assert _sanitize_launch_value("; rm -rf /") is None   # semicolon
    assert _sanitize_launch_value("$(whoami)") is None    # dollar / parens
    assert _sanitize_launch_value("| cat /etc/passwd") is None  # pipe
    assert _sanitize_launch_value("`id`") is None         # backtick
    assert _sanitize_launch_value("val\x00ue") is None    # null byte
    assert _sanitize_launch_value("foo!bar") is None      # exclamation

    # '&' is intentionally allowed for URL query strings
    # (e.g. "?foo=bar&baz=qux").  Because Popen is called with a list and
    # shell=False, '&' has no shell semantics here.
    assert _sanitize_launch_value("?foo=bar&baz=qux") == "?foo=bar&baz=qux"

    # Empty / None → rejected
    assert _sanitize_launch_value(None) is None
    assert _sanitize_launch_value("") is None
    assert _sanitize_launch_value("   ") is None

    # Overlong string → rejected
    assert _sanitize_launch_value("a" * 2049) is None
    # Exactly at the limit is fine
    assert _sanitize_launch_value("a" * 2048) == "a" * 2048


def test_build_mode_command_allowlists_per_mode(tmp_path: Path) -> None:
    output_path = tmp_path / "out.json"
    artifact_root = tmp_path

    # Known key is forwarded with correct flag
    cmd = _build_mode_command(
        "website",
        {"target_url": "https://example.com", "max_pages": "5"},
        output_path,
        artifact_root,
    )
    assert "--target-url" in cmd
    assert "https://example.com" in cmd
    assert "--max-pages" in cmd
    assert "5" in cmd

    # Unknown keys for this mode are silently ignored
    cmd2 = _build_mode_command(
        "website",
        {"target_url": "https://example.com", "malicious_flag": "evil"},
        output_path,
        artifact_root,
    )
    assert "malicious_flag" not in cmd2
    assert "evil" not in cmd2

    # Unsupported mode raises ValueError
    import pytest
    with pytest.raises(ValueError, match="Unsupported mode"):
        _build_mode_command("unknown_mode", {}, output_path, artifact_root)

    # Every mode in _MODE_STRING_ARGS can be built without error (empty payload)
    for mode in _MODE_STRING_ARGS:
        result = _build_mode_command(mode, {}, output_path, artifact_root)
        assert "--mode" in result
        assert mode in result


def test_build_mode_command_drops_injection_values(tmp_path: Path) -> None:
    output_path = tmp_path / "out.json"
    artifact_root = tmp_path

    unsafe_payloads = [
        {"target_url": "; rm -rf /"},
        {"target_url": "$(cat /etc/shadow)"},
        {"target_url": "| evil"},
        {"max_pages": "-5"},         # starts with dash
        {"max_depth": "--inject"},   # starts with dash
    ]
    for payload in unsafe_payloads:
        cmd = _build_mode_command("website", payload, output_path, artifact_root)
        # No unsafe value should appear in the command
        for v in payload.values():
            assert v not in cmd, f"Unsafe value {v!r} leaked into command"
        # The corresponding flag should also be absent when only that key is given
        # (the flag is only emitted when the sanitised value is not None)
        if list(payload.keys()) == ["target_url"]:
            assert "--target-url" not in cmd


def test_launch_audit_spawns_runner_for_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import sys

    captured: dict = {}

    class FakeProcess:
        pid = 7777

    def _fake_popen(command, cwd, stdout, stderr):
        captured["command"] = command
        captured["cwd"] = cwd
        return FakeProcess()

    monkeypatch.setattr("kit.dashboard_server.subprocess.Popen", _fake_popen)

    config = DashboardServerConfig(
        repo_root=tmp_path,
        artifact_dir=tmp_path / "runs",
        dashboard_file=tmp_path / "dashboard.html",
    )

    result = _launch_audit(
        config,
        "website",
        {"target_url": "https://example.com", "max_pages": "3"},
    )

    # Response shape
    assert result["ok"] is True
    assert result["status"] == "started"
    assert result["mode"] == "website"
    assert result["pid"] == 7777
    assert result["launch_id"].startswith("website-")
    assert "output_path" in result
    assert "log_path" in result
    assert result["dashboard"] == "/dashboard/"

    # Subprocess received a valid kit.runner invocation
    cmd = captured["command"]
    assert cmd[0] == sys.executable
    assert cmd[1:3] == ["-m", "kit.runner"]
    assert "--mode" in cmd and "website" in cmd
    assert "--target-url" in cmd and "https://example.com" in cmd
    assert "--max-pages" in cmd and "3" in cmd

    # Launch directory and log file were created
    launch_root = (tmp_path / "runs" / ".launches" / result["launch_id"])
    assert launch_root.is_dir()
    assert (launch_root / "launch.log").exists()


# ---------------------------------------------------------------------------
# Multi-mode launch: HTTP endpoint integration tests
# ---------------------------------------------------------------------------


def test_api_launch_endpoint_returns_202_for_valid_website_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """POST /api/launch with a valid website payload → 202 Accepted."""

    class FakeProcess:
        pid = 5555

    def _fake_popen(command, cwd, stdout, stderr):
        return FakeProcess()

    monkeypatch.setattr("kit.dashboard_server.subprocess.Popen", _fake_popen)

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            response = httpx.post(
                f"{base_url}/api/launch",
                json={"mode": "website", "target_url": "https://example.com"},
                headers={"X-API-Key": "op-key"},
            )

    assert response.status_code == 202
    body = response.json()
    assert body["ok"] is True
    assert body["mode"] == "website"
    assert body["launch_id"].startswith("website-")
    assert body["pid"] == 5555


def test_api_launch_endpoint_returns_400_for_unknown_mode(tmp_path: Path) -> None:
    """POST /api/launch with an unsupported mode → 400 Bad Request."""
    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            response = httpx.post(
                f"{base_url}/api/launch",
                json={"mode": "totally_fake_mode"},
                headers={"X-API-Key": "op-key"},
            )

    assert response.status_code == 400


def test_api_launch_endpoint_returns_400_for_missing_required_field(tmp_path: Path) -> None:
    """POST /api/launch for website mode without target_url → 400 Bad Request."""
    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            response = httpx.post(
                f"{base_url}/api/launch",
                json={"mode": "website"},
                headers={"X-API-Key": "op-key"},
            )

    assert response.status_code == 400


def test_api_launch_endpoint_old_repo_audit_still_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """/api/repo-audit must remain functional after the /api/launch addition."""

    class FakeProcess:
        pid = 1111

    def _fake_popen(command, cwd, stdout, stderr):
        return FakeProcess()

    monkeypatch.setattr("kit.dashboard_server.subprocess.Popen", _fake_popen)

    with _env_vars({"ALETHEIA_DASHBOARD_API_KEY": "op-key"}):
        with _running_dashboard(tmp_path, auth_mode="api-key") as base_url:
            response = httpx.post(
                f"{base_url}/api/repo-audit",
                json={"repo_url": "https://github.com/example/public-repo"},
                headers={"X-API-Key": "op-key"},
            )

    assert response.status_code == 202
    assert response.json()["status"] == "started"