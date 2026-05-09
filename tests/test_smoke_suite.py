from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kit import runner


class _SmokeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path in {"/", ""}:
            body = b"<html><head><title>Home</title></head><body><a href='/pricing'>Pricing</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/pricing":
            body = b"<html><head><title>Pricing</title></head><body>Plans</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/dashboard":
            body = b"unauthorized"
            self.send_response(401)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()


@pytest.fixture()
def smoke_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SmokeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_repo_dependency_cli_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (repo_dir / "pip-audit-report.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "urllib3",
                        "version": "1.26.4",
                        "vulns": [
                            {
                                "id": "PYSEC-SMOKE-1",
                                "description": "Smoke dependency advisory",
                                "fix_versions": ["1.26.5"],
                            }
                        ],
                    }
                ]
            }
        )
    )
    output = tmp_path / "repo_summary.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "repo",
            "--repo-path",
            str(repo_dir),
            "--deps-scan",
            "auto",
            "--output",
            str(output),
        ],
    )

    rc = runner.cli()
    summary = json.loads(output.read_text())

    assert rc == 0
    assert summary["mode"] == "repo"
    assert summary["dependencies"]["findings_total"] >= 1
    assert summary["findings_by_type"].get("dependency_vulnerability", 0) >= 1


def test_website_routes_cli_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path, smoke_site: str) -> None:
    output = tmp_path / "website_summary.json"

    monkeypatch.setattr(
        "kit.web_audit.runner._run_playwright_audit",
        lambda config: (_ for _ in ()).throw(RuntimeError("playwright unavailable in smoke")),
    )
    monkeypatch.setattr(
        "kit.web_audit.runner.run_prompt_injection_tests",
        lambda **kwargs: {"active_tests": [], "findings": []},
    )
    monkeypatch.setattr(
        "kit.web_audit.runner.run_signature_check",
        lambda **kwargs: {"active_tests": [], "findings": []},
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "website",
            "--target-url",
            smoke_site,
            "--required-route",
            "/",
            "--required-route",
            "/pricing",
            "--protected-route",
            "/dashboard",
            "--output",
            str(output),
        ],
    )

    rc = runner.cli()
    summary = json.loads(output.read_text())

    assert rc == 0
    assert summary["audit_backend"] == "http_fallback"
    assert summary["required_routes_failed"] == []
    assert summary["gates"]["pass"] is True
    assert summary["findings_by_type"].get("auth_bypass", 0) == 0
    assert any(
        test.get("type") == "auth_bypass" and test.get("test_name") == "/dashboard" and test.get("result") == "blocked"
        for test in summary["active_tests"]
    )