from __future__ import annotations

import base64
import json
import mimetypes
import os
import subprocess
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from engine.repo_audit.scanner import _normalize_public_github_repo_url


@dataclass(frozen=True)
class DashboardServerConfig:
    repo_root: Path
    artifact_dir: Path
    dashboard_file: Path
    host: str = "127.0.0.1"
    port: int = 8080


def _load_run_index(artifact_dir: Path) -> list[dict[str, object]]:
    index_path = artifact_dir / "index.json"
    if not index_path.exists():
        return []
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []

    entries: list[dict[str, object]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        entries.append(item)
    return entries


def _normalize_run_entries(config: DashboardServerConfig) -> list[dict[str, object]]:
    entries = _load_run_index(config.artifact_dir)
    normalized: list[dict[str, object]] = []
    for item in entries:
        summary_rel = str(item.get("summary") or "").strip()
        command_center_rel = str(item.get("command_center") or "").strip()
        sqlite_rel = str(item.get("sqlite") or "").strip()
        normalized.append(
            {
                "generated_at": item.get("generated_at"),
                "mode": item.get("mode"),
                "summary": f"/runs/{summary_rel}" if summary_rel else None,
                "command_center": f"/runs/{command_center_rel}" if command_center_rel else None,
                "sqlite": f"/runs/{sqlite_rel}" if sqlite_rel else None,
            }
        )
    normalized.sort(key=lambda row: str(row.get("generated_at") or ""))
    return normalized


def _launch_public_repo_audit(config: DashboardServerConfig, repo_url: str) -> dict[str, object]:
    normalized_repo_url = _normalize_public_github_repo_url(repo_url)
    artifact_root = config.artifact_dir.resolve()
    repo_root = config.repo_root.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    launch_id = f"github-{stamp}-{uuid4().hex[:8]}"
    launch_root = artifact_root / ".launches" / launch_id
    launch_root.mkdir(parents=True, exist_ok=True)

    output_path = launch_root / "summary.json"
    log_path = launch_root / "launch.log"
    command = [
        sys.executable,
        "-m",
        "kit.runner",
        "run",
        "--mode",
        "repo",
        "--repo-url",
        normalized_repo_url,
        "--artifact-dir",
        str(artifact_root),
        "--output",
        str(output_path),
        "--cli-only",
    ]

    with open(log_path, "ab") as log_file:
        process = subprocess.Popen(
            command,
            cwd=str(repo_root),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    return {
        "ok": True,
        "status": "started",
        "launch_id": launch_id,
        "repo_url": repo_url,
        "resolved_repo_url": normalized_repo_url,
        "output_path": str(output_path.relative_to(artifact_root)),
        "log_path": str(log_path.relative_to(artifact_root)),
        "pid": process.pid,
        "dashboard": "/dashboard/",
    }


def _dashboard_auth_settings() -> tuple[str, str] | None:
    password = os.environ.get("ALETHEIA_DASHBOARD_PASSWORD")
    if not password:
                return None
    username = os.environ.get("ALETHEIA_DASHBOARD_USERNAME", "aletheia")
    return username, password


def _parse_basic_auth_header(value: str) -> tuple[str, str] | None:
    raw = str(value or "").strip()
    if not raw.lower().startswith("basic "):
        return None
    token = raw.split(None, 1)[1].strip() if " " in raw else ""
    if not token:
        return None
    try:
        decoded = base64.b64decode(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def create_dashboard_handler(config: DashboardServerConfig):
    repo_root = config.repo_root.resolve()
    artifact_root = config.artifact_dir.resolve()
    dashboard_file = config.dashboard_file.resolve()

    class DashboardHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def _require_auth(self) -> bool:
            settings = _dashboard_auth_settings()
            if settings is None:
                return True
            expected_username, expected_password = settings
            provided = _parse_basic_auth_header(self.headers.get("Authorization", ""))
            if provided == (expected_username, expected_password):
                return True
            body = b"Authentication required"
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="Aletheia Dashboard"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False

        def _send_json(self, payload: object, status: int = HTTPStatus.OK) -> None:
            encoded = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _send_file(self, file_path: Path) -> None:
            if not file_path.exists() or not file_path.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return

            mime_type, _ = mimetypes.guess_type(str(file_path))
            payload = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _resolve_run_path(self, path_fragment: str) -> Path | None:
            requested = (artifact_root / path_fragment.lstrip("/")).resolve()
            if os.path.commonpath([str(requested), str(artifact_root)]) != str(artifact_root):
                return None
            return requested

        def do_GET(self) -> None:
            if not self._require_auth():
                return
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/dashboard", "/dashboard/"}:
                self._send_file(dashboard_file)
                return

            if parsed.path == "/api/runs":
                self._send_json({"files": _normalize_run_entries(config)})
                return

            if parsed.path == "/api/health":
                entries = _normalize_run_entries(config)
                self._send_json(
                    {
                        "ok": True,
                        "dashboard": "/dashboard/",
                        "runs_total": len(entries),
                        "latest_run": entries[-1] if entries else None,
                    }
                )
                return

            if parsed.path.startswith("/runs/"):
                run_path = self._resolve_run_path(parsed.path[len("/runs/"):])
                if run_path is None:
                    self.send_error(HTTPStatus.FORBIDDEN, "Invalid artifact path")
                    return
                self._send_file(run_path)
                return

            if parsed.path == "/api/latest":
                entries = _normalize_run_entries(config)
                self._send_json(entries[-1] if entries else {}, status=HTTPStatus.OK)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:
            if not self._require_auth():
                return
            parsed = urlparse(self.path)
            if parsed.path != "/api/repo-audit":
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return

            content_length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                payload = json.loads(raw_body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON body")
                return

            repo_url = str((payload or {}).get("repo_url") or "").strip()
            if not repo_url:
                self.send_error(HTTPStatus.BAD_REQUEST, "repo_url is required")
                return

            try:
                result = _launch_public_repo_audit(config, repo_url)
            except ValueError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            except Exception as exc:  # pragma: no cover - defensive server path
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
                return

            self._send_json(result, status=HTTPStatus.ACCEPTED)

    return DashboardHandler


def serve_dashboard(config: DashboardServerConfig) -> None:
    handler = create_dashboard_handler(config)
    with ThreadingHTTPServer((config.host, config.port), handler) as server:
        server.serve_forever()