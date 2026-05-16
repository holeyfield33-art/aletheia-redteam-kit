from __future__ import annotations

import base64
from collections import deque
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import logging
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse
from uuid import uuid4

from engine.repo_audit.scanner import _normalize_public_github_repo_url
from kit.auth import DashboardAuthManager, sanitize_next_path

LOGGER = logging.getLogger(__name__)
LAUNCH_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_LAUNCH_LOG_TAIL_LINES = 400
MAX_LAUNCH_LOG_TAIL_LINES = 5000


class ProcessTracker:
    """Track subprocess launches and their status."""
    
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: dict[str, dict] = {}
    
    def register(self, launch_id: str, process_meta: dict) -> None:
        """Register a subprocess launch."""
        with self._lock:
            self._processes[launch_id] = {
                **process_meta,
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }
    
    def get_status(self, launch_id: str) -> dict | None:
        """Get status of a launch."""
        with self._lock:
            meta = self._processes.get(launch_id)
            if not meta:
                return None
            
            status = dict(meta)
            pid = status.get("pid")
            
            # Check if process is still running
            if pid is not None:
                try:
                    os.kill(pid, 0)  # Signal 0 = check if process exists
                    status["running"] = True
                except (OSError, ProcessLookupError):
                    status["running"] = False
            
            return status
    
    def list_launches(self) -> list[dict]:
        """List all tracked launches."""
        with self._lock:
            return list(self._processes.values())
    
    def terminate(self, launch_id: str) -> bool:
        """Terminate a process if still running."""
        with self._lock:
            meta = self._processes.get(launch_id)
            if not meta:
                return False
            
            pid = meta.get("pid")
            if pid is None:
                return False
            
            try:
                os.kill(pid, 15)  # SIGTERM
                meta["terminated_at"] = datetime.now(timezone.utc).isoformat()
                return True
            except (OSError, ProcessLookupError):
                return False


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _sanitize_repo_url_input(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("repo_url is required")
    if len(candidate) > 512:
        raise ValueError("repo_url is too long")
    if _has_control_chars(candidate):
        raise ValueError("repo_url contains invalid characters")
    return candidate


def _parse_tail_lines(query: str) -> int:
    raw = parse_qs(query).get("tail_lines", [str(DEFAULT_LAUNCH_LOG_TAIL_LINES)])[0]
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise ValueError("tail_lines must be an integer") from exc
    if value <= 0:
        raise ValueError("tail_lines must be greater than zero")
    return min(value, MAX_LAUNCH_LOG_TAIL_LINES)


def _read_log_tail(log_path: Path, *, tail_lines: int) -> tuple[str, int]:
    buffer: deque[str] = deque(maxlen=max(1, int(tail_lines)))
    total_lines = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            buffer.append(line)
            total_lines += 1
    return "".join(buffer), total_lines


class _RequestRateLimiter:
    def __init__(self, *, requests_per_minute: int, now_fn=time.time) -> None:
        self._limit = max(1, int(requests_per_minute))
        self._now_fn = now_fn
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        now = float(self._now_fn())
        key = str(key or "unknown")
        with self._lock:
            window_start, count = self._windows.get(key, (now, 0))
            elapsed = now - window_start
            if elapsed >= 60:
                window_start = now
                count = 0
            count += 1
            self._windows[key] = (window_start, count)
            if count <= self._limit:
                return True, 0
            retry_after = max(1, int(60 - elapsed))
            return False, retry_after


@dataclass(frozen=True)
class DashboardServerConfig:
    repo_root: Path
    artifact_dir: Path
    dashboard_file: Path
    host: str = "127.0.0.1"
    port: int = 8080
    auth_mode: str = "auto"


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


def _launch_public_repo_audit(config: DashboardServerConfig, repo_url: str, tracker: ProcessTracker | None = None) -> dict[str, object]:
    normalized_repo_url = _normalize_public_github_repo_url(_sanitize_repo_url_input(repo_url))
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

    result = {
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
    
    # Register with tracker
    if tracker:
        tracker.register(launch_id, result)
    
    return result


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
    auth_manager = DashboardAuthManager.from_env(auth_mode=config.auth_mode, host=config.host)
    auth_manager.log_startup_warnings()
    request_rate_limiter = _RequestRateLimiter(
        requests_per_minute=int(os.environ.get("ALETHEIA_DASHBOARD_RATE_LIMIT_PER_MINUTE", "30"))
    )
    process_tracker = ProcessTracker()

    def _parse_launch_id(path: str, *, suffix: str | None = None) -> str | None:
        base_prefix = "/api/launches/"
        if not path.startswith(base_prefix):
            return None
        remainder = path[len(base_prefix):]
        if suffix is not None:
            if not remainder.endswith(suffix):
                return None
            remainder = remainder[: -len(suffix)]
        launch_id = remainder.rstrip("/")
        if not launch_id or "/" in launch_id:
            return None
        if not LAUNCH_ID_PATTERN.fullmatch(launch_id):
            return None
        return launch_id

    def _render_login_page(*, next_path: str, error: str | None = None) -> bytes:
        status = f'<p class="status">{error}</p>' if error else ""
        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Aletheia Dashboard Login</title>
    <style>
      body {{ background: #0b0b0c; color: #f4f4f5; font-family: ui-sans-serif, system-ui, sans-serif; }}
      main {{ max-width: 26rem; margin: 6rem auto; padding: 2rem; border: 1px solid #27272a; border-radius: 1rem; background: #111113; }}
      h1 {{ margin: 0 0 0.5rem; font-size: 1.5rem; }}
      p {{ color: #a1a1aa; }}
      label {{ display: block; margin-top: 1rem; font-size: 0.95rem; }}
      input {{ width: 100%; margin-top: 0.35rem; padding: 0.75rem; border-radius: 0.75rem; border: 1px solid #3f3f46; background: #09090b; color: inherit; }}
      button {{ width: 100%; margin-top: 1.25rem; padding: 0.8rem; border: 0; border-radius: 999px; background: #15803d; color: white; font-weight: 700; cursor: pointer; }}
      .status {{ color: #fca5a5; }}
    </style>
  </head>
  <body>
    <main>
      <h1>Operator Login</h1>
      <p>Authenticate to access hosted dashboard artifacts and control-plane APIs.</p>
      {status}
      <form method="post" action="/login">
        <input type="hidden" name="next" value="{next_path}" />
        <label>Username<input name="username" autocomplete="username" required /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        <button type="submit">Sign in</button>
      </form>
    </main>
  </body>
</html>""".encode("utf-8")

    class DashboardHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def _client_ip(self) -> str:
            return str((self.client_address or ["unknown"])[0])

        def _is_exempt_path(self, path: str) -> bool:
            return path == "/api/health" or path == "/login"

        def _wants_html(self) -> bool:
            accept = str(self.headers.get("Accept", "")).lower()
            return "text/html" in accept or accept in {"", "*/*"}

        def _authorize(self, *, path: str) -> bool:
            if self._is_exempt_path(path):
                return True

            outcome = auth_manager.authenticate_request(headers=self.headers, client_ip=self._client_ip())
            limiter_key = outcome.principal if outcome.allowed and outcome.principal else self._client_ip()
            allowed, retry_after = request_rate_limiter.allow(str(limiter_key))
            if not allowed:
                payload = {"ok": False, "error": "rate_limit_exceeded"}
                self._send_json(
                    payload,
                    status=HTTPStatus.TOO_MANY_REQUESTS,
                    extra_headers={"Retry-After": str(retry_after)},
                )
                return False
            if outcome.allowed:
                return True

            if auth_manager.config.mode == "basic" and not path.startswith("/api/") and self._wants_html():
                target = sanitize_next_path(path)
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", f"/login?next={quote(target, safe='/')}")
                self.end_headers()
                return False

            payload = {"ok": False, "error": outcome.reason}
            self._send_json(payload, status=outcome.status, extra_headers=self._auth_headers(outcome))
            return False

        def _auth_headers(self, outcome) -> dict[str, str]:
            headers: dict[str, str] = {}
            if outcome.challenge:
                headers["WWW-Authenticate"] = outcome.challenge
            if outcome.retry_after is not None:
                headers["Retry-After"] = str(outcome.retry_after)
            return headers

        def _send_json(self, payload: object, status: int = HTTPStatus.OK, extra_headers: dict[str, str] | None = None) -> None:
            encoded = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)

        def _send_html(self, payload: bytes, status: int = HTTPStatus.OK, extra_headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

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
            if ".." in path_fragment or _has_control_chars(path_fragment):
                return None
            requested = (artifact_root / path_fragment.lstrip("/")).resolve()
            if os.path.commonpath([str(requested), str(artifact_root)]) != str(artifact_root):
                return None
            return requested

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                if auth_manager.config.mode != "basic":
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                    return
                if auth_manager.authenticate_request(headers=self.headers, client_ip=self._client_ip()).allowed:
                    self.send_response(HTTPStatus.SEE_OTHER)
                    self.send_header("Location", sanitize_next_path(parse_qs(parsed.query).get("next", ["/dashboard/"])[0]))
                    self.end_headers()
                    return
                next_path = sanitize_next_path(parse_qs(parsed.query).get("next", ["/dashboard/"])[0])
                self._send_html(_render_login_page(next_path=next_path))
                return

            if parsed.path == "/logout":
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/login")
                self.send_header("Set-Cookie", auth_manager.build_logout_cookie_header())
                self.end_headers()
                return

            if not self._authorize(path=parsed.path):
                return

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
                        "auth_mode": auth_manager.config.mode,
                        "auth_enabled": auth_manager.config.enabled,
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

            # Process tracking endpoints
            if parsed.path == "/api/launches":
                launches = process_tracker.list_launches()
                self._send_json({"launches": launches})
                return

            if parsed.path.startswith("/api/launches/") and parsed.path.endswith("/logs"):
                launch_id = _parse_launch_id(parsed.path, suffix="/logs")
                if launch_id is None:
                    self.send_error(HTTPStatus.BAD_REQUEST, "invalid launch_id")
                    return
                try:
                    tail_lines = _parse_tail_lines(parsed.query)
                except ValueError as exc:
                    self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                log_path = self._resolve_run_path(f".launches/{launch_id}/launch.log")
                if log_path is None or not log_path.exists():
                    self.send_error(HTTPStatus.NOT_FOUND, "Log not found")
                    return

                try:
                    logs, total_lines = _read_log_tail(log_path, tail_lines=tail_lines)
                    self._send_json(
                        {
                            "launch_id": launch_id,
                            "logs": logs,
                            "tail_lines": tail_lines,
                            "total_lines": total_lines,
                            "truncated": total_lines > tail_lines,
                        }
                    )
                except IOError as exc:
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Failed to read logs: {exc}")
                return

            if parsed.path.startswith("/api/launches/"):
                launch_id = _parse_launch_id(parsed.path)
                if launch_id is None:
                    self.send_error(HTTPStatus.BAD_REQUEST, "invalid launch_id")
                    return

                status = process_tracker.get_status(launch_id)
                if status is None:
                    self.send_error(HTTPStatus.NOT_FOUND, "Launch not found")
                    return

                self._send_json(status)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                if auth_manager.config.mode != "basic":
                    self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                    return
                content_length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
                form = parse_qs(raw_body, keep_blank_values=True)
                username = str(form.get("username", [""])[0])
                password = str(form.get("password", [""])[0])
                next_path = sanitize_next_path(form.get("next", ["/dashboard/"])[0])
                outcome = auth_manager.authenticate_login(
                    username=username,
                    password=password,
                    client_ip=self._client_ip(),
                )
                if outcome.allowed and outcome.principal is not None:
                    self.send_response(HTTPStatus.SEE_OTHER)
                    self.send_header("Location", next_path)
                    self.send_header("Set-Cookie", auth_manager.build_set_cookie_header(auth_manager.create_session_cookie(outcome.principal)))
                    self.end_headers()
                    return
                error = "Too many attempts. Try again later." if outcome.status == HTTPStatus.TOO_MANY_REQUESTS else "Invalid username or password."
                extra_headers = self._auth_headers(outcome)
                self._send_html(_render_login_page(next_path=next_path, error=error), status=outcome.status, extra_headers=extra_headers)
                return

            if parsed.path == "/logout":
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/login")
                self.send_header("Set-Cookie", auth_manager.build_logout_cookie_header())
                self.end_headers()
                return

            if not self._authorize(path=parsed.path):
                return
            
            # Handle launch cancellation
            if parsed.path.startswith("/api/launches/") and parsed.path.endswith("/cancel"):
                launch_id = _parse_launch_id(parsed.path, suffix="/cancel")
                if launch_id is None:
                    self.send_error(HTTPStatus.BAD_REQUEST, "invalid launch_id")
                    return
                
                success = process_tracker.terminate(launch_id)
                if not success:
                    self.send_error(HTTPStatus.NOT_FOUND, "Launch not found or already completed")
                    return
                
                self._send_json({"ok": True, "launch_id": launch_id, "status": "terminated"})
                return
            
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

            repo_url = _sanitize_repo_url_input(str((payload or {}).get("repo_url") or ""))
            if not repo_url:
                self.send_error(HTTPStatus.BAD_REQUEST, "repo_url is required")
                return

            try:
                result = _launch_public_repo_audit(config, repo_url, tracker=process_tracker)
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
        LOGGER.warning(
            "dashboard.server.security tls=required reverse_proxy=recommended auth_mode=%s",
            config.auth_mode,
        )
        if config.auth_mode == "disabled":
            LOGGER.warning(
                "dashboard.server.security auth disabled: exposure outside trusted internal networks is unsafe"
            )
        LOGGER.info(
            "dashboard.server.start host=%s port=%s auth_mode=%s",
            config.host,
            config.port,
            config.auth_mode,
        )
        server.serve_forever()