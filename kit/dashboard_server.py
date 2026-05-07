from __future__ import annotations

import json
import mimetypes
import os
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


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


def create_dashboard_handler(config: DashboardServerConfig):
    repo_root = config.repo_root.resolve()
    artifact_root = config.artifact_dir.resolve()
    dashboard_file = config.dashboard_file.resolve()

    class DashboardHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

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

    return DashboardHandler


def serve_dashboard(config: DashboardServerConfig) -> None:
    handler = create_dashboard_handler(config)
    with ThreadingHTTPServer((config.host, config.port), handler) as server:
        server.serve_forever()