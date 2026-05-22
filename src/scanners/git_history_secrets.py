from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

ALLOWED_TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".css",
}

SECRET_HISTORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key_literal",
        re.compile(r"(api[_-]?key|token|secret)\s*[:=]\s*['\"]?[a-z0-9_\-]{16,}['\"]?", re.IGNORECASE),
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----"),
    ),
    (
        "password_literal",
        re.compile(r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE),
    ),
]


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in ALLOWED_TEXT_SUFFIXES


def _collect_current_secrets(repo_root: Path) -> set[str]:
    current = set()
    for path in repo_root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or not _is_text_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(repo_root))
        for pattern_name, regex in SECRET_HISTORY_PATTERNS:
            for match in regex.finditer(text):
                evidence = match.group(0).strip()
                current.add(f"{pattern_name}|{rel}|{evidence}")
    return current


def _get_git_command(repo_root: Path, args: list[str], timeout_seconds: int = 30) -> tuple[str, str, int, bool]:
    git_bin = shutil.which("git")
    if not git_bin:
        return "", "", -1, False
    try:
        result = subprocess.run(
            [git_bin] + args,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return result.stdout or "", result.stderr or "", result.returncode, False
    except subprocess.TimeoutExpired as exc:
        return "", str(exc), -1, True


def _parse_git_grep_line(line: str) -> tuple[str, str, int, str] | None:
    parts = line.split(":", 3)
    if len(parts) < 4:
        return None
    commit, path, line_str, text = parts
    try:
        line_no = int(line_str)
    except ValueError:
        return None
    return commit, path, line_no, text


def scan_git_history_secrets(repo_root: Path, history_scan_depth: int = 100) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not (repo_root / ".git").exists():
        return [], {"status": "skipped", "reason": "no_git_repository"}

    git_bin = shutil.which("git")
    if not git_bin:
        return [], {"status": "unavailable", "reason": "git_not_found"}

    stdout, stderr, exit_code, timed_out = _get_git_command(repo_root, ["rev-list", "--all", f"--max-count={history_scan_depth}"])
    if timed_out:
        return [], {"status": "timeout", "reason": "git_rev_list_timed_out"}
    if exit_code != 0:
        return [], {"status": "error", "reason": "git_rev_list_failed", "stderr": stderr.strip()}

    commits = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not commits:
        return [], {"status": "skipped", "reason": "no_commits"}

    current_secrets = _collect_current_secrets(repo_root)
    pattern_text = "|".join(f"({pattern.pattern})" for _, pattern in SECRET_HISTORY_PATTERNS)
    grep_args = ["grep", "-I", "-n", "-E", "-i", pattern_text, "--"] + commits
    stdout, stderr, exit_code, timed_out = _get_git_command(repo_root, grep_args, timeout_seconds=60)
    if timed_out:
        return [], {"status": "timeout", "reason": "git_grep_timed_out"}
    if exit_code not in {0, 1}:
        return [], {"status": "error", "reason": "git_grep_failed", "stderr": stderr.strip()}

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for raw_line in stdout.splitlines():
        parsed = _parse_git_grep_line(raw_line)
        if not parsed:
            continue
        commit, rel_path, line_no, text = parsed
        evidence = text.strip()
        match_type = None
        for pattern_name, regex in SECRET_HISTORY_PATTERNS:
            if regex.search(text):
                match_type = pattern_name
                break
        if not match_type:
            continue

        current_key = f"{match_type}|{rel_path}|{evidence}"
        if current_key in current_secrets:
            continue

        key = (commit, rel_path, line_no, evidence)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "severity": "CRITICAL",
                "type": "removed_secret_history",
                "title": "Removed secret found in git history",
                "file": f"{commit}:{rel_path}",
                "line": line_no,
                "evidence": evidence[:220],
                "recommendation": (
                    "Rotate exposed credentials, remove them from git history, and audit repository history for additional artifacts."
                ),
            }
        )

    return findings, {
        "status": "executed",
        "history_scan_depth": len(commits),
        "removed_secrets": len(findings),
    }
