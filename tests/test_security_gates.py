from __future__ import annotations

from pathlib import Path

from scripts import run_security_gates


def _patch_binary_absent(monkeypatch) -> None:
    """Make _find_binary return None for any name regardless of PATH or venv."""
    monkeypatch.setattr(run_security_gates, "which", lambda name: None)
    monkeypatch.setattr(run_security_gates, "_find_binary", lambda name: None)


def test_run_trufflehog_missing_binary_returns_empty_findings(monkeypatch, tmp_path: Path) -> None:
    _patch_binary_absent(monkeypatch)

    findings = run_security_gates._run_trufflehog(tmp_path, [])

    assert findings == []


def test_run_semgrep_missing_binary_returns_empty_findings(monkeypatch, tmp_path: Path) -> None:
    _patch_binary_absent(monkeypatch)

    findings = run_security_gates._run_semgrep(tmp_path, tmp_path / "rules.yml", [])

    assert findings == []


def test_find_binary_falls_back_to_venv(monkeypatch, tmp_path: Path) -> None:
    """_find_binary should return the venv-local binary when it's not on PATH."""
    import sys, os
    fake_bin = tmp_path / "semgrep"
    fake_bin.write_text("#!/bin/sh\necho ok\n")
    fake_bin.chmod(0o755)

    monkeypatch.setattr(run_security_gates, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))

    result = run_security_gates._find_binary("semgrep")

    assert result == str(fake_bin)