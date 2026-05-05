"""Repository audit engine for static code/config/dependency checks."""

from .scanner import run_repo_audit

__all__ = ["run_repo_audit"]
