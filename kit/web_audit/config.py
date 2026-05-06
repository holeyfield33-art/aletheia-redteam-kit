from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(slots=True)
class AuthStep:
    """Single browser automation step used for authenticated flows."""

    action: Literal["goto", "fill", "click", "wait_for_selector", "wait_for_url"]
    selector: str | None = None
    value: str | None = None
    url: str | None = None
    timeout_ms: int | None = None
    label: str | None = None


@dataclass(slots=True)
class CustomFindingRule:
    """User-provided custom rule that can emit a finding when matched."""

    name: str
    pattern: str
    target: Literal["body", "url", "title", "headers"] = "body"
    match: Literal["contains", "regex"] = "contains"
    case_sensitive: bool = False
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    type: str = "custom_rule"
    title: str | None = None
    expected: str = "Pattern should not be present"


@dataclass(slots=True)
class PromptInjectionTest:
    """Configured adversarial prompt injection check."""

    name: str
    payload: str
    expected: Literal["blocked", "succeeded"] = "blocked"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"


@dataclass(slots=True)
class AuthBypassTarget:
    """Protected route target used for unauthenticated access checks."""

    path: str
    method: Literal["GET", "POST"] = "GET"


@dataclass(slots=True)
class WebAuditConfig:
    """Configuration for website audit runs."""

    base_url: str
    output: str = "website_summary.json"
    max_pages: int = 100
    max_depth: int = 2
    timeout_sec: float = 15.0
    headless: bool = True
    required_routes: list[str] | None = None
    max_critical: int = 0
    max_high: int = 3
    min_pass_rate: float = 95.0
    allow_http_fallback: bool = True
    custom_rules: list[CustomFindingRule] | None = None
    auth_workflow: list[AuthStep] | None = None
    auth_seed_urls: list[str] | None = None
    prompt_injection_tests: list[PromptInjectionTest] | None = None
    protected_routes: list[AuthBypassTarget] | None = None
    protected_route_profiles: list[str] | None = None
    baseline_summary_path: str | None = None
    trust_critical_penalty: int = 40
    trust_high_penalty: int = 20
    exploit_success_weight: int = 25
    safe_min_trust: int = 80
    safe_max_exploitability: int = 20
    warning_min_trust: int = 50
    warning_max_exploitability: int = 60
    # Noise reduction
    js_error_severity: str = "MEDIUM"
    dead_click_error_severity: str = "MEDIUM"
    max_js_errors_per_page: int = 5
    max_network_errors_per_page: int = 5
    skip_external_network_errors: bool = True
    deduplicate_findings: bool = True
    # Screenshot capture
    capture_screenshots: bool = False
    screenshot_dir: str = "screenshots"
