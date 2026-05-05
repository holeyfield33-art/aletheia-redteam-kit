from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from engine.scoring import compute_scores
from engine.tests.auth_bypass import run_auth_bypass_tests
from engine.tests.prompt_injection import default_prompt_injection_tests, run_prompt_injection_tests
from engine.tests.signature_check import run_signature_check

from .config import AuthStep, CustomFindingRule, WebAuditConfig
from .schema import Finding


def run_website_audit(config: WebAuditConfig) -> dict[str, Any]:
    """Run website audit, using browser mode and optionally falling back to HTTP route checks."""
    try:
        return _run_playwright_audit(config)
    except Exception as exc:
        if not config.allow_http_fallback:
            raise
        fallback = _run_http_fallback(config)
        fallback["audit_backend"] = "http_fallback"
        fallback["backend_warning"] = f"Playwright backend unavailable; fallback used: {exc}"
        return fallback


def _run_playwright_audit(config: WebAuditConfig) -> dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Playwright is required for browser website mode. Install optional dependency 'web' and run 'playwright install'."
        ) from exc

    findings: list[dict[str, Any]] = []
    visited: set[str] = set()
    discovered: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(config.base_url, 0)])
    interactions_tested = 0
    skipped_actions = 0
    auth_summary = {
        "configured": bool(config.auth_workflow),
        "attempted": False,
        "success": False,
        "steps_total": len(config.auth_workflow or []),
        "steps_completed": 0,
        "failed_step": None,
        "error": None,
    }
    auth_cookies: list[dict[str, Any]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=config.headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        if config.auth_workflow:
            auth_summary["attempted"] = True
            auth_result = _run_auth_workflow(
                page=page,
                base_url=config.base_url,
                steps=config.auth_workflow,
                default_timeout_ms=int(config.timeout_sec * 1000),
            )
            auth_summary.update(auth_result)
            if auth_result["success"]:
                auth_cookies = context.cookies()
            if not auth_result["success"]:
                findings.append(
                    Finding(
                        severity="HIGH",
                        type="auth_failure",
                        title="Authentication workflow failed",
                        page_url=auth_result.get("failed_url") or config.base_url,
                        element_selector=auth_result.get("failed_selector"),
                        action="auth_step",
                        expected="Configured auth workflow completes successfully",
                        observed=auth_result.get("error") or "Unknown auth workflow failure",
                        evidence={
                            "failed_step": auth_result.get("failed_step"),
                            "steps_completed": auth_result.get("steps_completed", 0),
                            "steps_total": auth_result.get("steps_total", len(config.auth_workflow)),
                        },
                        reproducible_steps=[
                            f"Open {config.base_url}",
                            "Replay configured auth workflow JSON steps",
                        ],
                    ).to_dict()
                )

            for seed in _normalize_auth_seed_urls(config.base_url, config.auth_seed_urls):
                if seed not in discovered:
                    discovered.add(seed)
                    queue.append((seed, 0))

            if auth_result.get("current_url") and _is_internal_url(config.base_url, auth_result["current_url"]):
                current_url = str(auth_result["current_url"])
                if current_url not in discovered:
                    discovered.add(current_url)
                    queue.append((current_url, 0))

        while queue and len(visited) < config.max_pages:
            url, depth = queue.popleft()
            if depth > config.max_depth or url in visited:
                continue

            visited.add(url)
            console_errors: list[str] = []
            failed_requests: list[str] = []

            def on_console(msg):
                if msg.type == "error":
                    console_errors.append(msg.text)

            def on_request_failed(req):
                failed_requests.append(req.url)

            page.on("console", on_console)
            page.on("requestfailed", on_request_failed)

            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=int(config.timeout_sec * 1000))
            except PlaywrightTimeoutError:
                findings.append(
                    Finding(
                        severity="HIGH",
                        type="perf_timeout",
                        title="Route timed out",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="Route responds within timeout",
                        observed=f"No response before {config.timeout_sec}s timeout",
                        evidence={"timeout_sec": config.timeout_sec},
                        reproducible_steps=[f"Open {url}"],
                    ).to_dict()
                )
                page.remove_listener("console", on_console)
                page.remove_listener("requestfailed", on_request_failed)
                continue

            status_code = response.status if response else None
            if status_code is None or status_code >= 400:
                findings.append(
                    Finding(
                        severity="CRITICAL" if (status_code or 0) >= 500 else "HIGH",
                        type="route_error",
                        title="Route returned error status",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="HTTP < 400",
                        observed=f"HTTP {status_code}",
                        evidence={"status_code": status_code},
                        reproducible_steps=[f"Navigate to {url}"],
                    ).to_dict()
                )

            page_title = page.title()
            page_body = page.content()
            findings.extend(
                _apply_custom_rules(
                    rules=config.custom_rules,
                    page_url=url,
                    title=page_title,
                    body=page_body,
                    headers={},
                )
            )

            hrefs = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.getAttribute('href')).filter(Boolean)",
            )
            for href in hrefs:
                absolute = urljoin(url, href)
                if _is_internal_url(config.base_url, absolute) and absolute not in discovered and absolute not in visited:
                    discovered.add(absolute)
                    queue.append((absolute, depth + 1))

            buttons = page.locator("button, [role='button']")
            button_count = min(buttons.count(), 10)
            for idx in range(button_count):
                selector = f"button_or_role_button[{idx}]"
                interactions_tested += 1
                try:
                    disabled = buttons.nth(idx).is_disabled(timeout=1000)
                    if disabled:
                        continue
                    label = (buttons.nth(idx).inner_text(timeout=1000) or "").strip()
                    if not _is_safe_button_action(label):
                        skipped_actions += 1
                        continue
                    before_url = page.url
                    buttons.nth(idx).click(timeout=2000)
                    page.wait_for_timeout(200)
                    if page.url == before_url:
                        findings.append(
                            Finding(
                                severity="MEDIUM",
                                type="dead_click",
                                title="Button click had no observable effect",
                                page_url=url,
                                element_selector=selector,
                                action="click",
                                expected="URL or UI state changes",
                                observed="No navigation change detected",
                                evidence={"before_url": before_url, "after_url": page.url},
                                reproducible_steps=[f"Navigate to {url}", f"Click {selector}"],
                            ).to_dict()
                        )
                except Exception as exc:
                    findings.append(
                        Finding(
                            severity="HIGH",
                            type="dead_click",
                            title="Button click failed",
                            page_url=url,
                            element_selector=selector,
                            action="click",
                            expected="Element is clickable",
                            observed=str(exc),
                            evidence={"error": str(exc)},
                            reproducible_steps=[f"Navigate to {url}", f"Click {selector}"],
                        ).to_dict()
                    )

            tabs = page.locator("[role='tab']")
            tab_count = min(tabs.count(), 10)
            for idx in range(tab_count):
                selector = f"role_tab[{idx}]"
                interactions_tested += 1
                try:
                    tabs.nth(idx).click(timeout=2000)
                    selected = tabs.nth(idx).get_attribute("aria-selected")
                    if selected != "true":
                        findings.append(
                            Finding(
                                severity="MEDIUM",
                                type="tab_failure",
                                title="Tab did not activate",
                                page_url=url,
                                element_selector=selector,
                                action="tab_switch",
                                expected="aria-selected='true' after click",
                                observed=f"aria-selected={selected}",
                                evidence={"aria_selected": selected},
                                reproducible_steps=[f"Navigate to {url}", f"Click {selector}"],
                            ).to_dict()
                        )
                except Exception as exc:
                    findings.append(
                        Finding(
                            severity="HIGH",
                            type="tab_failure",
                            title="Tab click failed",
                            page_url=url,
                            element_selector=selector,
                            action="tab_switch",
                            expected="Tab is clickable",
                            observed=str(exc),
                            evidence={"error": str(exc)},
                            reproducible_steps=[f"Navigate to {url}", f"Click {selector}"],
                        ).to_dict()
                    )

            for message in console_errors:
                findings.append(
                    Finding(
                        severity="HIGH",
                        type="js_error",
                        title="Console error detected",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="No console runtime errors",
                        observed=message,
                        evidence={"console_message": message},
                        reproducible_steps=[f"Navigate to {url}", "Open browser console"],
                    ).to_dict()
                )

            for failed_url in failed_requests:
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        type="network_error",
                        title="Network request failed",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="No failed network requests",
                        observed=failed_url,
                        evidence={"request_url": failed_url},
                        reproducible_steps=[f"Navigate to {url}", "Inspect network panel"],
                    ).to_dict()
                )

            page.remove_listener("console", on_console)
            page.remove_listener("requestfailed", on_request_failed)

        browser.close()

    summary = _finalize_summary(
        config=config,
        findings=findings,
        visited=visited,
        discovered=discovered,
        interactions_tested=interactions_tested,
        skipped_actions=skipped_actions,
        auth=auth_summary,
        auth_cookies=auth_cookies,
    )
    summary["audit_backend"] = "playwright"
    return summary


def _run_http_fallback(config: WebAuditConfig) -> dict[str, Any]:
    """Fallback route-only audit using HTTP requests when browser backend is unavailable."""
    findings: list[dict[str, Any]] = []
    visited: set[str] = set()
    discovered: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(config.base_url, 0)])
    auth_summary = {
        "configured": bool(config.auth_workflow),
        "attempted": False,
        "success": False,
        "steps_total": len(config.auth_workflow or []),
        "steps_completed": 0,
        "failed_step": None,
        "error": None,
    }

    if config.auth_workflow:
        findings.append(
            Finding(
                severity="HIGH",
                type="auth_failure",
                title="Authentication workflow unavailable in HTTP fallback",
                page_url=config.base_url,
                element_selector=None,
                action="auth_step",
                expected="Authenticated checks require browser backend",
                observed="Playwright backend unavailable; HTTP fallback cannot execute auth workflow",
                evidence={"steps_total": len(config.auth_workflow)},
                reproducible_steps=[
                    "Install Playwright runtime dependencies",
                    "Re-run website audit with browser backend",
                ],
            ).to_dict()
        )
        auth_summary["error"] = "auth_workflow_requires_browser_backend"

    with httpx.Client(timeout=config.timeout_sec, follow_redirects=True) as client:
        while queue and len(visited) < config.max_pages:
            url, depth = queue.popleft()
            if depth > config.max_depth or url in visited:
                continue
            visited.add(url)

            try:
                response = client.get(url)
            except httpx.TimeoutException:
                findings.append(
                    Finding(
                        severity="HIGH",
                        type="perf_timeout",
                        title="Route timed out (HTTP fallback)",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="Route responds within timeout",
                        observed=f"No response before {config.timeout_sec}s timeout",
                        evidence={"timeout_sec": config.timeout_sec},
                        reproducible_steps=[f"Open {url}"],
                    ).to_dict()
                )
                continue
            except Exception as exc:
                findings.append(
                    Finding(
                        severity="HIGH",
                        type="network_error",
                        title="Route request failed (HTTP fallback)",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="Route request succeeds",
                        observed=str(exc),
                        evidence={"error": str(exc)},
                        reproducible_steps=[f"Open {url}"],
                    ).to_dict()
                )
                continue

            status_code = response.status_code
            if status_code >= 400:
                findings.append(
                    Finding(
                        severity="CRITICAL" if status_code >= 500 else "HIGH",
                        type="route_error",
                        title="Route returned error status (HTTP fallback)",
                        page_url=url,
                        element_selector=None,
                        action="visit",
                        expected="HTTP < 400",
                        observed=f"HTTP {status_code}",
                        evidence={"status_code": status_code},
                        reproducible_steps=[f"Navigate to {url}"],
                    ).to_dict()
                )

            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type.lower():
                page_title = _extract_title(response.text)
                findings.extend(
                    _apply_custom_rules(
                        rules=config.custom_rules,
                        page_url=url,
                        title=page_title,
                        body=response.text,
                        headers=dict(response.headers),
                    )
                )
                for href in _extract_hrefs(response.text):
                    absolute = urljoin(url, href)
                    if _is_internal_url(config.base_url, absolute) and absolute not in discovered and absolute not in visited:
                        discovered.add(absolute)
                        queue.append((absolute, depth + 1))

    return _finalize_summary(
        config=config,
        findings=findings,
        visited=visited,
        discovered=discovered,
        interactions_tested=0,
        skipped_actions=0,
        auth=auth_summary,
        auth_cookies=[],
    )


def _run_auth_workflow(
    *,
    page: Any,
    base_url: str,
    steps: list[AuthStep],
    default_timeout_ms: int,
) -> dict[str, Any]:
    result = {
        "configured": True,
        "attempted": True,
        "success": False,
        "steps_total": len(steps),
        "steps_completed": 0,
        "failed_step": None,
        "failed_selector": None,
        "failed_url": None,
        "error": None,
        "current_url": None,
    }

    for idx, step in enumerate(steps, 1):
        timeout = step.timeout_ms or default_timeout_ms
        try:
            if step.action == "goto":
                target_url = urljoin(base_url, step.url or "")
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout)
            elif step.action == "fill":
                page.locator(step.selector).first.fill(step.value or "", timeout=timeout)
            elif step.action == "click":
                page.locator(step.selector).first.click(timeout=timeout)
            elif step.action == "wait_for_selector":
                page.wait_for_selector(step.selector, timeout=timeout)
            elif step.action == "wait_for_url":
                target_url = urljoin(base_url, step.url or "")
                page.wait_for_url(target_url, timeout=timeout)

            result["steps_completed"] = idx
        except Exception as exc:
            result["failed_step"] = {
                "index": idx,
                "label": step.label,
                "action": step.action,
                "selector": step.selector,
                "url": step.url,
            }
            result["failed_selector"] = step.selector
            result["failed_url"] = step.url
            result["error"] = str(exc)
            result["current_url"] = getattr(page, "url", None)
            return result

    result["success"] = True
    result["current_url"] = getattr(page, "url", None)
    return result


def _normalize_auth_seed_urls(base_url: str, seeds: list[str] | None) -> list[str]:
    if not seeds:
        return []

    normalized: list[str] = []
    for raw in seeds:
        candidate = urljoin(base_url, raw)
        if _is_internal_url(base_url, candidate):
            normalized.append(candidate)
    return normalized


def _extract_hrefs(html: str) -> list[str]:
    hrefs: list[str] = []
    marker = 'href="'
    start = 0
    while True:
        idx = html.find(marker, start)
        if idx == -1:
            break
        begin = idx + len(marker)
        end = html.find('"', begin)
        if end == -1:
            break
        href = html[begin:end].strip()
        if href and not href.startswith("#") and not href.startswith("javascript:"):
            hrefs.append(href)
        start = end + 1
    return hrefs


def _extract_title(html: str) -> str:
    lower = html.lower()
    open_idx = lower.find("<title")
    if open_idx == -1:
        return ""
    start_tag_end = lower.find(">", open_idx)
    if start_tag_end == -1:
        return ""
    close_idx = lower.find("</title>", start_tag_end)
    if close_idx == -1:
        return ""
    return html[start_tag_end + 1 : close_idx].strip()


def _apply_custom_rules(
    *,
    rules: list[CustomFindingRule] | None,
    page_url: str,
    title: str,
    body: str,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    if not rules:
        return []

    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    findings: list[dict[str, Any]] = []

    for rule in rules:
        target_value = _rule_target_value(
            target=rule.target,
            page_url=page_url,
            title=title,
            body=body,
            headers=header_text,
        )
        matched, excerpt = _rule_match(rule, target_value)
        if not matched:
            continue
        findings.append(
            Finding(
                severity=rule.severity,
                type=rule.type,
                title=rule.title or f"Custom rule matched: {rule.name}",
                page_url=page_url,
                element_selector=None,
                action="custom_rule_check",
                expected=rule.expected,
                observed=f"Rule '{rule.name}' matched in {rule.target}",
                evidence={
                    "rule_name": rule.name,
                    "target": rule.target,
                    "pattern": rule.pattern,
                    "match": rule.match,
                    "excerpt": excerpt,
                },
                reproducible_steps=[
                    f"Open {page_url}",
                    f"Inspect {rule.target} for pattern: {rule.pattern}",
                ],
            ).to_dict()
        )

    return findings


def _rule_target_value(*, target: str, page_url: str, title: str, body: str, headers: str) -> str:
    if target == "url":
        return page_url
    if target == "title":
        return title
    if target == "headers":
        return headers
    return body


def _rule_match(rule: CustomFindingRule, target_value: str) -> tuple[bool, str | None]:
    if not target_value:
        return False, None

    if rule.match == "regex":
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(rule.pattern, flags)
        except re.error:
            return False, None
        matched = compiled.search(target_value)
        if not matched:
            return False, None
        snippet = matched.group(0)
        return True, snippet[:180]

    source = target_value if rule.case_sensitive else target_value.lower()
    needle = rule.pattern if rule.case_sensitive else rule.pattern.lower()
    idx = source.find(needle)
    if idx == -1:
        return False, None
    end = idx + len(rule.pattern)
    excerpt = target_value[max(0, idx - 30) : min(len(target_value), end + 30)].strip()
    return True, excerpt[:180]


def _finalize_summary(
    *,
    config: WebAuditConfig,
    findings: list[dict[str, Any]],
    visited: set[str],
    discovered: set[str],
    interactions_tested: int,
    skipped_actions: int,
    auth: dict[str, Any] | None,
    auth_cookies: list[dict[str, Any]],
) -> dict[str, Any]:
    active_test_results = _run_active_tests(config, auth_cookies=auth_cookies)
    findings = [*findings, *active_test_results["findings"]]
    active_tests = active_test_results["active_tests"]
    severity_counts = Counter(f["severity"] for f in findings)
    type_counts = Counter(f["type"] for f in findings)
    checks_total = max(1, len(visited) + interactions_tested)
    pass_rate = round(100.0 * max(0, checks_total - len(findings)) / checks_total, 1)
    required_routes = config.required_routes or []
    required_routes_failed = [route for route in required_routes if not _required_route_hit(route, visited)]
    gates = evaluate_gates(
        findings_by_severity={
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
        },
        pass_rate=pass_rate,
        required_routes_failed=required_routes_failed,
        max_critical=config.max_critical,
        max_high=config.max_high,
        min_pass_rate=config.min_pass_rate,
    )
    scores = compute_scores(findings=findings, active_tests=active_tests, config=config)
    regression = _build_regression_summary(
        baseline_summary_path=config.baseline_summary_path,
        current_summary={
            "findings_total": len(findings),
            "trust_score": scores["trust_score"],
            "exploitability_score": scores["exploitability_score"],
            "verdict": scores["verdict"],
            "attack_summary": scores["attack_summary"],
            "active_tests": active_tests,
        },
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": config.base_url,
        "crawl_stats": {
            "pages_discovered": len(discovered),
            "pages_visited": len(visited),
            "interactions_tested": interactions_tested,
            "skipped_actions": skipped_actions,
        },
        "findings_total": len(findings),
        "findings_by_severity": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "findings_by_type": {
            "route_error": type_counts.get("route_error", 0),
            "dead_click": type_counts.get("dead_click", 0),
            "tab_failure": type_counts.get("tab_failure", 0),
            "js_error": type_counts.get("js_error", 0),
            "network_error": type_counts.get("network_error", 0),
            "perf_timeout": type_counts.get("perf_timeout", 0),
            "auth_failure": type_counts.get("auth_failure", 0),
            "prompt_injection": type_counts.get("prompt_injection", 0),
            "signature_failure": type_counts.get("signature_failure", 0),
            "auth_bypass": type_counts.get("auth_bypass", 0),
            **{
                kind: count
                for kind, count in type_counts.items()
                if kind
                not in {
                    "route_error",
                    "dead_click",
                    "tab_failure",
                    "js_error",
                    "network_error",
                    "perf_timeout",
                    "auth_failure",
                    "prompt_injection",
                    "signature_failure",
                    "auth_bypass",
                }
            },
        },
        "pass_rate": pass_rate,
        **scores,
        "required_routes": required_routes,
        "required_routes_failed": required_routes_failed,
        "auth": auth,
        "gates": gates,
        "regression": regression,
        "active_tests": active_tests,
        "findings": findings,
    }


def _run_active_tests(config: WebAuditConfig, *, auth_cookies: list[dict[str, Any]]) -> dict[str, Any]:
    active_tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    prompt_results = run_prompt_injection_tests(
        target_url=config.base_url,
        tests=config.prompt_injection_tests or default_prompt_injection_tests(),
    )
    active_tests.extend(prompt_results["active_tests"])
    findings.extend(prompt_results["findings"])

    signature_results = run_signature_check(base_url=config.base_url, timeout_sec=config.timeout_sec)
    active_tests.extend(signature_results["active_tests"])
    findings.extend(signature_results["findings"])

    auth_results = run_auth_bypass_tests(
        base_url=config.base_url,
        timeout_sec=config.timeout_sec,
        protected_routes=config.protected_routes,
        protected_route_profiles=config.protected_route_profiles,
        auth_cookies=auth_cookies,
    )
    active_tests.extend(auth_results["active_tests"])
    findings.extend(auth_results["findings"])

    return {"active_tests": active_tests, "findings": findings}


def _is_internal_url(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(candidate)
    if not target.scheme:
        return True
    return base.netloc == target.netloc and target.scheme in {"http", "https"}


def _required_route_hit(required: str, visited: set[str]) -> bool:
    return any(required in url for url in visited)


def _build_regression_summary(
    *,
    baseline_summary_path: str | None,
    current_summary: dict[str, Any],
) -> dict[str, Any] | None:
    if not baseline_summary_path:
        return None

    try:
        baseline = json.loads(Path(baseline_summary_path).read_text())
    except Exception as exc:
        return {
            "baseline_summary_path": baseline_summary_path,
            "error": f"unable_to_load_baseline: {exc}",
        }

    baseline_failed = _failed_active_test_keys(baseline.get("active_tests", []))
    current_failed = _failed_active_test_keys(current_summary.get("active_tests", []))
    baseline_attack_summary = baseline.get("attack_summary", {})
    current_attack_summary = current_summary.get("attack_summary", {})

    return {
        "baseline_summary_path": baseline_summary_path,
        "trust_score_delta": current_summary.get("trust_score", 0) - int(baseline.get("trust_score", 0) or 0),
        "exploitability_score_delta": current_summary.get("exploitability_score", 0)
        - int(baseline.get("exploitability_score", 0) or 0),
        "findings_total_delta": current_summary.get("findings_total", 0) - int(baseline.get("findings_total", 0) or 0),
        "successful_attacks_delta": int(current_attack_summary.get("successful_attacks", 0) or 0)
        - int(baseline_attack_summary.get("successful_attacks", 0) or 0),
        "verdict_changed": current_summary.get("verdict") != baseline.get("verdict"),
        "previous_verdict": baseline.get("verdict"),
        "current_verdict": current_summary.get("verdict"),
        "new_failed_active_tests": sorted(current_failed - baseline_failed),
        "resolved_failed_active_tests": sorted(baseline_failed - current_failed),
        "improved": (
            current_summary.get("trust_score", 0) >= int(baseline.get("trust_score", 0) or 0)
            and current_summary.get("exploitability_score", 0) <= int(baseline.get("exploitability_score", 0) or 0)
            and int(current_attack_summary.get("successful_attacks", 0) or 0)
            <= int(baseline_attack_summary.get("successful_attacks", 0) or 0)
        ),
    }


def _failed_active_test_keys(active_tests: list[dict[str, Any]]) -> set[str]:
    failed_results = {"failed", "succeeded", "bypassed", "error"}
    keys: set[str] = set()
    for test in active_tests:
        if test.get("result") not in failed_results:
            continue
        keys.add(f"{test.get('type', 'unknown')}:{test.get('test_name', 'unnamed')}")
    return keys


def _is_safe_button_action(label: str) -> bool:
    text = label.lower().strip()
    if not text:
        return True

    unsafe_markers = (
        "delete",
        "remove",
        "logout",
        "log out",
        "sign out",
        "purchase",
        "buy",
        "checkout",
        "pay",
        "unsubscribe",
        "deactivate",
        "terminate",
    )
    return not any(marker in text for marker in unsafe_markers)


def evaluate_gates(
    *,
    findings_by_severity: dict[str, int],
    pass_rate: float,
    required_routes_failed: list[str],
    max_critical: int,
    max_high: int,
    min_pass_rate: float,
) -> dict[str, Any]:
    critical = findings_by_severity.get("CRITICAL", 0)
    high = findings_by_severity.get("HIGH", 0)
    violations: list[str] = []
    if critical > max_critical:
        violations.append(f"critical>{max_critical}")
    if high > max_high:
        violations.append(f"high>{max_high}")
    if pass_rate < min_pass_rate:
        violations.append(f"pass_rate<{min_pass_rate}")
    if required_routes_failed:
        violations.append("required_routes_failed")
    return {
        "pass": len(violations) == 0,
        "violations": violations,
    }
