from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from kit.web_audit.config import AuthBypassTarget
from kit.web_audit.schema import Finding

PROTECTED_ROUTE_PROFILES: dict[str, list[AuthBypassTarget]] = {
    "core": [
        AuthBypassTarget(path="/dashboard"),
        AuthBypassTarget(path="/account"),
        AuthBypassTarget(path="/settings"),
        AuthBypassTarget(path="/billing"),
        AuthBypassTarget(path="/admin"),
    ],
    "auth": [
        AuthBypassTarget(path="/dashboard"),
        AuthBypassTarget(path="/account"),
        AuthBypassTarget(path="/settings"),
    ],
    "billing": [
        AuthBypassTarget(path="/billing"),
        AuthBypassTarget(path="/billing/invoices"),
        AuthBypassTarget(path="/billing/payment-methods"),
    ],
    "admin": [
        AuthBypassTarget(path="/admin"),
        AuthBypassTarget(path="/admin/users"),
        AuthBypassTarget(path="/admin/settings"),
    ],
    "api": [
        AuthBypassTarget(path="/api/auth/session"),
        AuthBypassTarget(path="/api/keys"),
        AuthBypassTarget(path="/api/admin"),
    ],
}


def default_protected_routes() -> list[AuthBypassTarget]:
    return list(PROTECTED_ROUTE_PROFILES["core"])


def run_auth_bypass_tests(
    *,
    base_url: str,
    timeout_sec: float,
    protected_routes: list[AuthBypassTarget] | None = None,
    protected_route_profiles: list[str] | None = None,
    auth_cookies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    targets = expand_protected_routes(protected_route_profiles, protected_routes)
    active_tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    cookie_jar = _cookie_jar(auth_cookies)

    with httpx.Client(timeout=timeout_sec, follow_redirects=False) as client:
        for target in targets:
            route_url = urljoin(base_url.rstrip("/") + "/", target.path.lstrip("/"))
            bypass_variant = None
            bypass_status = None
            authenticated_status = None
            for variant_name, headers in _header_variants(route_url):
                try:
                    response = client.request(target.method, route_url, headers=headers)
                except Exception:
                    continue
                if response.status_code == 200:
                    bypass_variant = variant_name
                    bypass_status = response.status_code
                    break

            if cookie_jar:
                try:
                    auth_response = client.request(target.method, route_url, cookies=cookie_jar)
                    authenticated_status = auth_response.status_code
                except Exception:
                    authenticated_status = None

            result = "bypassed" if bypass_variant else "blocked"
            active_tests.append(
                {
                    "type": "auth_bypass",
                    "test_name": target.path,
                    "result": result,
                    "severity": "HIGH",
                    "message": (
                        f"Unauthenticated access granted via {bypass_variant}" if bypass_variant else "Protected route denied"
                    ),
                    "authenticated_result": _authenticated_result(authenticated_status, bool(cookie_jar)),
                    "authenticated_status_code": authenticated_status,
                }
            )

            if bypass_variant:
                finding = Finding(
                    severity="HIGH",
                    type="auth_bypass",
                    title="Protected route accessible without valid token",
                    page_url=route_url,
                    element_selector=None,
                    action="auth_probe",
                    expected="Protected routes reject unauthenticated access",
                    observed=f"HTTP {bypass_status} via {bypass_variant}",
                    evidence={
                        "variant": bypass_variant,
                        "status_code": bypass_status,
                        "authenticated_status_code": authenticated_status,
                    },
                    reproducible_steps=[
                        f"Send unauthenticated request to {route_url}",
                        f"Repeat with {bypass_variant} headers",
                    ],
                ).to_dict()
                finding["result"] = "bypassed"
                findings.append(finding)

    return {"active_tests": active_tests, "findings": findings}


def expand_protected_routes(
    profiles: list[str] | None,
    explicit_routes: list[AuthBypassTarget] | None,
) -> list[AuthBypassTarget]:
    ordered: list[AuthBypassTarget] = []
    seen: set[tuple[str, str]] = set()

    for profile in profiles or ["core"]:
        for route in PROTECTED_ROUTE_PROFILES.get(profile, []):
            key = (route.method, route.path)
            if key not in seen:
                seen.add(key)
                ordered.append(route)

    for route in explicit_routes or []:
        key = (route.method, route.path)
        if key not in seen:
            seen.add(key)
            ordered.append(route)

    return ordered


def _header_variants(route_url: str) -> list[tuple[str, dict[str, str]]]:
    return [
        ("empty_headers", {}),
        ("modified_headers", {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": route_url}),
        ("fake_token", {"Authorization": "Bearer fake-token"}),
    ]


def _cookie_jar(auth_cookies: list[dict[str, Any]] | None) -> dict[str, str]:
    if not auth_cookies:
        return {}
    jar: dict[str, str] = {}
    for cookie in auth_cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value is not None:
            jar[str(name)] = str(value)
    return jar


def _authenticated_result(status_code: int | None, had_cookies: bool) -> str:
    if not had_cookies:
        return "not_configured"
    if status_code == 200:
        return "granted"
    if status_code is None:
        return "error"
    return "denied"