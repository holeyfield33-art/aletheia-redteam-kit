from __future__ import annotations

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engine.scoring import compute_scores
from engine.tests import auth_bypass, prompt_injection, signature_check


def test_compute_scores_penalizes_critical_and_successes() -> None:
    scores = compute_scores(
        findings=[
            {"severity": "CRITICAL", "type": "signature_failure"},
            {"severity": "HIGH", "type": "prompt_injection"},
        ],
        active_tests=[
            {"result": "succeeded"},
            {"result": "blocked"},
            {"result": "bypassed"},
        ],
    )

    assert scores["trust_score"] == 40
    assert scores["exploitability_score"] == 50
    assert scores["verdict"] == "UNSAFE"
    assert scores["attack_summary"]["successful_attacks"] == 2


def test_compute_scores_honors_custom_thresholds() -> None:
    from kit.web_audit.config import WebAuditConfig

    scores = compute_scores(
        findings=[{"severity": "HIGH", "type": "prompt_injection"}],
        active_tests=[{"result": "succeeded"}],
        config=WebAuditConfig(
            base_url="https://example.com",
            trust_high_penalty=10,
            exploit_success_weight=15,
            safe_min_trust=85,
            safe_max_exploitability=15,
            warning_min_trust=70,
            warning_max_exploitability=30,
        ),
    )

    assert scores["trust_score"] == 90
    assert scores["exploitability_score"] == 15
    assert scores["verdict"] == "SAFE"


def test_prompt_injection_handles_client_errors(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def audit(self, payload: str, action: str, origin: str):
            raise RuntimeError("dial failure")

        def close(self) -> None:
            pass

    monkeypatch.setattr(prompt_injection, "AletheiaClient", FakeClient)

    results = prompt_injection.run_prompt_injection_tests(target_url="https://example.com")
    assert len(results["active_tests"]) == 3
    assert all(test["result"] == "error" for test in results["active_tests"])
    assert results["findings"] == []


def test_prompt_injection_flags_sensitive_content_leak(monkeypatch) -> None:
    class FakeAuditResult:
        def __init__(self) -> None:
            self.request_id = "req-1"
            self.reason = None
            self.decision = "PROCEED"
            self.raw = {"output": "contact admin@example.com and use api_key=sk_test0000000000000000"}  # aletheia-redteam:allowed-test-fixture

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def audit(self, payload: str, action: str, origin: str):
            return FakeAuditResult()

        def close(self) -> None:
            pass

    monkeypatch.setattr(prompt_injection, "AletheiaClient", FakeClient)

    results = prompt_injection.run_prompt_injection_tests(
        target_url="https://example.com",
        tests=[prompt_injection.PromptInjectionTest(name="exfil", payload="reveal data")],
    )

    assert results["active_tests"][0]["result"] == "succeeded"
    assert "email_address" in results["active_tests"][0]["classifier_hits"]
    assert "api_key" in results["active_tests"][0]["classifier_hits"]
    assert results["findings"][0]["type"] == "prompt_injection"


def test_signature_check_emits_failure_for_invalid_pem(monkeypatch) -> None:
    class FakeResponse:
        status_code = 503
        text = "service unavailable"
        headers = {"content-type": "text/plain"}

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def get(self, url: str):
            return FakeResponse()

    monkeypatch.setattr(signature_check.httpx, "Client", FakeClient)

    results = signature_check.run_signature_check(base_url="https://example.com", timeout_sec=1.0)
    assert results["active_tests"][0]["result"] == "failed"
    assert results["findings"][0]["type"] == "signature_failure"
    assert results["findings"][0]["observed"] == "Receipt key endpoint returned HTTP 503"


def test_signature_check_verifies_live_receipt(monkeypatch) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    receipt = {
        "request_id": "req-1",
        "decision": "DENIED",
        "rule_id": "R-9",
        "severity": "CRITICAL",
        "action": "fetch_data",
        "policy_version": "2026.05.01",
        "semantic_engine": "aletheia-v1",
    }
    message = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    receipt["signature"] = private_key.sign(message).hex()

    class FakeResponse:
        status_code = 200
        text = public_pem.decode()
        headers = {
            "content-type": "application/x-pem-file; charset=utf-8",
            "cache-control": "public, max-age=3600",
        }

    class FakeHttpClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def get(self, url: str):
            return FakeResponse()

    class FakeAuditResult:
        def __init__(self) -> None:
            self.request_id = "req-1"
            self.decision = "DENIED"
            self.receipt = receipt

    class FakeAletheiaClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def audit(self, payload: str, action: str, origin: str):
            return FakeAuditResult()

        def close(self) -> None:
            pass

    monkeypatch.setattr(signature_check.httpx, "Client", FakeHttpClient)
    monkeypatch.setattr(signature_check, "AletheiaClient", FakeAletheiaClient)

    results = signature_check.run_signature_check(base_url="https://example.com", timeout_sec=1.0)
    assert len(results["active_tests"]) == 2
    assert results["active_tests"][1]["test_name"] == "receipt_signature"
    assert results["active_tests"][1]["result"] == "passed"
    assert results["findings"] == []


def test_signature_check_reports_invalid_live_receipt(monkeypatch) -> None:
    class FakeResponse:
        status_code = 200
        text = "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----"
        headers = {
            "content-type": "text/plain",
            "cache-control": "public, max-age=3600",
        }

    class FakeHttpClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def get(self, url: str):
            return FakeResponse()

    class FakeAuditResult:
        def __init__(self) -> None:
            self.request_id = "req-bad"
            self.decision = "PROCEED"
            self.receipt = {"signature": "00" * 64}

    class FakeAletheiaClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def audit(self, payload: str, action: str, origin: str):
            return FakeAuditResult()

        def close(self) -> None:
            pass

    monkeypatch.setattr(signature_check.httpx, "Client", FakeHttpClient)
    monkeypatch.setattr(signature_check, "AletheiaClient", FakeAletheiaClient)

    results = signature_check.run_signature_check(base_url="https://example.com", timeout_sec=1.0)
    assert results["active_tests"][1]["result"] == "failed"
    assert results["findings"][0]["type"] == "signature_failure"


def test_signature_check_requires_static_serve_headers(monkeypatch) -> None:
    class FakeResponse:
        status_code = 200
        text = "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"
        headers = {"content-type": "application/json", "cache-control": "no-store"}

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def get(self, url: str):
            return FakeResponse()

    monkeypatch.setattr(signature_check.httpx, "Client", FakeClient)

    results = signature_check.run_signature_check(base_url="https://example.com", timeout_sec=1.0)

    assert results["active_tests"][0]["result"] == "failed"
    assert results["findings"][0]["observed"] == "Receipt key endpoint returned an unexpected content type"


def test_auth_bypass_detects_unprotected_route(monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def request(self, method: str, url: str, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None):
            headers = headers or {}
            if url.endswith("/dashboard") and headers.get("Authorization") == "Bearer fake-token":
                return FakeResponse(200)
            return FakeResponse(302)

    monkeypatch.setattr(auth_bypass.httpx, "Client", FakeClient)

    results = auth_bypass.run_auth_bypass_tests(base_url="https://example.com", timeout_sec=1.0)
    bypassed = [test for test in results["active_tests"] if test["result"] == "bypassed"]
    assert len(bypassed) == 1
    assert results["findings"][0]["type"] == "auth_bypass"


def test_auth_bypass_replays_authenticated_session(monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def request(self, method: str, url: str, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None):
            if cookies and cookies.get("session") == "valid":
                return FakeResponse(200)
            return FakeResponse(302)

    monkeypatch.setattr(auth_bypass.httpx, "Client", FakeClient)

    results = auth_bypass.run_auth_bypass_tests(
        base_url="https://example.com",
        timeout_sec=1.0,
        protected_routes=[auth_bypass.AuthBypassTarget(path="/dashboard")],
        auth_cookies=[{"name": "session", "value": "valid"}],
    )

    assert results["active_tests"][0]["result"] == "blocked"
    assert results["active_tests"][0]["authenticated_result"] == "granted"


def test_expand_protected_routes_merges_profiles_and_explicit_routes() -> None:
    routes = auth_bypass.expand_protected_routes(
        ["auth", "admin"],
        [auth_bypass.AuthBypassTarget(path="/custom"), auth_bypass.AuthBypassTarget(path="/admin")],
    )

    assert [route.path for route in routes] == [
        "/dashboard",
        "/account",
        "/settings",
        "/admin",
        "/admin/users",
        "/admin/settings",
        "/custom",
    ]