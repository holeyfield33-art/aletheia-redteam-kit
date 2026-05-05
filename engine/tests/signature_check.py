from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from kit.client import AletheiaClient
from kit.verify import verify_receipt
from kit.web_audit.schema import Finding

from .prompt_injection import derive_api_base_url

_RECEIPT_KEY_PATH = "/.well-known/aletheia-receipt-key.pem"


def run_signature_check(*, base_url: str, timeout_sec: float) -> dict[str, Any]:
    target_url = urljoin(base_url.rstrip("/") + "/", _RECEIPT_KEY_PATH.lstrip("/"))
    active_tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    status_code: int | None = None
    body = ""
    try:
        with httpx.Client(timeout=timeout_sec, follow_redirects=True) as client:
            response = client.get(target_url)
        status_code = response.status_code
        body = response.text
    except Exception as exc:
        active_tests.append({
            "type": "signature_check",
            "test_name": "receipt_key",
            "result": "failed",
            "severity": "CRITICAL",
            "message": str(exc),
        })
        findings.append(_signature_failure_finding(target_url, None, str(exc)))
        return {"active_tests": active_tests, "findings": findings}

    if status_code != 200 or not _looks_like_pem(body):
        message = "Trust chain cannot be verified"
        active_tests.append({
            "type": "signature_check",
            "test_name": "receipt_key",
            "result": "failed",
            "severity": "CRITICAL",
            "message": message,
            "status_code": status_code,
        })
        findings.append(_signature_failure_finding(target_url, status_code, message))
        return {"active_tests": active_tests, "findings": findings}

    active_tests.append({
        "type": "signature_check",
        "test_name": "receipt_key",
        "result": "passed",
        "severity": "CRITICAL",
        "message": "Trust chain endpoint returned a valid PEM",
        "status_code": status_code,
    })

    live_receipt = _verify_live_receipt(base_url=base_url, public_key_pem=body.encode())
    active_tests.append(live_receipt["active_test"])
    if live_receipt["finding"]:
        findings.append(live_receipt["finding"])

    return {"active_tests": active_tests, "findings": findings}


def _looks_like_pem(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if "-----BEGIN " not in stripped or "-----END " not in stripped:
        return False
    return len(stripped.splitlines()) >= 3


def _signature_failure_finding(target_url: str, status_code: int | None, message: str) -> dict[str, Any]:
    finding = Finding(
        severity="CRITICAL",
        type="signature_failure",
        title="Trust chain verification failed",
        page_url=target_url,
        element_selector=None,
        action="trust_verification",
        expected="Receipt key endpoint returns a valid PEM",
        observed=message,
        evidence={"status_code": status_code},
        reproducible_steps=[f"Navigate to {target_url}"],
    ).to_dict()
    finding["message"] = "Trust chain cannot be verified"
    finding["status_code"] = status_code
    return finding


def _verify_live_receipt(*, base_url: str, public_key_pem: bytes) -> dict[str, Any]:
    api_base_url = derive_api_base_url(base_url)
    receipt_url = f"{api_base_url}/api/v1/audit"
    client: AletheiaClient | None = None

    try:
        client = AletheiaClient(base_url=api_base_url)
        result = client.audit(
            payload="Health check: confirm signed receipt verification path.",
            action="fetch_data",
            origin="active-adversarial-audit",
        )
    except Exception as exc:
        return {
            "active_test": {
                "type": "signature_check",
                "test_name": "receipt_signature",
                "result": "error",
                "severity": "CRITICAL",
                "message": str(exc),
            },
            "finding": None,
        }
    finally:
        if client is not None:
            client.close()

    receipt = result.receipt or {}
    signature_valid = False
    verification_error: str | None = None
    try:
        signature_valid = verify_receipt(receipt, public_key_pem)
    except Exception as exc:
        verification_error = str(exc)

    if signature_valid:
        return {
            "active_test": {
                "type": "signature_check",
                "test_name": "receipt_signature",
                "result": "passed",
                "severity": "CRITICAL",
                "message": "Live API receipt signature verified",
                "request_id": result.request_id,
            },
            "finding": None,
        }

    message = verification_error or "Live API receipt signature could not be verified"
    finding = Finding(
        severity="CRITICAL",
        type="signature_failure",
        title="Receipt signature verification failed",
        page_url=receipt_url,
        element_selector=None,
        action="trust_verification",
        expected="Live API receipt verifies against the published public key",
        observed=message,
        evidence={
            "request_id": result.request_id,
            "decision": result.decision,
            "has_signature": bool(receipt.get("signature")),
        },
        reproducible_steps=[
            f"Send a benign payload to {receipt_url}",
            "Verify the returned receipt signature against /.well-known/aletheia-receipt-key.pem",
        ],
    ).to_dict()
    finding["message"] = message
    return {
        "active_test": {
            "type": "signature_check",
            "test_name": "receipt_signature",
            "result": "failed",
            "severity": "CRITICAL",
            "message": message,
            "request_id": result.request_id,
        },
        "finding": finding,
    }