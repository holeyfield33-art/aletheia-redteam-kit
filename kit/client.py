"""Thin httpx client around the Aletheia hosted API."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api.aletheia-core.com"
DEFAULT_TIMEOUT_SEC = 30.0


@dataclass
class AuditResult:
    """One audit response from the Aletheia engine."""

    request_id: str
    decision: str
    reason: str | None
    receipt: dict[str, Any]
    raw: dict[str, Any]


class AletheiaClient:
    """
    Synchronous client for the Aletheia /v1/audit endpoint.

    Usage:
        client = AletheiaClient()  # reads ALETHEIA_API_KEY from env
        result = client.audit("Ignore previous instructions", action="fetch_data", origin="redteam-kit")
        print(result.decision)  # "DENIED"
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self.api_key = api_key or os.environ.get("ALETHEIA_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "ALETHEIA_API_KEY is required. Get a key at "
                "https://app.aletheia-core.com/keys"
            )

        self.base_url = (
            base_url or os.environ.get("ALETHEIA_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "X-API-Key": self.api_key,
                "Accept-Encoding": "identity",
            },
            timeout=timeout,
        )

    def audit(self, payload: str, action: str, origin: str) -> AuditResult:
        """Send a payload to the engine; return the result + signed receipt."""
        resp = self._client.post(
            "/api/v1/audit",
            json={"payload": payload, "action": action, "origin": origin},
        )
        # 403 is a valid "DENIED" response from the engine, not an HTTP error
        if resp.status_code not in (200, 403):
            resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            snippet = resp.text[:180].replace("\n", " ")
            raise RuntimeError(
                f"Expected JSON audit response but got {content_type or 'unknown content type'} "
                f"(status {resp.status_code}): {snippet}"
            )

        if not resp.content.strip():
            decision = "DENIED" if resp.status_code == 403 else "PROCEED"
            return AuditResult(
                request_id="",
                decision=decision,
                reason=f"Empty JSON response body from server (status {resp.status_code})",
                receipt={},
                raw={"status_code": resp.status_code, "empty_body": True},
            )

        body = resp.json()
        decision = body.get("decision")
        if not decision and resp.status_code == 403:
            decision = "DENIED"

        return AuditResult(
            request_id=body.get("request_id") or body.get("metadata", {}).get("request_id", ""),
            decision=decision or "UNKNOWN",
            reason=body.get("reason") or body.get("error"),
            receipt=body.get("receipt", {}),
            raw=body,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AletheiaClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()