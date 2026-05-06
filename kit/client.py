"""Thin httpx client around the Aletheia hosted API."""
from __future__ import annotations

import os
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api.aletheia-core.com"
DEFAULT_TIMEOUT_SEC = 30.0
DEFAULT_TRANSIENT_RETRIES = 2


@dataclass
class AuditResult:
    """One audit response from the Aletheia engine."""

    request_id: str
    decision: str
    reason: str | None
    receipt: dict[str, Any]
    raw: dict[str, Any]


@dataclass
class _RetryableAuditAnomaly(Exception):
    status_code: int
    reason: str
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
        transient_retries: int = DEFAULT_TRANSIENT_RETRIES,
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
        self.transient_retries = max(0, int(transient_retries))
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
        attempts = self.transient_retries + 1
        last_anomaly: _RetryableAuditAnomaly | None = None

        for attempt in range(1, attempts + 1):
            resp = self._client.post(
                "/api/v1/audit",
                json={"payload": payload, "action": action, "origin": origin},
            )
            try:
                return self._parse_audit_response(resp, attempt=attempt, attempts=attempts)
            except _RetryableAuditAnomaly as anomaly:
                last_anomaly = anomaly
                if attempt >= attempts:
                    break

        assert last_anomaly is not None
        decision = "DENIED" if last_anomaly.status_code == 403 else "UNKNOWN"
        return AuditResult(
            request_id="",
            decision=decision,
            reason=f"{last_anomaly.reason}; treated as {decision}",
            receipt={},
            raw=last_anomaly.raw,
        )

    def _parse_audit_response(self, resp: httpx.Response, *, attempt: int, attempts: int) -> AuditResult:
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
            raise _RetryableAuditAnomaly(
                status_code=resp.status_code,
                reason=self._retry_reason(
                    f"Empty JSON response body from server (status {resp.status_code})",
                    attempt=attempt,
                    attempts=attempts,
                ),
                raw={
                    "status_code": resp.status_code,
                    "empty_body": True,
                    "empty_body_anomaly": resp.status_code == 200,
                    "attempt": attempt,
                    "attempts": attempts,
                },
            )

        try:
            body = resp.json()
        except JSONDecodeError as exc:
            raise _RetryableAuditAnomaly(
                status_code=resp.status_code,
                reason=self._retry_reason(
                    f"Invalid JSON response body from server (status {resp.status_code}): {exc}",
                    attempt=attempt,
                    attempts=attempts,
                ),
                raw={
                    "status_code": resp.status_code,
                    "invalid_json": True,
                    "attempt": attempt,
                    "attempts": attempts,
                },
            ) from exc

        if not isinstance(body, dict):
            raise _RetryableAuditAnomaly(
                status_code=resp.status_code,
                reason=self._retry_reason(
                    f"Unexpected JSON payload type from server (status {resp.status_code})",
                    attempt=attempt,
                    attempts=attempts,
                ),
                raw={
                    "status_code": resp.status_code,
                    "invalid_payload_type": type(body).__name__,
                    "attempt": attempt,
                    "attempts": attempts,
                },
            )

        decision = body.get("decision")
        if not decision and resp.status_code == 403:
            decision = "DENIED"

        if not decision:
            raise _RetryableAuditAnomaly(
                status_code=resp.status_code,
                reason=self._retry_reason(
                    f"Missing decision in JSON response body from server (status {resp.status_code})",
                    attempt=attempt,
                    attempts=attempts,
                ),
                raw={
                    "status_code": resp.status_code,
                    "missing_decision": True,
                    "attempt": attempt,
                    "attempts": attempts,
                    "body": body,
                },
            )

        return AuditResult(
            request_id=body.get("request_id") or body.get("metadata", {}).get("request_id", ""),
            decision=decision,
            reason=body.get("reason") or body.get("error"),
            receipt=body.get("receipt", {}),
            raw=body,
        )

    def _retry_reason(self, message: str, *, attempt: int, attempts: int) -> str:
        if attempt >= attempts:
            return f"{message} after {attempts} attempts"
        return f"{message}; retrying ({attempt}/{attempts})"

    def audit_conversation(
        self,
        turns: list[str],
        *,
        action: str,
        origin: str,
        include_context: bool = True,
    ) -> list[AuditResult]:
        """Audit a multi-turn conversation by carrying forward prior turn outcomes."""
        results: list[AuditResult] = []
        context_lines: list[str] = []

        for index, turn in enumerate(turns, 1):
            payload = turn
            if include_context and context_lines:
                context_blob = "\n".join(context_lines)
                payload = (
                    "Conversation context from earlier turns:\n"
                    f"{context_blob}\n\n"
                    f"Current user turn ({index}/{len(turns)}):\n{turn}"
                )

            result = self.audit(payload=payload, action=action, origin=origin)
            results.append(result)
            context_lines.append(
                f"Turn {index}: decision={result.decision}; reason={result.reason or 'none'}"
            )

        return results

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AletheiaClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()