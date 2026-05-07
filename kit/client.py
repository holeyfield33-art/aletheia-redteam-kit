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
    request_id: str


@dataclass
class DecisionLookup:
    request_id: str
    decision: str | None
    endpoint: str | None
    auth_mode: str


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
            request_id=last_anomaly.request_id,
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
            request_id = self._extract_request_id(body=None, response=resp)
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
                request_id=request_id,
            )

        try:
            body = resp.json()
        except JSONDecodeError as exc:
            request_id = self._extract_request_id(body=None, response=resp)
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
                request_id=request_id,
            ) from exc

        if not isinstance(body, dict):
            request_id = self._extract_request_id(body=None, response=resp)
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
                request_id=request_id,
            )

        decision = body.get("decision")
        if not decision and resp.status_code == 403:
            decision = "DENIED"

        if not decision:
            request_id = self._extract_request_id(body=body, response=resp)
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
                request_id=request_id,
            )

        return AuditResult(
            request_id=self._extract_request_id(body=body, response=resp),
            decision=decision,
            reason=body.get("reason") or body.get("error"),
            receipt=body.get("receipt", {}),
            raw=body,
        )

    def lookup_decision(self, request_id: str) -> DecisionLookup:
        """Resolve authoritative decision for a request_id from available APIs."""
        normalized_request_id = str(request_id or "").strip()
        if not normalized_request_id:
            return DecisionLookup(request_id="", decision=None, endpoint=None, auth_mode="not_applicable")

        receipt_paths = [
            f"/api/v1/receipt/{normalized_request_id}",
            f"/v1/receipt/{normalized_request_id}",
        ]
        for path in receipt_paths:
            try:
                response = self._client.get(path)
            except httpx.HTTPError:
                continue

            if response.status_code == 200:
                decision = self._decision_from_payload(self._safe_json(response), normalized_request_id)
                if decision:
                    return DecisionLookup(
                        request_id=normalized_request_id,
                        decision=decision,
                        endpoint=f"{self.base_url}{path}",
                        auth_mode="api_key",
                    )
            if response.status_code in {401, 403}:
                return DecisionLookup(
                    request_id=normalized_request_id,
                    decision=None,
                    endpoint=f"{self.base_url}{path}",
                    auth_mode="session_cookie_required",
                )

        dashboard_base = os.environ.get("ALETHEIA_DASHBOARD_BASE_URL", "https://app.aletheia-core.com").rstrip("/")
        with httpx.Client(
            base_url=dashboard_base,
            headers={
                "X-API-Key": self.api_key,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
            timeout=self._client.timeout,
        ) as dashboard_client:
            for query_key in ("request_id", "requestId"):
                try:
                    response = dashboard_client.get("/api/logs", params={query_key: normalized_request_id})
                except httpx.HTTPError:
                    continue

                if response.status_code == 200:
                    decision = self._decision_from_payload(self._safe_json(response), normalized_request_id)
                    if decision:
                        return DecisionLookup(
                            request_id=normalized_request_id,
                            decision=decision,
                            endpoint=f"{dashboard_base}/api/logs",
                            auth_mode="api_key",
                        )
                    continue

                if response.status_code in {401, 403}:
                    return DecisionLookup(
                        request_id=normalized_request_id,
                        decision=None,
                        endpoint=f"{dashboard_base}/api/logs",
                        auth_mode="session_cookie_required",
                    )

        return DecisionLookup(request_id=normalized_request_id, decision=None, endpoint=None, auth_mode="unknown")

    def _extract_request_id(self, *, body: dict[str, Any] | None, response: httpx.Response | None) -> str:
        if isinstance(body, dict):
            candidates = [
                body.get("request_id"),
                (body.get("metadata") or {}).get("request_id"),
                (body.get("receipt") or {}).get("request_id"),
            ]
            for candidate in candidates:
                normalized = str(candidate or "").strip()
                if normalized:
                    return normalized

        if response is not None:
            for header_name in ("x-request-id", "x-correlation-id"):
                normalized = str(response.headers.get(header_name, "")).strip()
                if normalized:
                    return normalized

        return ""

    def _safe_json(self, response: httpx.Response) -> Any:
        try:
            return response.json()
        except Exception:
            return None

    def _decision_from_payload(self, payload: Any, request_id: str) -> str | None:
        if isinstance(payload, dict):
            decision = self._normalize_decision(payload.get("decision"))
            if decision:
                return decision

            receipt = payload.get("receipt")
            if isinstance(receipt, dict):
                decision = self._normalize_decision(receipt.get("decision"))
                if decision:
                    return decision

            rows = payload.get("results") or payload.get("logs") or payload.get("items") or []
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    row_request_id = str(
                        row.get("request_id") or row.get("requestId") or (row.get("receipt") or {}).get("request_id") or ""
                    ).strip()
                    if row_request_id and row_request_id != request_id:
                        continue
                    decision = self._normalize_decision(row.get("decision") or row.get("outcome") or row.get("status"))
                    if decision:
                        return decision
            return None

        if isinstance(payload, list):
            for row in payload:
                if not isinstance(row, dict):
                    continue
                row_request_id = str(
                    row.get("request_id") or row.get("requestId") or (row.get("receipt") or {}).get("request_id") or ""
                ).strip()
                if row_request_id and row_request_id != request_id:
                    continue
                decision = self._normalize_decision(row.get("decision") or row.get("outcome") or row.get("status"))
                if decision:
                    return decision

        return None

    def _normalize_decision(self, value: Any) -> str | None:
        normalized = str(value or "").strip().upper()
        if normalized in {"PROCEED", "DENIED", "SANDBOX_BLOCKED", "UNKNOWN", "ERROR"}:
            return normalized
        return None

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