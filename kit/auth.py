from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from secrets import token_urlsafe
from typing import Callable, Mapping

import bcrypt

LOGGER = logging.getLogger(__name__)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _base64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _parse_basic_auth_header(value: str) -> tuple[str, str] | None:
    raw = str(value or "").strip()
    if not raw.lower().startswith("basic "):
        return None
    token = raw.split(None, 1)[1].strip() if " " in raw else ""
    if not token:
        return None
    try:
        decoded = base64.b64decode(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def sanitize_next_path(path: str | None) -> str:
    raw = str(path or "").strip()
    if not raw.startswith("/") or raw.startswith("//"):
        return "/dashboard/"
    return raw


@dataclass(frozen=True)
class DashboardAuthConfig:
    mode: str
    username: str | None
    password_hash: bytes | None
    api_key_header: str
    api_key_hash: bytes | None
    session_secret: str
    session_cookie_name: str
    session_ttl_seconds: int
    secure_cookies: bool
    trust_proxy_headers: bool
    proxy_user_header: str
    proxy_authorization_header: str
    rate_limit_attempts: int
    rate_limit_window_seconds: int
    lockout_seconds: int
    warnings: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return self.mode != "disabled"


@dataclass(frozen=True)
class DashboardAuthOutcome:
    allowed: bool
    principal: str | None = None
    via: str | None = None
    status: int = HTTPStatus.UNAUTHORIZED
    reason: str = "authentication_required"
    retry_after: int | None = None
    challenge: str | None = None


@dataclass
class _RateLimitState:
    failed_attempts: deque[float] = field(default_factory=deque)
    locked_until: float = 0.0


class DashboardAuthManager:
    def __init__(
        self,
        config: DashboardAuthConfig,
        *,
        logger: logging.Logger | None = None,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.logger = logger or LOGGER
        self._now_fn = now_fn or time.time
        self._rate_limit: dict[str, _RateLimitState] = {}

    @classmethod
    def from_env(cls, *, auth_mode: str = "auto", host: str = "127.0.0.1") -> "DashboardAuthManager":
        warnings: list[str] = []
        username = os.environ.get("ALETHEIA_DASHBOARD_USERNAME", "aletheia") or "aletheia"
        password_hash = _load_hash_from_env(
            hash_name="ALETHEIA_DASHBOARD_PASSWORD_HASH",
            plaintext_name="ALETHEIA_DASHBOARD_PASSWORD",
            warnings=warnings,
            warning_label="dashboard password",
        )
        api_key_hash = _load_hash_from_env(
            hash_name="ALETHEIA_DASHBOARD_API_KEY_HASH",
            plaintext_name="ALETHEIA_DASHBOARD_API_KEY",
            warnings=warnings,
            warning_label="dashboard API key",
        )
        trust_proxy_headers = _env_flag("ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH", False)
        proxy_user_header = os.environ.get("ALETHEIA_DASHBOARD_PROXY_USER_HEADER", "X-Forwarded-User") or "X-Forwarded-User"
        proxy_authorization_header = (
            os.environ.get("ALETHEIA_DASHBOARD_PROXY_AUTHORIZATION_HEADER", "Authorization") or "Authorization"
        )
        resolved_mode = auth_mode
        if auth_mode == "auto":
            if api_key_hash is not None:
                resolved_mode = "api-key"
            elif password_hash is not None:
                resolved_mode = "basic"
            elif trust_proxy_headers:
                resolved_mode = "proxy"
            else:
                resolved_mode = "disabled"

        if resolved_mode == "disabled":
            warnings.append(
                "Hosted dashboard authentication is disabled; expose only on trusted networks behind TLS termination and a hardened reverse proxy."
            )

        if resolved_mode == "basic" and password_hash is None:
            raise ValueError(
                "Dashboard basic auth requires ALETHEIA_DASHBOARD_PASSWORD or ALETHEIA_DASHBOARD_PASSWORD_HASH"
            )
        if resolved_mode == "api-key" and api_key_hash is None:
            raise ValueError(
                "Dashboard API key auth requires ALETHEIA_DASHBOARD_API_KEY or ALETHEIA_DASHBOARD_API_KEY_HASH"
            )
        if resolved_mode == "proxy" and not trust_proxy_headers:
            raise ValueError(
                "Dashboard proxy auth requires ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH=true"
            )

        session_secret = os.environ.get("ALETHEIA_DASHBOARD_SESSION_SECRET") or ""
        if resolved_mode == "basic" and not session_secret:
            session_secret = token_urlsafe(32)
            warnings.append(
                "ALETHEIA_DASHBOARD_SESSION_SECRET is not set; generated an ephemeral session secret for this process."
            )

        secure_default = host not in {"127.0.0.1", "localhost"}
        secure_cookies = _env_flag("ALETHEIA_DASHBOARD_SECURE_COOKIES", secure_default)

        config = DashboardAuthConfig(
            mode=resolved_mode,
            username=username,
            password_hash=password_hash,
            api_key_header=os.environ.get("ALETHEIA_DASHBOARD_API_KEY_HEADER", "X-API-Key") or "X-API-Key",
            api_key_hash=api_key_hash,
            session_secret=session_secret,
            session_cookie_name=(
                os.environ.get("ALETHEIA_DASHBOARD_SESSION_COOKIE", "aletheia_dashboard_session")
                or "aletheia_dashboard_session"
            ),
            session_ttl_seconds=max(3600, int(os.environ.get("ALETHEIA_DASHBOARD_SESSION_TTL_HOURS", "12")) * 3600),
            secure_cookies=secure_cookies,
            trust_proxy_headers=trust_proxy_headers,
            proxy_user_header=proxy_user_header,
            proxy_authorization_header=proxy_authorization_header,
            rate_limit_attempts=max(1, int(os.environ.get("ALETHEIA_DASHBOARD_LOGIN_ATTEMPTS", "5"))),
            rate_limit_window_seconds=max(60, int(os.environ.get("ALETHEIA_DASHBOARD_LOGIN_WINDOW_SECONDS", "900"))),
            lockout_seconds=max(60, int(os.environ.get("ALETHEIA_DASHBOARD_LOCKOUT_SECONDS", "900"))),
            warnings=tuple(warnings),
        )
        return cls(config)

    def log_startup_warnings(self) -> None:
        for warning in self.config.warnings:
            self.logger.warning(warning)

    def authenticate_request(
        self,
        *,
        headers: Mapping[str, str],
        client_ip: str,
    ) -> DashboardAuthOutcome:
        if not self.config.enabled:
            return DashboardAuthOutcome(allowed=True, principal="anonymous", via="disabled")

        if self.config.mode == "proxy":
            forwarded_user = str(headers.get(self.config.proxy_user_header, "")).strip()
            if forwarded_user:
                self.logger.info("dashboard.auth.success mode=proxy ip=%s user=%s", client_ip, forwarded_user)
                return DashboardAuthOutcome(allowed=True, principal=forwarded_user, via="proxy_header")
            forwarded_auth = str(headers.get(self.config.proxy_authorization_header, "")).strip()
            if forwarded_auth:
                self.logger.info("dashboard.auth.success mode=proxy ip=%s via=authorization_header", client_ip)
                return DashboardAuthOutcome(allowed=True, principal="proxy-user", via="proxy_authorization")
            self.logger.warning("dashboard.auth.failure mode=proxy ip=%s reason=missing_proxy_identity", client_ip)
            return DashboardAuthOutcome(allowed=False, reason="missing_proxy_identity")

        if self.config.mode == "api-key":
            provided = str(headers.get(self.config.api_key_header, "")).strip()
            if not provided:
                authorization = str(headers.get("Authorization", "")).strip()
                if authorization.lower().startswith("bearer "):
                    provided = authorization.split(None, 1)[1].strip() if " " in authorization else ""
            if provided and self.config.api_key_hash is not None and bcrypt.checkpw(
                provided.encode("utf-8"), self.config.api_key_hash
            ):
                self.logger.info("dashboard.auth.success mode=api-key ip=%s", client_ip)
                return DashboardAuthOutcome(allowed=True, principal="api-key", via="api-key")
            self.logger.warning("dashboard.auth.failure mode=api-key ip=%s reason=invalid_api_key", client_ip)
            return DashboardAuthOutcome(allowed=False, reason="invalid_api_key")

        session_principal = self._validate_session_cookie(headers.get("Cookie", ""))
        if session_principal is not None:
            return DashboardAuthOutcome(allowed=True, principal=session_principal, via="session")

        provided = _parse_basic_auth_header(headers.get("Authorization", ""))
        if (
            provided is not None
            and self.config.username is not None
            and provided[0] == self.config.username
            and self.config.password_hash is not None
            and bcrypt.checkpw(provided[1].encode("utf-8"), self.config.password_hash)
        ):
            self.logger.info("dashboard.auth.success mode=basic ip=%s via=authorization_header", client_ip)
            return DashboardAuthOutcome(
                allowed=True,
                principal=self.config.username,
                via="basic_header",
            )

        self.logger.warning("dashboard.auth.failure mode=basic ip=%s reason=login_required", client_ip)
        return DashboardAuthOutcome(
            allowed=False,
            reason="login_required",
            challenge='Basic realm="Aletheia Dashboard"',
        )

    def authenticate_login(self, *, username: str, password: str, client_ip: str) -> DashboardAuthOutcome:
        if self.config.mode != "basic":
            return DashboardAuthOutcome(allowed=False, status=HTTPStatus.NOT_FOUND, reason="login_unavailable")

        state = self._rate_limit.setdefault(client_ip, _RateLimitState())
        now = self._now_fn()
        self._prune_state(state, now)
        if state.locked_until > now:
            retry_after = max(1, int(state.locked_until - now))
            self.logger.warning("dashboard.auth.lockout ip=%s retry_after=%s", client_ip, retry_after)
            return DashboardAuthOutcome(
                allowed=False,
                status=HTTPStatus.TOO_MANY_REQUESTS,
                reason="too_many_attempts",
                retry_after=retry_after,
            )

        valid = (
            self.config.username is not None
            and username == self.config.username
            and self.config.password_hash is not None
            and bcrypt.checkpw(password.encode("utf-8"), self.config.password_hash)
        )
        if valid:
            self._rate_limit.pop(client_ip, None)
            self.logger.info("dashboard.auth.login.success ip=%s user=%s", client_ip, username)
            return DashboardAuthOutcome(allowed=True, principal=username, via="login", status=HTTPStatus.SEE_OTHER)

        state.failed_attempts.append(now)
        self._prune_state(state, now)
        retry_after = None
        status = HTTPStatus.UNAUTHORIZED
        if len(state.failed_attempts) >= self.config.rate_limit_attempts:
            state.locked_until = now + self.config.lockout_seconds
            retry_after = self.config.lockout_seconds
            status = HTTPStatus.TOO_MANY_REQUESTS
        self.logger.warning("dashboard.auth.login.failure ip=%s user=%s status=%s", client_ip, username, status)
        return DashboardAuthOutcome(
            allowed=False,
            status=status,
            reason="invalid_credentials",
            retry_after=retry_after,
        )

    def create_session_cookie(self, principal: str) -> str:
        now = int(self._now_fn())
        payload = {
            "sub": principal,
            "iat": now,
            "exp": now + self.config.session_ttl_seconds,
        }
        payload_blob = json_dumps(payload).encode("utf-8")
        payload_token = _base64url_encode(payload_blob)
        signature = hmac.new(
            self.config.session_secret.encode("utf-8"),
            payload_token.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return f"{payload_token}.{_base64url_encode(signature)}"

    def build_set_cookie_header(self, value: str) -> str:
        cookie = SimpleCookie()
        cookie[self.config.session_cookie_name] = value
        morsel = cookie[self.config.session_cookie_name]
        morsel["path"] = "/"
        morsel["max-age"] = str(self.config.session_ttl_seconds)
        morsel["httponly"] = True
        morsel["samesite"] = "Strict"
        if self.config.secure_cookies:
            morsel["secure"] = True
        return cookie.output(header="").strip()

    def build_logout_cookie_header(self) -> str:
        cookie = SimpleCookie()
        cookie[self.config.session_cookie_name] = ""
        morsel = cookie[self.config.session_cookie_name]
        morsel["path"] = "/"
        morsel["max-age"] = "0"
        morsel["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        morsel["httponly"] = True
        morsel["samesite"] = "Strict"
        if self.config.secure_cookies:
            morsel["secure"] = True
        return cookie.output(header="").strip()

    def _prune_state(self, state: _RateLimitState, now: float) -> None:
        cutoff = now - self.config.rate_limit_window_seconds
        while state.failed_attempts and state.failed_attempts[0] < cutoff:
            state.failed_attempts.popleft()

    def _validate_session_cookie(self, raw_cookie_header: str) -> str | None:
        if self.config.mode != "basic" or not raw_cookie_header:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie_header)
        except CookieError:
            return None
        morsel = cookie.get(self.config.session_cookie_name)
        if morsel is None:
            return None
        value = morsel.value.strip()
        if "." not in value:
            return None
        payload_token, signature_token = value.split(".", 1)
        try:
            expected_signature = hmac.new(
                self.config.session_secret.encode("utf-8"),
                payload_token.encode("ascii"),
                hashlib.sha256,
            ).digest()
            provided_signature = _base64url_decode(signature_token)
            if not hmac.compare_digest(expected_signature, provided_signature):
                return None
            payload = json_loads(_base64url_decode(payload_token).decode("utf-8"))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
        expires_at = int(payload.get("exp", 0))
        if expires_at <= int(self._now_fn()):
            return None
        principal = str(payload.get("sub") or "").strip()
        return principal or None


class CookieError(ValueError):
    pass


def json_dumps(payload: object) -> str:
    return __import__("json").dumps(payload, separators=(",", ":"), sort_keys=True)


def json_loads(raw: str) -> dict[str, object]:
    parsed = __import__("json").loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Invalid session payload")
    return parsed


def _load_hash_from_env(
    *,
    hash_name: str,
    plaintext_name: str,
    warnings: list[str],
    warning_label: str,
) -> bytes | None:
    hashed = str(os.environ.get(hash_name) or "").strip()
    if hashed:
        return hashed.encode("utf-8")

    plaintext = os.environ.get(plaintext_name)
    if not plaintext:
        return None

    warnings.append(
        f"{warning_label.capitalize()} is provided via {plaintext_name}; prefer a bcrypt hash in {hash_name} for production deployments."
    )
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12))