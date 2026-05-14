import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

export type DashboardAuthMode = "disabled" | "basic" | "api-key" | "proxy";

export interface DashboardAuthConfig {
  mode: DashboardAuthMode;
  username: string | null;
  passwordHash: string | null;
  apiKeyHeader: string;
  apiKeyHash: string | null;
  sessionSecret: string;
  sessionCookieName: string;
  sessionTtlSeconds: number;
  secureCookies: boolean;
  trustProxyHeaders: boolean;
  proxyUserHeader: string;
  proxyAuthorizationHeader: string;
  rateLimitAttempts: number;
  rateLimitWindowSeconds: number;
  lockoutSeconds: number;
  warnings: string[];
}

export interface DashboardAuthResult {
  authorized: boolean;
  principal?: string;
  via?: string;
  status: number;
  reason: string;
  retryAfter?: number;
  challenge?: string;
}

interface RateLimitState {
  attempts: number[];
  lockedUntil: number;
}

interface CookieLike {
  value: string;
}

export interface RequestLike {
  headers: Headers;
  cookies?: {
    get(name: string): CookieLike | undefined;
  };
}

const rateLimitState = new Map<string, RateLimitState>();
let cachedConfigSignature = "";
let cachedConfig: DashboardAuthConfig | null = null;
let generatedSessionSecret = "";
const emittedWarnings = new Set<string>();

function envFlag(name: string, defaultValue: boolean): boolean {
  const raw = process.env[name];
  if (raw == null) {
    return defaultValue;
  }
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function loadHashFromEnv(hashName: string, plainName: string, warningLabel: string): { hash: string | null; warnings: string[] } {
  const warnings: string[] = [];
  const hashed = (process.env[hashName] ?? "").trim();
  if (hashed) {
    return { hash: hashed, warnings };
  }

  const plaintext = process.env[plainName];
  if (!plaintext) {
    return { hash: null, warnings };
  }

  warnings.push(
    `${warningLabel} is configured via ${plainName}; prefer a bcrypt hash in ${hashName} for production deployments.`,
  );
  return { hash: bcrypt.hashSync(plaintext, 10), warnings };
}

function configSignature(): string {
  return JSON.stringify({
    authMode: process.env.ALETHEIA_DASHBOARD_AUTH_MODE,
    username: process.env.ALETHEIA_DASHBOARD_USERNAME,
    password: process.env.ALETHEIA_DASHBOARD_PASSWORD,
    passwordHash: process.env.ALETHEIA_DASHBOARD_PASSWORD_HASH,
    apiKey: process.env.ALETHEIA_DASHBOARD_API_KEY,
    apiKeyHash: process.env.ALETHEIA_DASHBOARD_API_KEY_HASH,
    apiKeyHeader: process.env.ALETHEIA_DASHBOARD_API_KEY_HEADER,
    sessionSecret: process.env.ALETHEIA_DASHBOARD_SESSION_SECRET,
    sessionCookie: process.env.ALETHEIA_DASHBOARD_SESSION_COOKIE,
    sessionTtlHours: process.env.ALETHEIA_DASHBOARD_SESSION_TTL_HOURS,
    secureCookies: process.env.ALETHEIA_DASHBOARD_SECURE_COOKIES,
    trustProxy: process.env.ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH,
    proxyUserHeader: process.env.ALETHEIA_DASHBOARD_PROXY_USER_HEADER,
    proxyAuthorizationHeader: process.env.ALETHEIA_DASHBOARD_PROXY_AUTHORIZATION_HEADER,
    loginAttempts: process.env.ALETHEIA_DASHBOARD_LOGIN_ATTEMPTS,
    loginWindow: process.env.ALETHEIA_DASHBOARD_LOGIN_WINDOW_SECONDS,
    lockout: process.env.ALETHEIA_DASHBOARD_LOCKOUT_SECONDS,
    nodeEnv: process.env.NODE_ENV,
  });
}

export function sanitizeNextPath(pathname?: string | null): string {
  const raw = String(pathname ?? "").trim();
  if (!raw.startsWith("/") || raw.startsWith("//")) {
    return "/";
  }
  return raw;
}

export function resolveDashboardAuthConfig(): DashboardAuthConfig {
  const signature = configSignature();
  if (cachedConfig && signature === cachedConfigSignature) {
    return cachedConfig;
  }

  const warnings: string[] = [];
  const requestedMode = ((process.env.ALETHEIA_DASHBOARD_AUTH_MODE ?? "auto").trim().toLowerCase() || "auto") as
    | "auto"
    | DashboardAuthMode;
  const username = (process.env.ALETHEIA_DASHBOARD_USERNAME ?? "aletheia").trim() || "aletheia";
  const passwordResult = loadHashFromEnv(
    "ALETHEIA_DASHBOARD_PASSWORD_HASH",
    "ALETHEIA_DASHBOARD_PASSWORD",
    "dashboard password",
  );
  const apiKeyResult = loadHashFromEnv(
    "ALETHEIA_DASHBOARD_API_KEY_HASH",
    "ALETHEIA_DASHBOARD_API_KEY",
    "dashboard api key",
  );
  warnings.push(...passwordResult.warnings, ...apiKeyResult.warnings);

  const trustProxyHeaders = envFlag("ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH", false);
  let resolvedMode: DashboardAuthMode;
  if (requestedMode === "auto") {
    if (apiKeyResult.hash) {
      resolvedMode = "api-key";
    } else if (passwordResult.hash) {
      resolvedMode = "basic";
    } else if (trustProxyHeaders) {
      resolvedMode = "proxy";
    } else {
      resolvedMode = "disabled";
    }
  } else {
    resolvedMode = requestedMode;
  }

  if (resolvedMode === "basic" && !passwordResult.hash) {
    throw new Error(
      "Sovereign Command Center basic auth requires ALETHEIA_DASHBOARD_PASSWORD or ALETHEIA_DASHBOARD_PASSWORD_HASH",
    );
  }
  if (resolvedMode === "api-key" && !apiKeyResult.hash) {
    throw new Error(
      "Sovereign Command Center API key auth requires ALETHEIA_DASHBOARD_API_KEY or ALETHEIA_DASHBOARD_API_KEY_HASH",
    );
  }
  if (resolvedMode === "proxy" && !trustProxyHeaders) {
    throw new Error("Sovereign Command Center proxy auth requires ALETHEIA_DASHBOARD_TRUST_PROXY_AUTH=true");
  }
  if (resolvedMode === "disabled") {
    warnings.push(
      "Sovereign Command Center auth is disabled; only expose it on a trusted network or behind a reverse proxy.",
    );
  }

  if (!generatedSessionSecret) {
    generatedSessionSecret = crypto.randomBytes(32).toString("hex");
  }
  const sessionSecret = process.env.ALETHEIA_DASHBOARD_SESSION_SECRET || generatedSessionSecret;
  if (resolvedMode === "basic" && !process.env.ALETHEIA_DASHBOARD_SESSION_SECRET) {
    warnings.push(
      "ALETHEIA_DASHBOARD_SESSION_SECRET is not set; generated an ephemeral secret for this process.",
    );
  }

  const config: DashboardAuthConfig = {
    mode: resolvedMode,
    username: resolvedMode === "basic" ? username : null,
    passwordHash: passwordResult.hash,
    apiKeyHeader: (process.env.ALETHEIA_DASHBOARD_API_KEY_HEADER ?? "X-API-Key").trim() || "X-API-Key",
    apiKeyHash: apiKeyResult.hash,
    sessionSecret,
    sessionCookieName:
      (process.env.ALETHEIA_DASHBOARD_SESSION_COOKIE ?? "aletheia_dashboard_session").trim() ||
      "aletheia_dashboard_session",
    sessionTtlSeconds: Math.max(3600, Number(process.env.ALETHEIA_DASHBOARD_SESSION_TTL_HOURS ?? "12") * 3600),
    secureCookies: envFlag("ALETHEIA_DASHBOARD_SECURE_COOKIES", process.env.NODE_ENV === "production"),
    trustProxyHeaders,
    proxyUserHeader: (process.env.ALETHEIA_DASHBOARD_PROXY_USER_HEADER ?? "X-Forwarded-User").trim() || "X-Forwarded-User",
    proxyAuthorizationHeader:
      (process.env.ALETHEIA_DASHBOARD_PROXY_AUTHORIZATION_HEADER ?? "Authorization").trim() || "Authorization",
    rateLimitAttempts: Math.max(1, Number(process.env.ALETHEIA_DASHBOARD_LOGIN_ATTEMPTS ?? "5")),
    rateLimitWindowSeconds: Math.max(60, Number(process.env.ALETHEIA_DASHBOARD_LOGIN_WINDOW_SECONDS ?? "900")),
    lockoutSeconds: Math.max(60, Number(process.env.ALETHEIA_DASHBOARD_LOCKOUT_SECONDS ?? "900")),
    warnings,
  };

  cachedConfig = config;
  cachedConfigSignature = signature;
  return config;
}

export function emitDashboardAuthWarnings(config: DashboardAuthConfig = resolveDashboardAuthConfig()): void {
  for (const warning of config.warnings) {
    if (emittedWarnings.has(warning)) {
      continue;
    }
    emittedWarnings.add(warning);
    console.warn(warning);
  }
}

function parseBasicAuthHeader(value: string | null): { username: string; password: string } | null {
  const raw = String(value ?? "").trim();
  if (!raw.toLowerCase().startsWith("basic ")) {
    return null;
  }
  const token = raw.split(/\s+/, 2)[1] ?? "";
  if (!token) {
    return null;
  }
  try {
    const decoded = Buffer.from(token, "base64").toString("utf8");
    if (!decoded.includes(":")) {
      return null;
    }
    const [username, password] = decoded.split(":", 2);
    return { username, password };
  } catch {
    return null;
  }
}

function pruneRateLimit(state: RateLimitState, nowMs: number, config: DashboardAuthConfig): void {
  const cutoff = nowMs - config.rateLimitWindowSeconds * 1000;
  while (state.attempts.length > 0 && state.attempts[0] < cutoff) {
    state.attempts.shift();
  }
}

export function resetDashboardAuthState(): void {
  rateLimitState.clear();
  cachedConfig = null;
  cachedConfigSignature = "";
  emittedWarnings.clear();
}

export function createSessionToken(principal: string, config: DashboardAuthConfig = resolveDashboardAuthConfig(), nowMs: number = Date.now()): string {
  const payload = {
    sub: principal,
    iat: Math.floor(nowMs / 1000),
    exp: Math.floor(nowMs / 1000) + config.sessionTtlSeconds,
  };
  const payloadToken = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", config.sessionSecret).update(payloadToken).digest("base64url");
  return `${payloadToken}.${signature}`;
}

export function verifySessionToken(
  token: string | undefined,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
  nowMs: number = Date.now(),
): string | null {
  if (!token || config.mode !== "basic") {
    return null;
  }
  const segments = token.split(".");
  if (segments.length !== 2) {
    return null;
  }
  const [payloadToken, signature] = segments;
  const expectedSignature = crypto.createHmac("sha256", config.sessionSecret).update(payloadToken).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(payloadToken, "base64url").toString("utf8")) as {
      sub?: string;
      exp?: number;
    };
    if (!payload.sub || !payload.exp || payload.exp <= Math.floor(nowMs / 1000)) {
      return null;
    }
    return payload.sub;
  } catch {
    return null;
  }
}

export function authenticateDashboardLogin(
  username: string,
  password: string,
  clientIp: string,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
  nowMs: number = Date.now(),
): DashboardAuthResult {
  if (config.mode !== "basic" || !config.passwordHash || !config.username) {
    return { authorized: false, status: 404, reason: "login_unavailable" };
  }

  const state = rateLimitState.get(clientIp) ?? { attempts: [], lockedUntil: 0 };
  pruneRateLimit(state, nowMs, config);
  if (state.lockedUntil > nowMs) {
    return {
      authorized: false,
      status: 429,
      reason: "too_many_attempts",
      retryAfter: Math.max(1, Math.ceil((state.lockedUntil - nowMs) / 1000)),
    };
  }

  const valid = username === config.username && bcrypt.compareSync(password, config.passwordHash);
  if (valid) {
    rateLimitState.delete(clientIp);
    console.info(`dashboard.auth.login.success ip=${clientIp} user=${username}`);
    return { authorized: true, principal: username, via: "login", status: 303, reason: "ok" };
  }

  state.attempts.push(nowMs);
  pruneRateLimit(state, nowMs, config);
  if (state.attempts.length >= config.rateLimitAttempts) {
    state.lockedUntil = nowMs + config.lockoutSeconds * 1000;
  }
  rateLimitState.set(clientIp, state);
  const status = state.lockedUntil > nowMs ? 429 : 401;
  console.warn(`dashboard.auth.login.failure ip=${clientIp} user=${username || "unknown"} status=${status}`);
  return {
    authorized: false,
    status,
    reason: status === 429 ? "too_many_attempts" : "invalid_credentials",
    retryAfter: status === 429 ? config.lockoutSeconds : undefined,
  };
}

function readCookieValue(request: RequestLike, cookieName: string): string | undefined {
  return request.cookies?.get(cookieName)?.value;
}

export function authorizeDashboardRequest(
  request: RequestLike,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
): DashboardAuthResult {
  if (config.mode === "disabled") {
    return { authorized: true, principal: "anonymous", via: "disabled", status: 200, reason: "disabled" };
  }

  if (config.mode === "proxy") {
    const forwardedUser = request.headers.get(config.proxyUserHeader)?.trim();
    if (forwardedUser) {
      console.info(`dashboard.auth.success mode=proxy via=header user=${forwardedUser}`);
      return { authorized: true, principal: forwardedUser, via: "proxy_header", status: 200, reason: "ok" };
    }
    const forwardedAuthorization = request.headers.get(config.proxyAuthorizationHeader)?.trim();
    if (forwardedAuthorization) {
      console.info("dashboard.auth.success mode=proxy via=authorization_header");
      return { authorized: true, principal: "proxy-user", via: "proxy_authorization", status: 200, reason: "ok" };
    }
    return { authorized: false, status: 401, reason: "missing_proxy_identity" };
  }

  if (config.mode === "api-key") {
    const providedKey =
      request.headers.get(config.apiKeyHeader)?.trim() ||
      request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "").trim() ||
      "";
    if (providedKey && config.apiKeyHash && bcrypt.compareSync(providedKey, config.apiKeyHash)) {
      console.info("dashboard.auth.success mode=api-key");
      return { authorized: true, principal: "api-key", via: "api-key", status: 200, reason: "ok" };
    }
    return { authorized: false, status: 401, reason: "invalid_api_key" };
  }

  const sessionPrincipal = verifySessionToken(readCookieValue(request, config.sessionCookieName), config);
  if (sessionPrincipal) {
    return { authorized: true, principal: sessionPrincipal, via: "session", status: 200, reason: "ok" };
  }

  const basic = parseBasicAuthHeader(request.headers.get("Authorization"));
  if (
    basic &&
    config.passwordHash &&
    config.username &&
    basic.username === config.username &&
    bcrypt.compareSync(basic.password, config.passwordHash)
  ) {
    return {
      authorized: true,
      principal: basic.username,
      via: "basic_header",
      status: 200,
      reason: "ok",
    };
  }

  return {
    authorized: false,
    status: 401,
    reason: "login_required",
    challenge: 'Basic realm="Aletheia Dashboard"',
  };
}

export function attachSessionCookie(
  response: NextResponse,
  principal: string,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
): NextResponse {
  response.cookies.set({
    name: config.sessionCookieName,
    value: createSessionToken(principal, config),
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: "strict",
    maxAge: config.sessionTtlSeconds,
    path: "/",
  });
  return response;
}

export function clearSessionCookie(
  response: NextResponse,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
): NextResponse {
  response.cookies.set({
    name: config.sessionCookieName,
    value: "",
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: "strict",
    maxAge: 0,
    path: "/",
  });
  return response;
}

export function buildUnauthorizedApiResponse(
  result: DashboardAuthResult,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
): NextResponse {
  const response = NextResponse.json({ ok: false, error: result.reason, authMode: config.mode }, { status: result.status });
  if (result.challenge) {
    response.headers.set("WWW-Authenticate", result.challenge);
  }
  if (result.retryAfter != null) {
    response.headers.set("Retry-After", String(result.retryAfter));
  }
  return response;
}

export function authorizeApiRouteRequest(
  request: NextRequest,
  config: DashboardAuthConfig = resolveDashboardAuthConfig(),
): NextResponse | null {
  const result = authorizeDashboardRequest(request, config);
  if (result.authorized) {
    return null;
  }
  return buildUnauthorizedApiResponse(result, config);
}
