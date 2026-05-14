import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { POST as loginPost } from "@/app/api/auth/login/route";
import { proxy } from "@/proxy";
import {
  authorizeDashboardRequest,
  createSessionToken,
  resetDashboardAuthState,
  resolveDashboardAuthConfig,
} from "./dashboard-auth";

function withEnv(values: Record<string, string | undefined>, run: () => Promise<void> | void): Promise<void> | void {
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(values)) {
    previous.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  resetDashboardAuthState();
  const finish = () => {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    resetDashboardAuthState();
  };

  try {
    const result = run();
    if (result instanceof Promise) {
      return result.finally(finish);
    }
    finish();
  } catch (error) {
    finish();
    throw error;
  }
}

test("resolveDashboardAuthConfig auto-detects basic auth from env", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: "secret-pass",
      ALETHEIA_DASHBOARD_USERNAME: "aletheia",
      ALETHEIA_DASHBOARD_AUTH_MODE: undefined,
    },
    () => {
      const config = resolveDashboardAuthConfig();
      assert.equal(config.mode, "basic");
      assert.equal(config.username, "aletheia");
      assert.ok(config.passwordHash);
    },
  ));

test("authorizeDashboardRequest accepts valid session cookies", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: "secret-pass",
      ALETHEIA_DASHBOARD_SESSION_SECRET: "session-secret",
    },
    () => {
      const config = resolveDashboardAuthConfig();
      const token = createSessionToken("aletheia", config);
      const request = new NextRequest("http://localhost/api/payloads", {
        headers: {
          cookie: `${config.sessionCookieName}=${token}`,
        },
      });
      const result = authorizeDashboardRequest(request, config);
      assert.equal(result.authorized, true);
      assert.equal(result.principal, "aletheia");
      assert.equal(result.via, "session");
    },
  ));

test("proxy redirects unauthenticated browser requests to login", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: "secret-pass",
      ALETHEIA_DASHBOARD_SESSION_SECRET: "session-secret",
    },
    () => {
      const response = proxy(new NextRequest("http://localhost/"));
      assert.equal(response.status, 307);
      assert.match(response.headers.get("location") ?? "", /^http:\/\/localhost\/login\?/);
    },
  ));

test("login route sets a session cookie for valid credentials", async () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: "secret-pass",
      ALETHEIA_DASHBOARD_USERNAME: "aletheia",
      ALETHEIA_DASHBOARD_SESSION_SECRET: "session-secret",
    },
    async () => {
      const form = new FormData();
      form.set("username", "aletheia");
      form.set("password", "secret-pass");
      form.set("next", "/");
      const request = new NextRequest("http://localhost/api/auth/login", {
        method: "POST",
        body: form,
      });
      const response = await loginPost(request);
      assert.equal(response.status, 303);
      assert.equal(response.headers.get("location"), "http://localhost/");
      assert.match(response.headers.get("set-cookie") ?? "", /aletheia_dashboard_session=/);
    },
  ));
