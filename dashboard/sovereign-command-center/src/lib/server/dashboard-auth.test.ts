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

const TEST_USERNAME = "aletheia";
const TEST_PASSWORD = "secret-pass"; // nosec aletheia-redteam:allowed-test-fixture
const TEST_SESSION_SECRET = "session-secret"; // nosec aletheia-redteam:allowed-test-fixture

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
      ALETHEIA_DASHBOARD_PASSWORD: TEST_PASSWORD,
      ALETHEIA_DASHBOARD_USERNAME: TEST_USERNAME,
      ALETHEIA_DASHBOARD_AUTH_MODE: undefined,
    },
    () => {
      const config = resolveDashboardAuthConfig();
      assert.equal(config.mode, "basic");
      assert.equal(config.username, TEST_USERNAME);
      assert.ok(config.passwordHash);
    },
  ));

test("authorizeDashboardRequest accepts valid session cookies", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: TEST_PASSWORD,
      ALETHEIA_DASHBOARD_SESSION_SECRET: TEST_SESSION_SECRET,
    },
    () => {
      const config = resolveDashboardAuthConfig();
      const token = createSessionToken(TEST_USERNAME, config);
      const request = new NextRequest("http://localhost/api/payloads", {
        headers: {
          cookie: `${config.sessionCookieName}=${token}`,
        },
      });
      const result = authorizeDashboardRequest(request, config);
      assert.equal(result.authorized, true);
      assert.equal(result.principal, TEST_USERNAME);
      assert.equal(result.via, "session");
    },
  ));

test("authorizeDashboardRequest treats malformed session signatures as unauthorized", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: TEST_PASSWORD,
      ALETHEIA_DASHBOARD_SESSION_SECRET: TEST_SESSION_SECRET,
    },
    () => {
      const config = resolveDashboardAuthConfig();
      const request = new NextRequest("http://localhost/api/payloads", {
        headers: {
          cookie: `${config.sessionCookieName}=malformed.short`,
        },
      });

      const result = authorizeDashboardRequest(request, config);
      assert.equal(result.authorized, false);
      assert.equal(result.reason, "login_required");
    },
  ));

test("proxy redirects unauthenticated browser requests to login", () =>
  withEnv(
    {
      ALETHEIA_DASHBOARD_PASSWORD: TEST_PASSWORD,
      ALETHEIA_DASHBOARD_SESSION_SECRET: TEST_SESSION_SECRET,
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
      ALETHEIA_DASHBOARD_PASSWORD: TEST_PASSWORD,
      ALETHEIA_DASHBOARD_USERNAME: TEST_USERNAME,
      ALETHEIA_DASHBOARD_SESSION_SECRET: TEST_SESSION_SECRET,
    },
    async () => {
      const form = new FormData();
      form.set("username", TEST_USERNAME);
      form.set("password", TEST_PASSWORD);
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
