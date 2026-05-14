import { NextRequest, NextResponse } from "next/server";
import {
  attachSessionCookie,
  authenticateDashboardLogin,
  emitDashboardAuthWarnings,
  resolveDashboardAuthConfig,
  sanitizeNextPath,
} from "@/lib/server/dashboard-auth";

function loginRedirect(request: NextRequest, nextPath: string, errorCode?: string): NextResponse {
  const redirectUrl = new URL("/login", request.url);
  redirectUrl.searchParams.set("next", sanitizeNextPath(nextPath));
  if (errorCode) {
    redirectUrl.searchParams.set("error", errorCode);
  }
  return NextResponse.redirect(redirectUrl, { status: 303 });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const config = resolveDashboardAuthConfig();
  emitDashboardAuthWarnings(config);
  if (config.mode !== "basic") {
    return NextResponse.json({ ok: false, error: "login_unavailable" }, { status: 404 });
  }

  const form = await request.formData();
  const username = String(form.get("username") ?? "");
  const password = String(form.get("password") ?? "");
  const nextPath = sanitizeNextPath(String(form.get("next") ?? "/"));
  const clientIp = request.headers.get("x-forwarded-for")?.split(",", 1)[0]?.trim() || "unknown";
  const result = authenticateDashboardLogin(username, password, clientIp, config);

  if (!result.authorized || !result.principal) {
    const response = loginRedirect(request, nextPath, result.reason);
    if (result.retryAfter != null) {
      response.headers.set("Retry-After", String(result.retryAfter));
    }
    return response;
  }

  return attachSessionCookie(NextResponse.redirect(new URL(nextPath, request.url), { status: 303 }), result.principal, config);
}
