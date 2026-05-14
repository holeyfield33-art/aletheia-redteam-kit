import { NextRequest, NextResponse } from "next/server";
import {
  authorizeDashboardRequest,
  buildUnauthorizedApiResponse,
  emitDashboardAuthWarnings,
  resolveDashboardAuthConfig,
  sanitizeNextPath,
} from "@/lib/server/dashboard-auth";

function isExemptPath(pathname: string): boolean {
  return (
    pathname === "/login" ||
    pathname === "/api/health" ||
    pathname.startsWith("/api/auth/") ||
    pathname.startsWith("/_next/") ||
    pathname === "/favicon.ico"
  );
}

export function proxy(request: NextRequest): NextResponse {
  const config = resolveDashboardAuthConfig();
  emitDashboardAuthWarnings(config);

  if (config.mode === "disabled" || isExemptPath(request.nextUrl.pathname)) {
    return NextResponse.next();
  }

  const result = authorizeDashboardRequest(request, config);
  if (result.authorized) {
    return NextResponse.next();
  }

  if (request.nextUrl.pathname.startsWith("/api/")) {
    return buildUnauthorizedApiResponse(result, config);
  }

  const loginUrl = new URL("/login", request.url);
  loginUrl.searchParams.set("next", sanitizeNextPath(`${request.nextUrl.pathname}${request.nextUrl.search}`));
  loginUrl.searchParams.set("error", result.reason);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
