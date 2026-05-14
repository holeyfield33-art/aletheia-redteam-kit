import { NextRequest, NextResponse } from "next/server";
import { clearSessionCookie, emitDashboardAuthWarnings, resolveDashboardAuthConfig } from "@/lib/server/dashboard-auth";

function buildLogoutResponse(request: NextRequest): NextResponse {
  return NextResponse.redirect(new URL("/login", request.url), { status: 303 });
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const config = resolveDashboardAuthConfig();
  emitDashboardAuthWarnings(config);
  return clearSessionCookie(buildLogoutResponse(request), config);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const config = resolveDashboardAuthConfig();
  emitDashboardAuthWarnings(config);
  return clearSessionCookie(buildLogoutResponse(request), config);
}
