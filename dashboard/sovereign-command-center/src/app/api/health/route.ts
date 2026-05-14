import { NextResponse } from "next/server";
import { emitDashboardAuthWarnings, resolveDashboardAuthConfig } from "@/lib/server/dashboard-auth";

export async function GET(): Promise<NextResponse> {
  const config = resolveDashboardAuthConfig();
  emitDashboardAuthWarnings(config);
  return NextResponse.json({
    ok: true,
    authEnabled: config.mode !== "disabled",
    authMode: config.mode,
  });
}
