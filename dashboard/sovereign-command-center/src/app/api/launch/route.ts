import { NextRequest, NextResponse } from "next/server";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";
import { startLaunch } from "@/lib/server/launch";
import { LaunchAuditRequest } from "@/lib/types";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  try {
    const body = (await request.json()) as LaunchAuditRequest;
    if (!body?.mode) {
      return NextResponse.json({ error: "mode is required" }, { status: 400 });
    }

    const summary = startLaunch(body);
    return NextResponse.json(summary, { status: 202 });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to start launch",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
