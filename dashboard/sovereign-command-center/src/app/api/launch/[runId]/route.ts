import { NextRequest, NextResponse } from "next/server";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";
import { getLaunch } from "@/lib/server/launch";

interface RouteParams {
  params: Promise<{ runId: string }>;
}

export async function GET(request: NextRequest, context: RouteParams): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  const { runId } = await context.params;
  const record = getLaunch(runId);

  if (!record) {
    return NextResponse.json({ error: "Launch run not found" }, { status: 404 });
  }

  return NextResponse.json(record);
}
