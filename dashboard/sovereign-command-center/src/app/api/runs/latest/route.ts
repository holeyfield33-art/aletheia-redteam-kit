import { NextRequest, NextResponse } from "next/server";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";
import { listLatestLaunches } from "@/lib/server/launch";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  const limitRaw = request.nextUrl.searchParams.get("limit") ?? "10";
  const limit = Number.isFinite(Number(limitRaw)) ? Number(limitRaw) : 10;
  const runs = listLatestLaunches(limit);
  return NextResponse.json({ runs });
}
