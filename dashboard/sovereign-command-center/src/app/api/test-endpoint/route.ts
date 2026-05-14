import { NextRequest, NextResponse } from "next/server";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";
import { runApiEndpointTest } from "@/lib/server/api-tester";
import { ApiTestRequest } from "@/lib/types";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  try {
    const body = (await request.json()) as ApiTestRequest;
    const results = await runApiEndpointTest(body);
    return NextResponse.json({
      total: results.length,
      results,
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to execute API endpoint test",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
