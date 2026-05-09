import { NextRequest, NextResponse } from "next/server";
import { runApiEndpointTest } from "@/lib/server/api-tester";
import { ApiTestRequest } from "@/lib/types";

export async function POST(request: NextRequest): Promise<NextResponse> {
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
