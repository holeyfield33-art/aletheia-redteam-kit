import { NextRequest, NextResponse } from "next/server";
import { loadPayloadPreview } from "@/lib/server/adversary";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  const payloads = loadPayloadPreview(36);
  return NextResponse.json({ payloads, total: payloads.length });
}
