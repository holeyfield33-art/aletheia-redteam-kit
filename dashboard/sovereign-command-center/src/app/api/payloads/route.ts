import { NextResponse } from "next/server";
import { loadPayloadPreview } from "@/lib/server/adversary";

export async function GET(): Promise<NextResponse> {
  const payloads = loadPayloadPreview(36);
  return NextResponse.json({ payloads, total: payloads.length });
}
