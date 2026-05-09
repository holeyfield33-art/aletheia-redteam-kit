import { NextRequest, NextResponse } from "next/server";
import { runSovereignAudit } from "@/lib/server/engine";
import { ProjectId, RuntimeMode } from "@/lib/types";

interface AuditRequest {
  projectId?: ProjectId;
  runtimeMode?: RuntimeMode;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = (await request.json()) as AuditRequest;
    const projectId: ProjectId = body.projectId ?? "aletheia-core";
    const runtimeMode: RuntimeMode = body.runtimeMode ?? "OFFLINE";

    const report = runSovereignAudit(projectId, runtimeMode);
    return NextResponse.json(report);
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to run sovereign audit",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
