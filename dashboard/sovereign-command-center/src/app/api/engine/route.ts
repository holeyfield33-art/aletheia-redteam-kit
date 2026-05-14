import { NextRequest, NextResponse } from "next/server";
import { authorizeApiRouteRequest } from "@/lib/server/dashboard-auth";
import { runSovereignAudit } from "@/lib/server/engine";
import { AuditModeSelection, ProjectId, RuntimeMode } from "@/lib/types";

interface AuditRequest {
  projectId?: ProjectId;
  runtimeMode?: RuntimeMode;
  modeSelection?: AuditModeSelection;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const unauthorized = authorizeApiRouteRequest(request);
  if (unauthorized) {
    return unauthorized;
  }

  try {
    const body = (await request.json()) as AuditRequest;
    const projectId: ProjectId = body.projectId ?? "aletheia-core";
    const runtimeMode: RuntimeMode = body.runtimeMode ?? "OFFLINE";
    const modeSelection: AuditModeSelection = body.modeSelection ?? {
      api: true,
      website: true,
      repo: true,
    };

    const report = runSovereignAudit(projectId, runtimeMode, modeSelection);
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
