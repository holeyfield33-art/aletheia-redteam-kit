import { runApiEndpointTest } from "@/lib/server/api-tester";
import { runSovereignAudit } from "@/lib/server/engine";
import {
  AuditModeSelection,
  LaunchAuditMode,
  LaunchAuditRecord,
  LaunchAuditRequest,
  LaunchAuditSummary,
  ProjectId,
  RuntimeMode,
} from "@/lib/types";

const MAX_STORED_RUNS = 80;

interface LaunchStore {
  byId: Map<string, LaunchAuditRecord>;
}

declare global {
  var __aletheiaLaunchStore: LaunchStore | undefined;
}

function getStore(): LaunchStore {
  if (!globalThis.__aletheiaLaunchStore) {
    globalThis.__aletheiaLaunchStore = { byId: new Map<string, LaunchAuditRecord>() };
  }
  return globalThis.__aletheiaLaunchStore;
}

function deriveModeSelection(mode: LaunchAuditMode, requested?: AuditModeSelection): AuditModeSelection {
  if (requested) {
    return requested;
  }

  if (mode === "combined") {
    return { api: true, website: true, repo: true };
  }
  if (mode === "api") {
    return { api: true, website: false, repo: false };
  }
  if (mode === "website") {
    return { api: false, website: true, repo: false };
  }
  if (mode === "repo") {
    return { api: false, website: false, repo: true };
  }
  return { api: true, website: false, repo: false };
}

function trimStore(store: LaunchStore): void {
  if (store.byId.size <= MAX_STORED_RUNS) {
    return;
  }
  const oldestFirst = Array.from(store.byId.values()).sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
  for (const item of oldestFirst.slice(0, store.byId.size - MAX_STORED_RUNS)) {
    store.byId.delete(item.runId);
  }
}

function summarize(record: LaunchAuditRecord): LaunchAuditSummary {
  return {
    runId: record.runId,
    mode: record.mode,
    status: record.status,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    projectId: record.projectId,
    runtimeMode: record.runtimeMode,
  };
}

export function startLaunch(request: LaunchAuditRequest): LaunchAuditSummary {
  const store = getStore();
  const now = new Date().toISOString();
  const runId = globalThis.crypto.randomUUID();

  const mode = request.mode;
  const projectId: ProjectId = request.projectId ?? "aletheia-core";
  const runtimeMode: RuntimeMode = request.runtimeMode ?? "OFFLINE";

  const initialRecord: LaunchAuditRecord = {
    runId,
    mode,
    status: "queued",
    createdAt: now,
    updatedAt: now,
    projectId,
    runtimeMode,
  };

  store.byId.set(runId, initialRecord);
  trimStore(store);

  void Promise.resolve().then(async () => {
    const runningRecord = store.byId.get(runId);
    if (!runningRecord) {
      return;
    }

    runningRecord.status = "running";
    runningRecord.updatedAt = new Date().toISOString();

    try {
      if (mode === "url") {
        const apiResults = await runApiEndpointTest(
          request.apiTestRequest ?? {
            enableMethodFuzzing: true,
            enableParameterInjection: true,
          },
        );
        runningRecord.apiResults = apiResults;
        runningRecord.total = apiResults.length;
      } else {
        const report = runSovereignAudit(projectId, runtimeMode, deriveModeSelection(mode, request.modeSelection));
        runningRecord.report = report;
      }
      runningRecord.status = "completed";
      runningRecord.updatedAt = new Date().toISOString();
    } catch (error) {
      runningRecord.status = "failed";
      runningRecord.error = error instanceof Error ? error.message : String(error);
      runningRecord.updatedAt = new Date().toISOString();
    }
  });

  return summarize(initialRecord);
}

export function getLaunch(runId: string): LaunchAuditRecord | null {
  const store = getStore();
  return store.byId.get(runId) ?? null;
}

export function listLatestLaunches(limit: number = 10): LaunchAuditSummary[] {
  const store = getStore();
  const size = Math.max(1, Math.min(50, limit));
  return Array.from(store.byId.values())
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, size)
    .map(summarize);
}
