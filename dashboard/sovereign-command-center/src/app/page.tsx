"use client";

import { useMemo, useState } from "react";
import { PROJECTS } from "@/lib/projects";
import {
  ApiTestResult,
  AuditModeSelection,
  AuditLog,
  LaunchAuditRecord,
  LaunchAuditRequest,
  ProjectId,
  RuntimeMode,
  SidebarView,
  SovereignAuditReport,
  WorkspaceTab,
} from "@/lib/types";

const SIDEBAR_ITEMS: Array<{ key: SidebarView; label: string; icon: string }> = [
  { key: "Home", label: "Home", icon: "HME" },
  { key: "RunAudit", label: "Run Audit", icon: "RUN" },
  { key: "Attacks", label: "Attacks", icon: "ATK" },
  { key: "Results", label: "Results", icon: "RSL" },
  { key: "History", label: "History", icon: "HIS" },
  { key: "Settings", label: "Settings", icon: "SYS" },
];

const WORKSPACE_TABS: WorkspaceTab[] = ["Integrity", "Supply Chain", "Narrative", "Adversarial"];
const WORKSPACE_TAB_LABELS: Record<WorkspaceTab, string> = {
  Integrity: "Integrity checks",
  "Supply Chain": "Code risks",
  Narrative: "Workflow drift",
  Adversarial: "Attack outcomes",
};
const API_PROFILE_STORAGE_KEY = "aletheia.apiTestProfiles.v1";

type AuditLaunchMode = "combined" | "api" | "website" | "repo" | "url";

const AUDIT_LAUNCH_MODES: Array<{ key: AuditLaunchMode; label: string; description: string }> = [
  { key: "combined", label: "Combined", description: "API + website + repository" },
  { key: "api", label: "API only", description: "Combined report focused on API" },
  { key: "website", label: "URL / website", description: "Single target URL audit" },
  { key: "repo", label: "Repository only", description: "Combined report focused on repo" },
  { key: "url", label: "Specific URL", description: "Endpoint-level attack sweep" },
];

const AUDIT_TEMPLATE_COPY: Record<AuditLaunchMode, { title: string; summary: string; cta: string }> = {
  combined: {
    title: "Full combined audit",
    summary: "Run the broadest audit across API, website, and repository surfaces with safe defaults.",
    cta: "Start combined audit",
  },
  api: {
    title: "API check",
    summary: "Focus on API behavior and policy decisions without running website or repository analysis.",
    cta: "Start API audit",
  },
  website: {
    title: "Website scan",
    summary: "Review a target URL for website-level findings and control-surface weaknesses.",
    cta: "Start website audit",
  },
  repo: {
    title: "Repository scan",
    summary: "Inspect repository hygiene, secrets exposure, and code-risk indicators.",
    cta: "Start repository audit",
  },
  url: {
    title: "Specific endpoint test",
    summary: "Run targeted URL and endpoint checks with optional method fuzzing and parameter injection.",
    cta: "Start endpoint test",
  },
};

interface ApiTestProfile {
  id: string;
  name: string;
  singleUrl: string;
  method: string;
  batchText: string;
  jsonTargets: Array<{ url: string; method?: string }>;
  methodFuzzing: boolean;
  parameterInjection: boolean;
  selectedPayloadCategories: string[];
  updatedAt: string;
}

const TERMINAL_LAUNCH_STATES = new Set(["completed", "failed"] as const);

function severityClass(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "severity-critical";
    case "HIGH":
      return "severity-high";
    case "MEDIUM":
      return "severity-medium";
    default:
      return "severity-low";
  }
}

function makeClientActionLog(
  projectId: ProjectId,
  runtimeMode: RuntimeMode,
  event: string,
  payload: Record<string, unknown>,
): AuditLog {
  const canonical = JSON.stringify(payload);
  return {
    id: globalThis.crypto.randomUUID(),
    generatedAt: new Date().toISOString(),
    projectId,
    runtimeMode,
    event,
    outcome: "PASS",
    payload,
    signing: {
      status: "pending",
      algorithm: "ed25519",
      canonicalPayloadHash: `client-${canonical.length}`,
      vaultTarget: "mneme",
    },
  };
}

function LineGraph({ values }: { values: number[] }) {
  if (!values.length) {
    return <p className="text-sm text-zinc-400">Runtime OFFLINE. Spectral stream paused.</p>;
  }

  const max = Math.max(...values);
  const min = Math.min(...values);
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 100;
      const normalized = (value - min) / (Math.max(1, max - min));
      const y = 100 - normalized * 100;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg viewBox="0 0 100 100" className="h-44 w-full rounded-md border border-zinc-800 bg-black/40">
      <polyline fill="none" stroke="#1f9a67" strokeWidth="2" points={points} />
    </svg>
  );
}

function ConfidenceGauge({ score }: { score: number }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const dash = (score / 100) * circumference;
  return (
    <div className="panel p-4 flex flex-col items-center justify-center">
      <svg viewBox="0 0 120 120" className="h-44 w-44">
        <circle cx="60" cy="60" r={radius} stroke="#2a2a2a" strokeWidth="10" fill="none" />
        <circle
          cx="60"
          cy="60"
          r={radius}
          stroke="#1f9a67"
          strokeWidth="10"
          fill="none"
          strokeDasharray={`${dash} ${circumference}`}
          transform="rotate(-90 60 60)"
          strokeLinecap="round"
        />
        <text x="60" y="56" textAnchor="middle" className="fill-zinc-200 text-xs font-medium" dominantBaseline="middle">
          Confidence
        </text>
        <text x="60" y="72" textAnchor="middle" className="fill-white text-xl font-bold" dominantBaseline="middle">
          {score}
        </text>
      </svg>
      <span className="text-xs text-zinc-400">Derived from integrity, narrative, supply-chain, and adversarial findings.</span>
    </div>
  );
}

function RemediationCards({
  cards,
}: {
  cards: Array<{ id: string; title: string; severity: string; summary: string; suggestedFix: string; source: string }>;
}) {
  if (!cards.length) {
    return <p className="text-sm text-zinc-400">No remediation cards generated.</p>;
  }

  return (
    <div className="grid gap-3">
      {cards.map((card) => (
        <article key={card.id} className="panel p-4">
          <div className="flex items-center justify-between gap-2">
            <h4 className="font-semibold text-zinc-100">{card.title}</h4>
            <span className={`text-xs font-semibold ${severityClass(card.severity)}`}>{card.severity}</span>
          </div>
          <p className="mt-2 text-sm text-zinc-300">{card.summary}</p>
          <pre className="mt-3 overflow-x-auto rounded-md border border-zinc-800 bg-black/40 p-3 text-xs text-zinc-200">
            {card.suggestedFix}
          </pre>
          <p className="mt-2 text-xs uppercase tracking-wide text-zinc-500">Source: {card.source}</p>
        </article>
      ))}
    </div>
  );
}

export default function Home() {
  const [projectId, setProjectId] = useState<ProjectId>("aletheia-core");
  const [runtimeMode, setRuntimeMode] = useState<RuntimeMode>("OFFLINE");
  const [activeView, setActiveView] = useState<SidebarView>("Home");
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("Integrity");
  const [report, setReport] = useState<SovereignAuditReport | null>(null);
  const [payloads, setPayloads] = useState<Array<{ id: string; name: string; category: string; severity: string }>>([]);
  const [mnemeLogs, setMnemeLogs] = useState<AuditLog[]>([]);
  const [status, setStatus] = useState("Idle");
  const [loading, setLoading] = useState(false);
  const [bootstrapped, setBootstrapped] = useState(false);
  const [modeSelection, setModeSelection] = useState<AuditModeSelection>({ api: true, website: true, repo: true });
  const [apiSingleUrl, setApiSingleUrl] = useState("");
  const [apiMethod, setApiMethod] = useState("POST");
  const [apiBatchText, setApiBatchText] = useState("");
  const [apiJsonTargets, setApiJsonTargets] = useState<Array<{ url: string; method?: string }>>([]);
  const [apiMethodFuzzing, setApiMethodFuzzing] = useState(true);
  const [apiParameterInjection, setApiParameterInjection] = useState(true);
  const [apiResults, setApiResults] = useState<ApiTestResult[]>([]);
  const [apiLoading, setApiLoading] = useState(false);
  const [selectedPayloadCategories, setSelectedPayloadCategories] = useState<string[]>([]);
  const [apiProfileName, setApiProfileName] = useState("");
  const [auditLaunchMode, setAuditLaunchMode] = useState<AuditLaunchMode>("combined");
  const [activeLaunchRunId, setActiveLaunchRunId] = useState<string | null>(null);
  const [attackPayloads, setAttackPayloads] = useState<Array<{ id: string; name: string; category: string; severity: string }>>([]);
  const [attackResults, setAttackResults] = useState<Record<string, "DENIED" | "PROCEED" | "ERROR" | "RUNNING">>({});
  const [runningSet, setRunningSet] = useState<Set<string>>(new Set());

  const [apiProfiles, setApiProfiles] = useState<ApiTestProfile[]>(() => {
    if (typeof window === "undefined") {
      return [];
    }
    try {
      const raw = localStorage.getItem(API_PROFILE_STORAGE_KEY);
      if (!raw) {
        return [];
      }
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed.filter((profile) => profile && typeof profile.name === "string");
    } catch {
      return [];
    }
  });

  const selectedProject = useMemo(() => {
    return PROJECTS.find((project) => project.id === projectId) ?? PROJECTS[0];
  }, [projectId]);

  const commandStats = useMemo(() => {
    if (!report) {
      return {
        confidence: 0,
        totalFindings: 0,
        baselineVulns: 0,
      };
    }
    return {
      confidence: report.confidenceScore,
      totalFindings: report.supplyChain.findings.length + report.narrative.findings.length,
      baselineVulns: report.adversarial.baselineVulnerabilities.length,
    };
  }, [report]);

  const commandKpis = useMemo(() => {
    const totalOutcomes = report?.adversarial.outcomes.length ?? 0;
    const protectedBlocks = report?.adversarial.outcomes.filter((outcome) => outcome.protectedDecision === "DENIED").length ?? 0;
    return {
      overallRiskScore: report ? Math.max(0, 100 - report.confidenceScore) : 0,
      blockRate: totalOutcomes ? Math.round((protectedBlocks / totalOutcomes) * 100) : 0,
      attackVisibility: report?.integrity.structuralScore ?? 0,
      criticalBypasses: report?.adversarial.baselineVulnerabilities.length ?? 0,
      lastRun: report ? new Date(report.generatedAt).toLocaleString() : "No run yet",
    };
  }, [report]);

  const payloadCategories = useMemo(() => {
    const categories = Array.from(new Set(payloads.map((payload) => payload.category))).sort();
    return categories;
  }, [payloads]);

  const latestFindingsSummary = useMemo(() => {
    if (!report) {
      return [] as Array<{ label: string; value: string }>;
    }
    return [
      { label: "Confidence", value: `${report.confidenceScore}` },
      { label: "Code findings", value: `${report.supplyChain.findings.length}` },
      { label: "Narrative findings", value: `${report.narrative.findings.length}` },
      { label: "Bypasses", value: `${report.adversarial.baselineVulnerabilities.length}` },
    ];
  }, [report]);

  const latestActivity = useMemo(() => mnemeLogs.slice(0, 12), [mnemeLogs]);

  function persistApiProfiles(nextProfiles: ApiTestProfile[]): void {
    setApiProfiles(nextProfiles);
    localStorage.setItem(API_PROFILE_STORAGE_KEY, JSON.stringify(nextProfiles));
  }

  function createApiProfileSnapshot(name: string): ApiTestProfile {
    return {
      id: `${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
      name,
      singleUrl: apiSingleUrl,
      method: apiMethod,
      batchText: apiBatchText,
      jsonTargets: apiJsonTargets,
      methodFuzzing: apiMethodFuzzing,
      parameterInjection: apiParameterInjection,
      selectedPayloadCategories,
      updatedAt: new Date().toISOString(),
    };
  }

  function saveApiProfile(): void {
    const name = apiProfileName.trim();
    if (!name) {
      setStatus("Enter a profile name before saving.");
      return;
    }

    const snapshot = createApiProfileSnapshot(name);
    const existing = apiProfiles.find((profile) => profile.name.toLowerCase() === name.toLowerCase());

    if (existing) {
      const updated = apiProfiles.map((profile) =>
        profile.id === existing.id
          ? {
              ...snapshot,
              id: existing.id,
            }
          : profile,
      );
      persistApiProfiles(updated);
      setStatus(`Updated API test profile: ${name}`);
      return;
    }

    persistApiProfiles([snapshot, ...apiProfiles].slice(0, 25));
    setStatus(`Saved API test profile: ${name}`);
  }

  function loadApiProfile(profile: ApiTestProfile): void {
    setApiProfileName(profile.name);
    setApiSingleUrl(profile.singleUrl);
    setApiMethod(profile.method);
    setApiBatchText(profile.batchText);
    setApiJsonTargets(profile.jsonTargets ?? []);
    setApiMethodFuzzing(profile.methodFuzzing);
    setApiParameterInjection(profile.parameterInjection);
    setSelectedPayloadCategories(profile.selectedPayloadCategories ?? []);
    setStatus(`Loaded API test profile: ${profile.name}`);
  }

  function deleteApiProfile(profileId: string): void {
    const profile = apiProfiles.find((item) => item.id === profileId);
    const nextProfiles = apiProfiles.filter((item) => item.id !== profileId);
    persistApiProfiles(nextProfiles);
    setStatus(`Deleted API test profile: ${profile?.name ?? profileId}`);
  }

  function clearApiTargets(): void {
    setApiSingleUrl("");
    setApiBatchText("");
    setApiJsonTargets([]);
    setStatus("Cleared endpoint target inputs.");
  }

  function applyAuditLaunchMode(nextMode: AuditLaunchMode): void {
    setAuditLaunchMode(nextMode);

    if (nextMode === "combined") {
      setModeSelection({ api: true, website: true, repo: true });
      setActiveView("RunAudit");
      setStatus("Prepared combined audit preset.");
      return;
    }

    if (nextMode === "api") {
      setModeSelection({ api: true, website: false, repo: false });
      setActiveView("RunAudit");
      setStatus("Prepared API-only audit preset.");
      return;
    }

    if (nextMode === "website") {
      setModeSelection({ api: false, website: true, repo: false });
      setActiveView("RunAudit");
      setStatus(`Prepared URL / website audit preset for ${selectedProject.runtimeEndpoint}.`);
      return;
    }

    if (nextMode === "repo") {
      setModeSelection({ api: false, website: false, repo: true });
      setActiveView("RunAudit");
      setStatus("Prepared repository-only audit preset.");
      return;
    }

    setActiveView("RunAudit");
    if (!apiSingleUrl.trim()) {
      setApiSingleUrl(selectedProject.runtimeEndpoint);
    }
    if (apiMethod === "POST") {
      setApiMethod("GET");
    }
    setStatus(`Prepared specific URL audit for ${selectedProject.runtimeEndpoint}.`);
  }

  async function sleep(ms: number): Promise<void> {
    await new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  async function pollLaunch(runId: string): Promise<LaunchAuditRecord> {
    for (let attempt = 0; attempt < 180; attempt += 1) {
      const response = await fetch(`/api/launch/${runId}`);
      if (!response.ok) {
        throw new Error(`Launch status request failed with HTTP ${response.status}`);
      }

      const record = (await response.json()) as LaunchAuditRecord;
      setStatus(`Run ${runId.slice(0, 8)} status: ${record.status}`);

      if (record.status === "completed" || record.status === "failed") {
        return record;
      }

      await sleep(1000);
    }

    throw new Error("Launch timed out while waiting for completion.");
  }

  function buildLaunchRequest(mode: AuditLaunchMode, runMode: RuntimeMode): LaunchAuditRequest {
    const single = apiSingleUrl.trim();
    const batchTargets = apiBatchText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((url) => ({ url, method: apiMethod }));

    return {
      mode,
      projectId,
      runtimeMode: runMode,
      modeSelection,
      apiTestRequest:
        mode === "url"
          ? {
              singleTarget: single ? { url: single, method: apiMethod } : undefined,
              batchTargets,
              jsonTargets: apiJsonTargets,
              enableMethodFuzzing: apiMethodFuzzing,
              enableParameterInjection: apiParameterInjection,
              payloadCategoryFilter: selectedPayloadCategories.length ? selectedPayloadCategories : undefined,
            }
          : undefined,
    };
  }

  async function executeLaunch(mode: AuditLaunchMode, runMode: RuntimeMode): Promise<LaunchAuditRecord> {
    const requestBody = buildLaunchRequest(mode, runMode);

    const launchResponse = await fetch("/api/launch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
    });
    if (!launchResponse.ok) {
      throw new Error(`Launch start failed with HTTP ${launchResponse.status}`);
    }

    const launchSummary = (await launchResponse.json()) as { runId: string };
    setActiveLaunchRunId(launchSummary.runId);
    setStatus(`Launch queued: ${launchSummary.runId.slice(0, 8)}`);
    return pollLaunch(launchSummary.runId);
  }

  async function runSelectedAudit(): Promise<void> {
    if (auditLaunchMode === "url") {
      if (!apiSingleUrl.trim()) {
        setApiSingleUrl(selectedProject.runtimeEndpoint);
      }
      setActiveView("RunAudit");
      await runApiEndpointTests();
      return;
    }

    await runAudit(runtimeMode, auditLaunchMode);
  }

  async function runAudit(runMode: RuntimeMode, reason: string): Promise<void> {
    if (!modeSelection.api && !modeSelection.website && !modeSelection.repo) {
      setStatus("Select at least one combined mode: api, website, or repo.");
      return;
    }

    setLoading(true);
    setStatus(`Running ${reason} audit for ${projectId} in ${runMode} mode...`);

    try {
      const mode: AuditLaunchMode =
        reason === "combined" || reason === "api" || reason === "website" || reason === "repo"
          ? reason
          : auditLaunchMode;
      const launchRecord = await executeLaunch(mode, runMode);

      if (launchRecord.status === "failed") {
        throw new Error(launchRecord.error ?? "Audit launch failed.");
      }

      if (!launchRecord.report) {
        throw new Error("Launch completed but no report payload was returned.");
      }

      const data = launchRecord.report as SovereignAuditReport;
      setReport(data);
      setMnemeLogs((prev) => [
        ...data.logs,
        makeClientActionLog(projectId, runMode, "ui.audit.trigger", { reason, projectId, runMode }),
        ...prev,
      ].slice(0, 400));
      setStatus(`Audit completed: ${data.generatedAt}`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setActiveLaunchRunId(null);
      setLoading(false);
    }
  }

  async function refreshPayloadLauncher(): Promise<void> {
    const response = await fetch("/api/payloads");
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    setPayloads(data.payloads ?? []);
  }

  async function importJsonTargets(file: File): Promise<void> {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed)) {
        setStatus("JSON target file must be an array of { url, method? }.");
        return;
      }
      const normalized = parsed
        .filter((item) => item && typeof item.url === "string")
        .map((item) => ({
          url: String(item.url),
          method: typeof item.method === "string" ? String(item.method).toUpperCase() : undefined,
        }));
      setApiJsonTargets(normalized);
      setStatus(`Imported ${normalized.length} API targets from JSON.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    }
  }

  async function runApiEndpointTests(): Promise<void> {
    const single = apiSingleUrl.trim();
    const batchTargets = apiBatchText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((url) => ({ url, method: apiMethod }));

    if (!single && !batchTargets.length && !apiJsonTargets.length) {
      setStatus("Provide at least one endpoint target: single URL, batch URLs, or JSON targets.");
      return;
    }

    setApiLoading(true);
    setStatus("Running adversarial API endpoint tests...");

    try {
      const launchRecord = await executeLaunch("url", runtimeMode);
      if (launchRecord.status === "failed") {
        throw new Error(launchRecord.error ?? "Endpoint launch failed.");
      }

      const results = (launchRecord.apiResults ?? []) as ApiTestResult[];
      setApiResults(results);
      setStatus(`API endpoint testing completed: ${results.length} test results.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setActiveLaunchRunId(null);
      setApiLoading(false);
    }
  }

  function togglePayloadCategory(category: string): void {
    setSelectedPayloadCategories((prev) => {
      if (prev.includes(category)) {
        return prev.filter((item) => item !== category);
      }
      return [...prev, category];
    });
  }

  function clearApiTestResults(): void {
    setApiResults([]);
    setStatus("Cleared API endpoint test results.");
  }

  function exportApiResults(): void {
    if (!apiResults.length) {
      setStatus("No API endpoint results available to export.");
      return;
    }
    const blob = new Blob([JSON.stringify(apiResults, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `api-endpoint-results-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function downloadMnemeBundle(): void {
    const blob = new Blob([JSON.stringify(mnemeLogs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `mneme-log-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function loadAttackPayloads(): Promise<void> {
    try {
      const response = await fetch("/api/payloads");
      if (!response.ok) return;
      const data = await response.json();
      setAttackPayloads(data.payloads ?? []);
    } catch {
      // silent — dashboard may be offline
    }
  }

  async function runSingleAttack(id: string): Promise<void> {
    setRunningSet((prev) => new Set(prev).add(id));
    setAttackResults((prev) => ({ ...prev, [id]: "RUNNING" }));
    try {
      const response = await fetch("/api/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "api", projectId, runtimeMode, payloadId: id }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const decision = (data?.decision ?? data?.result ?? "ERROR") as string;
      const normalized = decision.toUpperCase();
      setAttackResults((prev) => ({
        ...prev,
        [id]: normalized === "DENIED" || normalized === "PROCEED" ? normalized : "ERROR",
      }));
    } catch {
      setAttackResults((prev) => ({ ...prev, [id]: "ERROR" }));
    } finally {
      setRunningSet((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  }

  async function runCategoryAttacks(category: string): Promise<void> {
    const ids = attackPayloads.filter((p) => p.category === category).map((p) => p.id);
    await Promise.all(ids.map((id) => runSingleAttack(id)));
  }

  async function runAllAttacks(): Promise<void> {
    await Promise.all(attackPayloads.map((p) => runSingleAttack(p.id)));
  }

  async function bootstrapWorkspace(): Promise<void> {
    await refreshPayloadLauncher();
    await runAudit(runtimeMode, "regular");
    setBootstrapped(true);
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="w-64 border-r border-zinc-900 bg-black/50 p-4">
        <div className="mb-6">
          <h1 className="text-lg font-semibold tracking-tight">Aletheia Workspace</h1>
          <p className="mt-1 text-xs text-zinc-500">Guided audit launch, recent findings, and account controls</p>
        </div>

        <nav className="space-y-2">
          {SIDEBAR_ITEMS.map((item) => {
            const active = item.key === activeView;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => {
                  setActiveView(item.key);
                  if (item.key === "Attacks" && attackPayloads.length === 0) {
                    void loadAttackPayloads();
                  }
                }}
                className={`w-full rounded-md border px-3 py-2 text-left text-sm transition ${
                  active
                    ? "border-red-700 bg-red-950/40 text-zinc-100"
                    : "border-zinc-800 bg-zinc-950/30 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200"
                }`}
              >
                <span className="mr-2 inline-flex w-8 rounded bg-zinc-900 px-1.5 py-0.5 text-[10px] font-semibold text-zinc-300">
                  {item.icon}
                </span>
                {item.label}
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="flex-1 p-6">
        <header className="panel mb-5 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <label className="text-xs uppercase tracking-wide text-zinc-500" htmlFor="project-switcher">
                Project
              </label>
              <select
                id="project-switcher"
                className="rounded-md border border-zinc-700 bg-black/60 px-3 py-2 text-sm"
                value={projectId}
                onChange={(event) => {
                  setProjectId(event.target.value as ProjectId);
                  setMnemeLogs((prev) => [
                    makeClientActionLog(event.target.value as ProjectId, runtimeMode, "ui.project.switch", {
                      projectId: event.target.value,
                    }),
                    ...prev,
                  ].slice(0, 400));
                }}
              >
                {PROJECTS.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const next = runtimeMode === "CONNECTED" ? "OFFLINE" : "CONNECTED";
                  setRuntimeMode(next);
                  setMnemeLogs((prev) => [
                    makeClientActionLog(projectId, next, "ui.runtime.toggle", { previous: runtimeMode, next }),
                    ...prev,
                  ].slice(0, 400));
                }}
                className={`rounded-md border px-4 py-2 text-sm font-semibold ${
                  runtimeMode === "CONNECTED"
                    ? "border-emerald-700 bg-emerald-950/40 text-emerald-300"
                    : "border-red-700 bg-red-950/40 text-red-300"
                }`}
              >
                Runtime: {runtimeMode}
              </button>
              <form action="/api/auth/logout" method="post">
                <button
                  type="submit"
                  className="rounded-md border border-zinc-700 bg-zinc-950/50 px-4 py-2 text-sm text-zinc-200 hover:border-zinc-500"
                >
                  Sign out
                </button>
              </form>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveView("RunAudit")}
              className="rounded-md border border-red-700 bg-red-950/40 px-3 py-2 text-sm text-red-100 hover:bg-red-950/60"
            >
              Run a new audit
            </button>
            <button
              type="button"
              onClick={() => setActiveView("Results")}
              className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm hover:border-zinc-500"
            >
              Review latest results
            </button>
            <span className="self-center text-xs text-zinc-500">{status}</span>
            {activeLaunchRunId ? (
              <span className="self-center text-xs text-emerald-300">Active run: {activeLaunchRunId.slice(0, 8)}</span>
            ) : null}
          </div>
        </header>

        {!bootstrapped && (
          <section className="panel mb-5 p-4">
            <h2 className="text-sm font-semibold">Launch Preparation</h2>
            <p className="mt-2 text-sm text-zinc-400">
              Load the attack corpus and prime the first project-filtered run snapshot.
            </p>
            <button
              type="button"
              onClick={() => void bootstrapWorkspace()}
              disabled={loading}
              className="mt-3 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm hover:border-zinc-500 disabled:opacity-50"
            >
              Initialize command center
            </button>
          </section>
        )}

        {activeView === "Home" && (
          <section className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
            <div className="lg:col-span-2 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {[
                { label: "Overall risk", value: commandKpis.overallRiskScore, tone: "text-red-300" },
                { label: "Block rate", value: `${commandKpis.blockRate}%`, tone: "text-emerald-300" },
                { label: "Coverage", value: `${commandKpis.attackVisibility}%`, tone: "text-zinc-100" },
                { label: "Critical bypasses", value: commandKpis.criticalBypasses, tone: "text-orange-300" },
                { label: "Last run", value: commandKpis.lastRun, tone: "text-zinc-300" },
              ].map((kpi) => (
                <div key={kpi.label} className="panel p-4">
                  <p className="text-[11px] uppercase tracking-[0.24em] text-zinc-500">{kpi.label}</p>
                  <div className={`mt-2 text-2xl font-semibold tracking-tight ${kpi.tone}`}>{kpi.value}</div>
                </div>
              ))}
            </div>

            <div className="panel p-4">
              <h2 className="text-sm font-semibold tracking-wide text-zinc-200">Latest run snapshot</h2>
              <p className="mb-3 text-xs text-zinc-500">
                Current target endpoint: {selectedProject.runtimeEndpoint}
              </p>
              <LineGraph values={report?.gueK1Series ?? []} />
            </div>

            <div className="space-y-4">
              <ConfidenceGauge score={commandStats.confidence} />
              <div className="panel p-4 text-sm">
                <h3 className="font-semibold text-zinc-100">What needs attention</h3>
                <ul className="mt-2 space-y-1 text-zinc-300">
                  <li>Total findings: {commandStats.totalFindings}</li>
                  <li className="accent-crimson">Critical bypasses: {commandStats.baselineVulns}</li>
                  <li className="accent-emerald">Recorded activities: {mnemeLogs.length}</li>
                </ul>
              </div>
              <div className="panel p-4 text-sm">
                <h3 className="font-semibold text-zinc-100">Start here</h3>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setActiveView("RunAudit")}
                    className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs hover:border-zinc-500 disabled:opacity-50"
                  >
                    Run a new audit
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveView("History")}
                    className="rounded-md border border-red-700 bg-red-950/30 px-3 py-2 text-xs text-red-200 hover:bg-red-950/50"
                  >
                    Review recent activity
                  </button>
                </div>
              </div>
            </div>

            <div className="panel p-4">
              <h2 className="text-sm font-semibold text-zinc-100">Recommended audit templates</h2>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {AUDIT_LAUNCH_MODES.map((mode) => (
                  <button
                    key={mode.key}
                    type="button"
                    onClick={() => applyAuditLaunchMode(mode.key)}
                    className="rounded-xl border border-zinc-800 bg-black/30 p-4 text-left transition hover:border-zinc-600"
                  >
                    <p className="text-sm font-semibold text-zinc-100">{AUDIT_TEMPLATE_COPY[mode.key].title}</p>
                    <p className="mt-2 text-sm text-zinc-400">{AUDIT_TEMPLATE_COPY[mode.key].summary}</p>
                    <p className="mt-3 text-xs uppercase tracking-wide text-emerald-300">{AUDIT_TEMPLATE_COPY[mode.key].cta}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="panel p-4">
              <h2 className="text-sm font-semibold text-zinc-100">Latest findings</h2>
              <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {latestFindingsSummary.map((item) => (
                  <div key={item.label} className="rounded-lg border border-zinc-800 bg-black/30 p-3">
                    <p className="text-xs uppercase tracking-wide text-zinc-500">{item.label}</p>
                    <p className="mt-2 text-xl font-semibold text-zinc-100">{item.value}</p>
                  </div>
                ))}
                {!latestFindingsSummary.length && (
                  <p className="text-sm text-zinc-500">Run your first audit to populate this summary.</p>
                )}
              </div>
            </div>
          </section>
        )}

        {activeView === "Results" && (
          <section>
            <div className="mb-4 flex flex-wrap gap-2">
              {WORKSPACE_TABS.map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={`rounded-md border px-3 py-2 text-sm ${
                    tab === activeTab
                      ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                      : "border-zinc-800 bg-zinc-950/40 text-zinc-400 hover:border-zinc-600"
                  }`}
                >
                  {WORKSPACE_TAB_LABELS[tab]}
                </button>
              ))}
            </div>

            {activeTab === "Integrity" && report && (
              <div className="space-y-4">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold">Attack Visibility</h3>
                  <p className="mt-2 text-sm text-zinc-300">Score: {report.integrity.structuralScore}</p>
                  <p className="text-sm text-zinc-400">{report.integrity.scoutLogSummary}</p>
                  <p className="text-sm text-zinc-400">{report.integrity.judgeLogSummary}</p>
                </div>
                <RemediationCards cards={report.integrity.cards} />
              </div>
            )}

            {activeTab === "Supply Chain" && report && (
              <div className="space-y-4">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold">Coverage status</h3>
                  <p className="mt-2 text-sm text-zinc-300">Semgrep: {report.supplyChain.workerStatus.semgrep}</p>
                  <p className="text-sm text-zinc-300">Trufflehog: {report.supplyChain.workerStatus.trufflehog}</p>
                </div>
                <RemediationCards cards={report.supplyChain.cards.slice(0, 12)} />
              </div>
            )}

            {activeTab === "Narrative" && report && (
              <div className="space-y-4">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold">Narrative parity</h3>
                  <p className="mt-2 text-sm text-zinc-300">Parity Score: {report.narrative.parityScore}</p>
                  <p className="text-sm text-zinc-400">Ghost commands detected: {report.narrative.findings.length}</p>
                </div>
                <RemediationCards cards={report.narrative.cards} />
              </div>
            )}

            {activeTab === "Adversarial" && report && (
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold text-red-200">Unprotected results</h3>
                  <div className="mt-3 space-y-2 text-xs">
                    {report.adversarial.outcomes.slice(0, 16).map((outcome) => (
                      <div key={`${outcome.payloadId}-u`} className="rounded border border-zinc-800 p-2">
                        <p>{outcome.payloadId} · {outcome.category}</p>
                        <p className={outcome.unprotectedDecision === "PROCEED" ? "text-red-300" : "text-emerald-300"}>
                          {outcome.unprotectedDecision}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="panel p-4">
                  <h3 className="text-sm font-semibold text-emerald-200">Protected results</h3>
                  <div className="mt-3 space-y-2 text-xs">
                    {report.adversarial.outcomes.slice(0, 16).map((outcome) => (
                      <div key={`${outcome.payloadId}-p`} className="rounded border border-zinc-800 p-2">
                        <p>{outcome.payloadId} · {outcome.category}</p>
                        <p className={outcome.protectedDecision === "PROCEED" ? "text-red-300" : "text-emerald-300"}>
                          {outcome.protectedDecision}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="lg:col-span-2">
                  <RemediationCards cards={report.adversarial.cards} />
                </div>
              </div>
            )}
          </section>
        )}

        {activeView === "RunAudit" && (
          <section className="space-y-4">
            <div className="panel p-4">
              <h2 className="text-sm font-semibold">Run Audit</h2>
              <p className="mt-1 text-xs text-zinc-500">
                Choose a guided template, confirm the scope, and launch with one primary action.
              </p>

              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {AUDIT_LAUNCH_MODES.map((mode) => {
                  const active = auditLaunchMode === mode.key;
                  return (
                    <button
                      key={mode.key}
                      type="button"
                      onClick={() => applyAuditLaunchMode(mode.key)}
                      className={`rounded-xl border p-4 text-left transition ${
                        active
                          ? "border-red-700 bg-red-950/30"
                          : "border-zinc-800 bg-black/30 hover:border-zinc-600"
                      }`}
                    >
                      <p className="text-sm font-semibold text-zinc-100">{AUDIT_TEMPLATE_COPY[mode.key].title}</p>
                      <p className="mt-2 text-sm text-zinc-400">{AUDIT_TEMPLATE_COPY[mode.key].summary}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="panel rounded-md border border-zinc-800 bg-black/30 p-4">
              <div className="flex flex-wrap items-center gap-4">
                <span className="text-xs uppercase tracking-wide text-zinc-500">Audit scope</span>
                {([
                  ["api", "API"],
                  ["website", "Website"],
                  ["repo", "Repository"],
                ] as const).map(([key, label]) => (
                  <label key={key} className="flex items-center gap-2 text-xs text-zinc-300">
                    <input
                      type="checkbox"
                      checked={modeSelection[key]}
                      onChange={(event) => {
                        const checked = event.target.checked;
                        setModeSelection((prev) => ({ ...prev, [key]: checked }));
                      }}
                    />
                    {label}
                  </label>
                ))}
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={loading || apiLoading}
                  onClick={() => void runSelectedAudit()}
                  className="rounded-md border border-red-700 bg-red-950/40 px-4 py-2 text-sm font-semibold text-red-100 hover:bg-red-950/60 disabled:opacity-50"
                >
                  {loading || apiLoading ? "Starting..." : AUDIT_TEMPLATE_COPY[auditLaunchMode].cta}
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => void runAudit("OFFLINE", "pre-connection")}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
                >
                  Run offline baseline
                </button>
              </div>
            </div>

            <div className="panel p-4">
              <h3 className="text-sm font-semibold">Included payload families</h3>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {payloads.slice(0, 18).map((payload) => (
                  <div key={payload.id} className="rounded border border-zinc-800 bg-black/30 p-2 text-xs">
                    <p className="font-semibold text-zinc-200">{payload.id}</p>
                    <p className="text-zinc-400">{payload.name}</p>
                    <p className={severityClass(payload.severity)}>{payload.severity}</p>
                  </div>
                ))}
                {!payloads.length && <p className="text-sm text-zinc-500">Initialize the workspace to load payload families.</p>}
              </div>
            </div>
          </section>
        )}

        {activeView === "RunAudit" && (
          <section className="space-y-4">
            <details className="panel p-4">
              <summary className="cursor-pointer list-none text-sm font-semibold text-zinc-100">
                Advanced endpoint testing
              </summary>
              <p className="mt-1 text-xs text-zinc-500">
                Use this only when you need to target specific URLs or run endpoint-level adversarial checks.
              </p>

              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => applyAuditLaunchMode("url")}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-zinc-200 hover:border-zinc-500"
                >
                  Use project URL
                </button>
                <button
                  type="button"
                  onClick={() => void runSelectedAudit()}
                  className="rounded-md border border-red-700 bg-red-950/30 px-3 py-2 text-red-200 hover:bg-red-950/50"
                >
                  Run URL audit
                </button>
                <button
                  type="button"
                  onClick={() => applyAuditLaunchMode("api")}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-zinc-200 hover:border-zinc-500"
                >
                  API-only preset
                </button>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-3">
                <div className="lg:col-span-3 rounded-md border border-zinc-800 bg-black/30 p-3">
                  <div className="flex flex-wrap items-end gap-2">
                    <div className="min-w-[220px] flex-1">
                      <label className="text-xs text-zinc-500">Saved Test Profile Name</label>
                      <input
                        type="text"
                        value={apiProfileName}
                        onChange={(event) => setApiProfileName(event.target.value)}
                        placeholder="production-gateway-smoke"
                        className="mt-1 w-full rounded-md border border-zinc-700 bg-black/40 px-3 py-2 text-sm"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={saveApiProfile}
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 hover:border-zinc-500"
                    >
                      Save Profile
                    </button>
                    <button
                      type="button"
                      onClick={clearApiTargets}
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 hover:border-zinc-500"
                    >
                      Clear Targets
                    </button>
                  </div>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                    {apiProfiles.map((profile) => (
                      <div key={profile.id} className="rounded border border-zinc-800 bg-black/40 p-2 text-xs">
                        <p className="font-semibold text-zinc-200">{profile.name}</p>
                        <p className="mt-1 text-zinc-500">{new Date(profile.updatedAt).toLocaleString()}</p>
                        <div className="mt-2 flex gap-2">
                          <button
                            type="button"
                            onClick={() => loadApiProfile(profile)}
                            className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 hover:border-zinc-500"
                          >
                            Load
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteApiProfile(profile.id)}
                            className="rounded border border-red-800 px-2 py-1 text-red-300 hover:border-red-600"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))}
                    {!apiProfiles.length && (
                      <p className="text-zinc-500">No saved profiles yet. Configure a test setup and click Save Profile.</p>
                    )}
                  </div>
                </div>

                <div>
                  <label className="text-xs text-zinc-500">Single Endpoint URL</label>
                  <input
                    type="text"
                    value={apiSingleUrl}
                    onChange={(event) => setApiSingleUrl(event.target.value)}
                    placeholder="https://localhost:8000/v1/chat/completions"
                    className="mt-1 w-full rounded-md border border-zinc-700 bg-black/40 px-3 py-2 text-sm"
                  />
                </div>

                <div>
                  <label className="text-xs text-zinc-500">Method</label>
                  <select
                    value={apiMethod}
                    onChange={(event) => setApiMethod(event.target.value)}
                    className="mt-1 w-full rounded-md border border-zinc-700 bg-black/40 px-3 py-2 text-sm"
                  >
                    {["GET", "POST", "PUT", "PATCH", "DELETE"].map((method) => (
                      <option key={method} value={method}>{method}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs text-zinc-500">JSON Config Upload</label>
                  <input
                    type="file"
                    accept="application/json"
                    onChange={(event) => {
                      const file = event.target.files?.[0];
                      if (file) {
                        void importJsonTargets(file);
                      }
                    }}
                    className="mt-1 w-full rounded-md border border-zinc-700 bg-black/40 px-3 py-2 text-sm"
                  />
                  <p className="mt-1 text-[11px] text-zinc-500">Loaded JSON targets: {apiJsonTargets.length}</p>
                </div>
              </div>

              <div className="mt-4">
                <label className="text-xs text-zinc-500">Batch Endpoints (one URL per line)</label>
                <textarea
                  value={apiBatchText}
                  onChange={(event) => setApiBatchText(event.target.value)}
                  rows={5}
                  placeholder={"https://localhost:8000/v1/chat/completions\nhttps://localhost:8000/v1/moderations"}
                  className="mt-1 w-full rounded-md border border-zinc-700 bg-black/40 px-3 py-2 text-sm"
                />
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-4 text-xs">
                <label className="flex items-center gap-2 text-zinc-300">
                  <input
                    type="checkbox"
                    checked={apiMethodFuzzing}
                    onChange={(event) => setApiMethodFuzzing(event.target.checked)}
                  />
                  Method fuzzing
                </label>
                <label className="flex items-center gap-2 text-zinc-300">
                  <input
                    type="checkbox"
                    checked={apiParameterInjection}
                    onChange={(event) => setApiParameterInjection(event.target.checked)}
                  />
                  Parameter injection (query/header/body)
                </label>
              </div>

              <div className="mt-4">
                <div className="mb-2 flex flex-wrap items-center gap-3 text-xs">
                  <span className="text-zinc-500">Payload Categories</span>
                  <button
                    type="button"
                    onClick={() => setSelectedPayloadCategories(payloadCategories)}
                    className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 hover:border-zinc-500"
                  >
                    Select all
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedPayloadCategories([])}
                    className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 hover:border-zinc-500"
                  >
                    Use all by default
                  </button>
                </div>
                <div className="flex flex-wrap gap-3 text-xs text-zinc-300">
                  {payloadCategories.map((category) => (
                    <label key={category} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={selectedPayloadCategories.includes(category)}
                        onChange={() => togglePayloadCategory(category)}
                      />
                      {category}
                    </label>
                  ))}
                  {!payloadCategories.length && <span className="text-zinc-500">Initialize workspace to load categories.</span>}
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void runApiEndpointTests()}
                  disabled={apiLoading}
                  className="rounded-md border border-red-700 bg-red-950/30 px-4 py-2 text-sm text-red-200 hover:bg-red-950/50 disabled:opacity-50"
                >
                  {apiLoading ? "Running endpoint tests..." : "Run API Endpoint Adversarial Tests"}
                </button>
                <button
                  type="button"
                  onClick={clearApiTestResults}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-500"
                >
                  Clear Results
                </button>
                <button
                  type="button"
                  onClick={exportApiResults}
                  className="rounded-md border border-emerald-700 bg-emerald-950/30 px-4 py-2 text-sm text-emerald-200 hover:bg-emerald-950/50"
                >
                  Export API Test Results
                </button>
              </div>
            </details>

            <div className="panel overflow-x-auto p-4">
              <h3 className="mb-3 text-sm font-semibold">API Test Results</h3>
              <table className="min-w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 text-zinc-500">
                    <th className="px-2 py-2">Target</th>
                    <th className="px-2 py-2">Method</th>
                    <th className="px-2 py-2">Injection</th>
                    <th className="px-2 py-2">Status</th>
                    <th className="px-2 py-2">Duration</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-2 py-2">Signal</th>
                  </tr>
                </thead>
                <tbody>
                  {apiResults.slice(0, 300).map((result) => (
                    <tr key={result.id} className="border-b border-zinc-900 text-zinc-300">
                      <td className="px-2 py-2">{result.targetUrl}</td>
                      <td className="px-2 py-2">{result.method}</td>
                      <td className="px-2 py-2">{result.injectionMode}</td>
                      <td className="px-2 py-2">{result.statusCode || "ERR"}</td>
                      <td className="px-2 py-2">{result.durationMs}ms</td>
                      <td className={`px-2 py-2 ${severityClass(result.severity)}`}>{result.severity}</td>
                      <td className="px-2 py-2">{result.signal}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {activeView === "History" && (
          <section className="space-y-4">
            <div className="panel p-4">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold">Recent activity</h2>
                <button
                  type="button"
                  onClick={downloadMnemeBundle}
                  className="rounded-md border border-emerald-700 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200"
                >
                  Export JSON Log Bundle
                </button>
              </div>
              <p className="mt-2 text-xs text-zinc-500">
                This view shows the latest tracked actions for the current session and lets you export the activity bundle.
              </p>
            </div>

            {report && (
              <div className="panel p-4 text-sm text-zinc-300">
                <h3 className="font-semibold text-zinc-100">Latest completed run</h3>
                <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded border border-zinc-800 bg-black/30 p-3">
                    <p className="text-xs uppercase tracking-wide text-zinc-500">Generated</p>
                    <p className="mt-2">{new Date(report.generatedAt).toLocaleString()}</p>
                  </div>
                  <div className="rounded border border-zinc-800 bg-black/30 p-3">
                    <p className="text-xs uppercase tracking-wide text-zinc-500">Project</p>
                    <p className="mt-2">{report.projectId}</p>
                  </div>
                  <div className="rounded border border-zinc-800 bg-black/30 p-3">
                    <p className="text-xs uppercase tracking-wide text-zinc-500">Runtime</p>
                    <p className="mt-2">{report.runtimeMode}</p>
                  </div>
                  <div className="rounded border border-zinc-800 bg-black/30 p-3">
                    <p className="text-xs uppercase tracking-wide text-zinc-500">Confidence</p>
                    <p className="mt-2">{report.confidenceScore}</p>
                  </div>
                </div>
              </div>
            )}

            <div className="panel overflow-x-auto p-4">
              <table className="min-w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 text-zinc-500">
                    <th className="px-2 py-2">Timestamp</th>
                    <th className="px-2 py-2">Event</th>
                    <th className="px-2 py-2">Outcome</th>
                    <th className="px-2 py-2">Signature Status</th>
                  </tr>
                </thead>
                <tbody>
                  {latestActivity.map((log) => (
                    <tr key={log.id} className="border-b border-zinc-900 text-zinc-300">
                      <td className="px-2 py-2">{new Date(log.generatedAt).toLocaleString()}</td>
                      <td className="px-2 py-2">{log.event}</td>
                      <td className="px-2 py-2">{log.outcome}</td>
                      <td className="px-2 py-2 text-emerald-300">{log.signing.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {activeView === "Settings" && (
          <section className="space-y-4">
            <div className="panel p-4">
              <h2 className="text-sm font-semibold">Workspace settings</h2>
              <p className="mt-2 text-sm text-zinc-400">
                Manage session controls, default launch behavior, and exported activity artifacts.
              </p>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="panel p-4 text-sm text-zinc-300">
                <h3 className="font-semibold text-zinc-100">Session</h3>
                <p className="mt-2">Current runtime mode: {runtimeMode}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const next = runtimeMode === "CONNECTED" ? "OFFLINE" : "CONNECTED";
                      setRuntimeMode(next);
                    }}
                    className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs hover:border-zinc-500"
                  >
                    Toggle runtime
                  </button>
                  <form action="/api/auth/logout" method="post">
                    <button
                      type="submit"
                      className="rounded-md border border-red-700 bg-red-950/30 px-3 py-2 text-xs text-red-100 hover:bg-red-950/50"
                    >
                      Sign out
                    </button>
                  </form>
                </div>
              </div>

              <div className="panel p-4 text-sm text-zinc-300">
                <h3 className="font-semibold text-zinc-100">Exports</h3>
                <p className="mt-2">Download the current activity bundle for audit traceability.</p>
                <button
                  type="button"
                  onClick={downloadMnemeBundle}
                  className="mt-3 rounded-md border border-emerald-700 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200"
                >
                  Export activity bundle
                </button>
              </div>
            </div>
          </section>
        )}
        {activeView === "Attacks" && (() => {
          const categories = Array.from(new Set(attackPayloads.map((p) => p.category))).sort();
          const resultBadge = (id: string) => {
            const r = attackResults[id];
            if (!r) return null;
            if (r === "RUNNING") return <span className="rounded px-2 py-0.5 text-[10px] font-bold bg-zinc-700 text-zinc-300 animate-pulse">RUNNING</span>;
            if (r === "DENIED") return <span className="rounded px-2 py-0.5 text-[10px] font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-800">DENIED</span>;
            if (r === "PROCEED") return <span className="rounded px-2 py-0.5 text-[10px] font-bold bg-red-950/60 text-red-300 border border-red-800">PROCEED</span>;
            return <span className="rounded px-2 py-0.5 text-[10px] font-bold bg-zinc-800 text-zinc-400">ERROR</span>;
          };

          return (
            <section className="space-y-4">
              <div className="panel p-4 flex items-center justify-between gap-4">
                <div>
                  <h2 className="text-sm font-semibold">Attack Launcher</h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    {attackPayloads.length} attacks across {categories.length} categories. Click Run to execute individually or by category.
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void loadAttackPayloads()}
                    className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs text-zinc-300 hover:border-zinc-500"
                  >
                    Reload
                  </button>
                  <button
                    type="button"
                    disabled={attackPayloads.length === 0 || runningSet.size > 0}
                    onClick={() => void runAllAttacks()}
                    className="rounded-md border border-red-700 bg-red-950/40 px-4 py-2 text-sm font-semibold text-red-100 hover:bg-red-950/60 disabled:opacity-50"
                  >
                    {runningSet.size > 0 ? `Running (${runningSet.size})…` : "Run All"}
                  </button>
                </div>
              </div>

              {attackPayloads.length === 0 && (
                <div className="panel p-6 text-center text-sm text-zinc-500">
                  No attack payloads loaded. Click Reload or initialize the workspace first.
                </div>
              )}

              {categories.map((category) => {
                const items = attackPayloads.filter((p) => p.category === category);
                const categoryRunning = items.some((p) => runningSet.has(p.id));
                return (
                  <div key={category} className="panel p-4">
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <h3 className="text-sm font-semibold text-zinc-100 capitalize">
                        {category.replace(/_/g, " ")}
                        <span className="ml-2 text-xs font-normal text-zinc-500">({items.length})</span>
                      </h3>
                      <button
                        type="button"
                        disabled={categoryRunning}
                        onClick={() => void runCategoryAttacks(category)}
                        className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
                      >
                        {categoryRunning ? "Running…" : "Run Category"}
                      </button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b border-zinc-800 text-left text-zinc-500">
                            <th className="pb-2 pr-4 font-medium">ID</th>
                            <th className="pb-2 pr-4 font-medium">Name</th>
                            <th className="pb-2 pr-4 font-medium">Severity</th>
                            <th className="pb-2 pr-4 font-medium">Result</th>
                            <th className="pb-2 font-medium"></th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-900">
                          {items.map((attack) => (
                            <tr key={attack.id} className="hover:bg-zinc-900/40">
                              <td className="py-2 pr-4 font-mono text-zinc-400">{attack.id}</td>
                              <td className="py-2 pr-4 text-zinc-200">{attack.name}</td>
                              <td className={`py-2 pr-4 font-semibold ${severityClass(attack.severity)}`}>{attack.severity}</td>
                              <td className="py-2 pr-4">{resultBadge(attack.id)}</td>
                              <td className="py-2">
                                <button
                                  type="button"
                                  disabled={runningSet.has(attack.id)}
                                  onClick={() => void runSingleAttack(attack.id)}
                                  className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-[10px] text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
                                >
                                  {runningSet.has(attack.id) ? "…" : "Run"}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })}
            </section>
          );
        })()}
      </main>
    </div>
  );
}
