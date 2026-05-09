"use client";

import { useMemo, useState } from "react";
import { PROJECTS } from "@/lib/projects";
import {
  ApiTestResult,
  AuditModeSelection,
  AuditLog,
  ProjectId,
  RuntimeMode,
  SidebarView,
  SovereignAuditReport,
  WorkspaceTab,
} from "@/lib/types";

const SIDEBAR_ITEMS: Array<{ key: SidebarView; label: string; icon: string }> = [
  { key: "Command", label: "Command", icon: "CMD" },
  { key: "Inspector", label: "Inspector", icon: "AUD" },
  { key: "Adversary", label: "Adversary", icon: "RED" },
  { key: "ApiTesting", label: "API Testing", icon: "API" },
  { key: "Mneme", label: "Mneme", icon: "VAU" },
];

const WORKSPACE_TABS: WorkspaceTab[] = ["Integrity", "Supply Chain", "Narrative", "Adversarial"];

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
  const [activeView, setActiveView] = useState<SidebarView>("Command");
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

  async function runAudit(runMode: RuntimeMode, reason: string): Promise<void> {
    if (!modeSelection.api && !modeSelection.website && !modeSelection.repo) {
      setStatus("Select at least one combined mode: api, website, or repo.");
      return;
    }

    setLoading(true);
    setStatus(`Running ${reason} audit for ${projectId} in ${runMode} mode...`);

    try {
      const response = await fetch("/api/engine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId, runtimeMode: runMode, modeSelection }),
      });
      if (!response.ok) {
        throw new Error(`Engine request failed with HTTP ${response.status}`);
      }

      const data = (await response.json()) as SovereignAuditReport;
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
    setApiLoading(true);
    setStatus("Running adversarial API endpoint tests...");

    const batchTargets = apiBatchText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((url) => ({ url, method: apiMethod }));

    try {
      const response = await fetch("/api/test-endpoint", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          singleTarget: apiSingleUrl.trim() ? { url: apiSingleUrl.trim(), method: apiMethod } : undefined,
          batchTargets,
          jsonTargets: apiJsonTargets,
          enableMethodFuzzing: apiMethodFuzzing,
          enableParameterInjection: apiParameterInjection,
          payloadCategoryFilter: [],
        }),
      });
      if (!response.ok) {
        throw new Error(`API test failed with HTTP ${response.status}`);
      }
      const data = await response.json();
      setApiResults((data.results ?? []) as ApiTestResult[]);
      setStatus(`API endpoint testing completed: ${(data.results ?? []).length} test results.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setApiLoading(false);
    }
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

  async function bootstrapWorkspace(): Promise<void> {
    await refreshPayloadLauncher();
    await runAudit(runtimeMode, "regular");
    setBootstrapped(true);
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="w-64 border-r border-zinc-900 bg-black/50 p-4">
        <div className="mb-6">
          <h1 className="text-lg font-semibold tracking-tight">Aletheia Sovereign Center</h1>
          <p className="mt-1 text-xs text-zinc-500">Phase 1 + 2 Runtime Console</p>
        </div>

        <nav className="space-y-2">
          {SIDEBAR_ITEMS.map((item) => {
            const active = item.key === activeView;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setActiveView(item.key)}
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
              Aletheia Runtime Status: {runtimeMode}
            </button>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              disabled={loading}
              onClick={() => void runAudit(runtimeMode, "regular")}
              className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm hover:border-zinc-500 disabled:opacity-50"
            >
              Run Regular Audit
            </button>
            <button
              type="button"
              disabled={loading}
              onClick={() => void runAudit("OFFLINE", "pre-connection")}
              className="rounded-md border border-red-700 bg-red-950/30 px-3 py-2 text-sm text-red-200 hover:bg-red-950/50 disabled:opacity-50"
            >
              Run Pre-Connection Simulation
            </button>
            <span className="self-center text-xs text-zinc-500">{status}</span>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-4">
            <span className="text-xs uppercase tracking-wide text-zinc-500">Combined Mode Selection</span>
            {([
              ["api", "API"],
              ["website", "Website"],
              ["repo", "Repo"],
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
        </header>

        {!bootstrapped && (
          <section className="panel mb-5 p-4">
            <h2 className="text-sm font-semibold">Workspace Initialization</h2>
            <p className="mt-2 text-sm text-zinc-400">
              Load payload corpus and run first project-filtered audit snapshot.
            </p>
            <button
              type="button"
              onClick={() => void bootstrapWorkspace()}
              disabled={loading}
              className="mt-3 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm hover:border-zinc-500 disabled:opacity-50"
            >
              Initialize Workspace
            </button>
          </section>
        )}

        {activeView === "Command" && (
          <section className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
            <div className="panel p-4">
              <h2 className="text-sm font-semibold tracking-wide text-zinc-200">Spectral Monitor (GUE k=1)</h2>
              <p className="mb-3 text-xs text-zinc-500">
                Streaming only when runtime is CONNECTED. Current endpoint: {selectedProject.runtimeEndpoint}
              </p>
              <LineGraph values={report?.gueK1Series ?? []} />
            </div>

            <div className="space-y-4">
              <ConfidenceGauge score={commandStats.confidence} />
              <div className="panel p-4 text-sm">
                <h3 className="font-semibold text-zinc-100">HUD Metrics</h3>
                <ul className="mt-2 space-y-1 text-zinc-300">
                  <li>Total Findings: {commandStats.totalFindings}</li>
                  <li className="accent-crimson">Baseline Vulnerabilities: {commandStats.baselineVulns}</li>
                  <li className="accent-emerald">Signed-Ready Events: {mnemeLogs.length}</li>
                </ul>
              </div>
            </div>
          </section>
        )}

        {activeView === "Inspector" && (
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
                  [{tab}]
                </button>
              ))}
            </div>

            {activeTab === "Integrity" && report && (
              <div className="space-y-4">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold">Structural Health</h3>
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
                  <h3 className="text-sm font-semibold">Worker Status</h3>
                  <p className="mt-2 text-sm text-zinc-300">Semgrep: {report.supplyChain.workerStatus.semgrep}</p>
                  <p className="text-sm text-zinc-300">Trufflehog: {report.supplyChain.workerStatus.trufflehog}</p>
                </div>
                <RemediationCards cards={report.supplyChain.cards.slice(0, 12)} />
              </div>
            )}

            {activeTab === "Narrative" && report && (
              <div className="space-y-4">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold">README-to-Code Parity</h3>
                  <p className="mt-2 text-sm text-zinc-300">Parity Score: {report.narrative.parityScore}</p>
                  <p className="text-sm text-zinc-400">Ghost Commands detected: {report.narrative.findings.length}</p>
                </div>
                <RemediationCards cards={report.narrative.cards} />
              </div>
            )}

            {activeTab === "Adversarial" && report && (
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="panel p-4">
                  <h3 className="text-sm font-semibold text-red-200">Unprotected Results</h3>
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
                  <h3 className="text-sm font-semibold text-emerald-200">Aletheia-Protected Results</h3>
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

        {activeView === "Adversary" && report && (
          <section className="space-y-4">
            <div className="panel p-4">
              <h2 className="text-sm font-semibold">Payload Launcher</h2>
              <p className="mt-1 text-xs text-zinc-500">
                Source: aletheia-redteam-kit attack corpus. Pre-connection mode captures baseline vulnerabilities.
              </p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {payloads.slice(0, 18).map((payload) => (
                  <div key={payload.id} className="rounded border border-zinc-800 bg-black/30 p-2 text-xs">
                    <p className="font-semibold text-zinc-200">{payload.id}</p>
                    <p className="text-zinc-400">{payload.name}</p>
                    <p className={severityClass(payload.severity)}>{payload.severity}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="panel p-4">
                <h3 className="text-sm font-semibold text-red-200">Unprotected Results</h3>
                <ul className="mt-2 space-y-1 text-xs text-zinc-300">
                  {report.adversarial.outcomes.slice(0, 20).map((outcome) => (
                    <li key={`${outcome.payloadId}-raw`}>
                      {outcome.payloadId}: {outcome.unprotectedDecision}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="panel p-4">
                <h3 className="text-sm font-semibold text-emerald-200">Aletheia-Protected Results</h3>
                <ul className="mt-2 space-y-1 text-xs text-zinc-300">
                  {report.adversarial.outcomes.slice(0, 20).map((outcome) => (
                    <li key={`${outcome.payloadId}-protected`}>
                      {outcome.payloadId}: {outcome.protectedDecision}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </section>
        )}

        {activeView === "ApiTesting" && (
          <section className="space-y-4">
            <div className="panel p-4">
              <h2 className="text-sm font-semibold">Adversarial API Endpoint Testing</h2>
              <p className="mt-1 text-xs text-zinc-500">
                Run endpoint attacks with method fuzzing and parameter injection using payload corpus from attacks/*.json.
              </p>

              <div className="mt-4 grid gap-4 lg:grid-cols-3">
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

              <button
                type="button"
                onClick={() => void runApiEndpointTests()}
                disabled={apiLoading}
                className="mt-4 rounded-md border border-red-700 bg-red-950/30 px-4 py-2 text-sm text-red-200 hover:bg-red-950/50 disabled:opacity-50"
              >
                {apiLoading ? "Running endpoint tests..." : "Run API Endpoint Adversarial Tests"}
              </button>
            </div>

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

        {activeView === "Mneme" && (
          <section className="space-y-4">
            <div className="panel p-4">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold">Mneme Vault Queue</h2>
                <button
                  type="button"
                  onClick={downloadMnemeBundle}
                  className="rounded-md border border-emerald-700 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200"
                >
                  Export JSON Log Bundle
                </button>
              </div>
              <p className="mt-2 text-xs text-zinc-500">
                Every event is emitted as a signing-ready JSON object for cryptographic sealing.
              </p>
            </div>

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
                  {mnemeLogs.map((log) => (
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
      </main>
    </div>
  );
}
