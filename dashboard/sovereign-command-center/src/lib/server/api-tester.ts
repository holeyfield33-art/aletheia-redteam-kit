import fs from "fs";
import path from "path";
import {
  AdversarialPayload,
  ApiTestRequest,
  ApiTestResult,
  ApiTestTarget,
  Severity,
} from "@/lib/types";

const DEFAULT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

function repoRootFromAppCwd(): string {
  return path.resolve(process.cwd(), "../..");
}

function loadPayloadsFromKit(payloadCategoryFilter?: string[]): AdversarialPayload[] {
  const attacksDir = path.join(repoRootFromAppCwd(), "attacks");
  if (!fs.existsSync(attacksDir)) {
    return [];
  }

  const requested = new Set((payloadCategoryFilter ?? []).map((item) => item.toLowerCase()));
  const payloads: AdversarialPayload[] = [];
  const files = fs.readdirSync(attacksDir).filter((file) => file.endsWith(".json"));

  for (const file of files) {
    const abs = path.join(attacksDir, file);
    try {
      const parsed = JSON.parse(fs.readFileSync(abs, "utf8"));
      if (!Array.isArray(parsed)) {
        continue;
      }
      for (const payload of parsed) {
        const category = String(payload.category ?? "").toLowerCase();
        if (requested.size && !requested.has(category)) {
          continue;
        }
        payloads.push({
          id: String(payload.id ?? `${file}-${payloads.length}`),
          name: String(payload.name ?? "Unnamed Payload"),
          category: String(payload.category ?? "general"),
          payload: String(payload.payload ?? ""),
          expected_decision: String(payload.expected_decision ?? "DENIED"),
          severity: (String(payload.severity ?? "MEDIUM").toUpperCase() as Severity),
          action: String(payload.action ?? "block"),
        });
      }
    } catch {
      continue;
    }
  }

  return payloads.slice(0, 80);
}

function severityFromResponse(statusCode: number, durationMs: number, bodySnippet: string): Severity {
  if (statusCode >= 500) {
    return "CRITICAL";
  }
  if (statusCode >= 400 && statusCode !== 404) {
    return "HIGH";
  }
  if (durationMs > 5000) {
    return "MEDIUM";
  }
  const suspicious = /(stack trace|exception|sql syntax|traceback|internal server error)/i.test(bodySnippet);
  if (suspicious) {
    return "HIGH";
  }
  return "LOW";
}

function buildTargets(request: ApiTestRequest): ApiTestTarget[] {
  const merged = [
    ...(request.singleTarget ? [request.singleTarget] : []),
    ...(request.batchTargets ?? []),
    ...(request.jsonTargets ?? []),
  ];

  const unique = new Map<string, ApiTestTarget>();
  for (const target of merged) {
    const key = `${target.method ?? "GET"}-${target.url}`;
    if (target.url?.trim()) {
      unique.set(key, { url: target.url.trim(), method: (target.method ?? "GET").toUpperCase() });
    }
  }
  return Array.from(unique.values());
}

async function runSingleRequest(
  target: ApiTestTarget,
  method: string,
  injectionMode: "raw" | "query" | "header" | "body",
  payload: AdversarialPayload,
): Promise<ApiTestResult> {
  const start = Date.now();
  let url = target.url;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  let body: string | undefined;

  if (injectionMode === "query") {
    const parsed = new URL(url);
    parsed.searchParams.set("input", payload.payload);
    url = parsed.toString();
  } else if (injectionMode === "header") {
    headers["X-Aletheia-Adversarial-Payload"] = payload.payload;
  } else if (injectionMode === "body" || (injectionMode === "raw" && method !== "GET")) {
    body = JSON.stringify({ input: payload.payload, payloadId: payload.id });
  }

  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
    });
    const text = await response.text();
    const durationMs = Date.now() - start;
    const signal = text.slice(0, 220).replace(/\s+/g, " ").trim();

    return {
      id: `${payload.id}-${method}-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
      targetUrl: target.url,
      method,
      injectionMode,
      statusCode: response.status,
      ok: response.ok,
      durationMs,
      severity: severityFromResponse(response.status, durationMs, signal),
      signal,
      payloadId: payload.id,
    };
  } catch (error) {
    return {
      id: `${payload.id}-${method}-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
      targetUrl: target.url,
      method,
      injectionMode,
      statusCode: 0,
      ok: false,
      durationMs: Date.now() - start,
      severity: "CRITICAL",
      signal: error instanceof Error ? error.message : String(error),
      payloadId: payload.id,
    };
  }
}

export async function runApiEndpointTest(request: ApiTestRequest): Promise<ApiTestResult[]> {
  const targets = buildTargets(request);
  if (!targets.length) {
    return [];
  }

  const payloads = loadPayloadsFromKit(request.payloadCategoryFilter).slice(0, 10);
  if (!payloads.length) {
    return [];
  }

  const results: ApiTestResult[] = [];

  for (const target of targets.slice(0, 30)) {
    const methods = request.enableMethodFuzzing
      ? DEFAULT_METHODS
      : [(target.method ?? "GET").toUpperCase()];

    for (const method of methods) {
      for (const payload of payloads) {
        results.push(await runSingleRequest(target, method, "raw", payload));

        if (request.enableParameterInjection) {
          results.push(await runSingleRequest(target, method, "query", payload));
          results.push(await runSingleRequest(target, method, "header", payload));
          if (method !== "GET") {
            results.push(await runSingleRequest(target, method, "body", payload));
          }
        }

        if (results.length >= 400) {
          return results;
        }
      }
    }
  }

  return results;
}
