// Thin typed HTTP client for the TraceLayer API.
//
// * All requests go to the same origin (/api): Vite proxies in dev, nginx in Docker.
// * The analyst name and optional API token live in localStorage and are sent as
//   X-Analyst / Authorization headers; the backend records the name in the audit log.
// * Errors are normalised into ApiError so every page can show the backend's message.

import type {
  Analysis, AuditEntry, Batch, Claim, Detection, EventDetail, EventPage, Graph, InvestigationDetail,
  InvestigationListItem, Overview, Report, Run, SystemStatus, Timeline,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
  }
}

const SETTINGS_KEY = "tracelayer.settings";

export interface ClientSettings { analyst: string; token: string }

export function loadSettings(): ClientSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (raw) return { analyst: "analyst", token: "", ...JSON.parse(raw) };
  } catch {
    /* storage unavailable (private mode): fall back to defaults */
  }
  return { analyst: "analyst", token: "" };
}

export function saveSettings(s: ClientSettings): void {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* ignore */
  }
}

function headers(json: boolean): HeadersInit {
  const s = loadSettings();
  const h: Record<string, string> = { "X-Analyst": s.analyst || "analyst" };
  if (s.token) h.Authorization = `Bearer ${s.token}`;
  if (json) h["Content-Type"] = "application/json";
  return h;
}

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d: any) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`).join("; ");
  if (detail && typeof detail === "object" && "message" in detail) return String((detail as any).message);
  return "Request failed";
}

async function request<T>(method: string, path: string, body?: unknown, form?: FormData): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: headers(body !== undefined),
      body: form ?? (body !== undefined ? JSON.stringify(body) : undefined),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the TraceLayer API. Is the backend running on port 8000?");
  }
  if (!res.ok) {
    let detail: unknown = res.statusText;
    try {
      detail = (await res.json()).detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, describe(detail), detail);
  }
  return (await res.json()) as T;
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)));
    else sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export interface EventQuery {
  q?: string; event_type?: string[]; host?: string; user?: string; ip?: string; outcome?: string; tag?: string;
  start?: string; end?: string; investigation_id?: string; detection_id?: string; role?: string;
  order?: "asc" | "desc"; limit?: number; cursor?: string;
}

export const api = {
  status: () => request<SystemStatus>("GET", "/system/status"),
  overview: () => request<Overview>("GET", "/metrics/overview"),
  performance: () => request<Record<string, any>>("GET", "/metrics/performance"),

  events: (q: EventQuery) => request<EventPage>("GET", `/events${qs(q as Record<string, unknown>)}`),
  facets: (investigation_id?: string) =>
    request<Record<string, { value: string; count: number }[]>>("GET", `/events/facets${qs({ investigation_id })}`),
  event: (id: string) => request<EventDetail>("GET", `/events/${id}`),
  verifyEvent: (id: string) => request<{ ok: boolean; issues: string[] }>("GET", `/events/${id}/verify`),

  detections: (p: { severity?: string; investigation_id?: string; unassigned?: boolean } = {}) =>
    request<Detection[]>("GET", `/detections${qs(p)}`),
  rules: () => request<{ id: string; name: string; severity: string; tactic: string; technique: string; description: string }[]>("GET", "/rules"),

  investigations: (p: { status?: string; severity?: string; q?: string } = {}) =>
    request<InvestigationListItem[]>("GET", `/investigations${qs(p)}`),
  investigation: (id: string) => request<InvestigationDetail>("GET", `/investigations/${id}`),
  patchInvestigation: (id: string, body: { status?: string; assignee?: string; note?: string }) =>
    request<InvestigationListItem>("PATCH", `/investigations/${id}`, body),
  timeline: (id: string) => request<Timeline>("GET", `/investigations/${id}/timeline`),
  graph: (id: string) => request<Graph>("GET", `/investigations/${id}/graph`),
  audit: (id: string) => request<AuditEntry[]>("GET", `/investigations/${id}/audit`),

  analyses: (invId: string) => request<Analysis[]>("GET", `/investigations/${invId}/analyses`),
  createAnalysis: (invId: string, engine: string) =>
    request<Analysis>("POST", `/investigations/${invId}/analyses`, { engine }),
  reviewClaim: (analysisId: string, claimId: string, decision: string, note?: string) =>
    request<Claim>("POST", `/analyses/${analysisId}/claims/${claimId}/review`, { decision, note }),
  reviewAnalysis: (analysisId: string, decision: string, note?: string) =>
    request<Analysis>("POST", `/analyses/${analysisId}/review`, { decision, note }),
  validate: (investigation_id: string, output: string) =>
    request<{ integrity: Record<string, any>; claims: any[] }>("POST", "/integrity/validate", { investigation_id, output }),

  batches: () => request<Batch[]>("GET", "/ingest/batches"),
  verifyLedger: () => request<Record<string, any>>("POST", "/integrity/verify"),
  synthetic: (body: { seed: number; background_events: number; anchor: string; run_pipeline: boolean }) =>
    request<Record<string, any>>("POST", "/synthetic/generate", body),
  uploadFile: (file: File, source: string, parser: string, year?: number) => {
    const f = new FormData();
    f.append("file", file);
    f.append("source", source);
    f.append("parser", parser);
    if (year) f.append("year", String(year));
    return request<Record<string, any>>("POST", "/ingest/file", undefined, f);
  },
  startPipeline: () => request<Run>("POST", "/pipeline/runs"),
  runs: (kind?: string) => request<Run[]>("GET", `/pipeline/runs${qs({ kind })}`),
  run: (id: string) => request<Run>("GET", `/pipeline/runs/${id}`),
  reports: (kind: string) => request<Report[]>("GET", `/reports${qs({ kind })}`),
  report: (id: string) => request<Report>("GET", `/reports/${id}`),
  runEvaluation: () => request<Run>("POST", "/reports/evaluation"),
  runBenchmark: (events: number) => request<Run>("POST", "/reports/benchmark", { events }),

  /** Downloads go through fetch (not a plain link) so the auth/analyst headers are sent. */
  async download(invId: string, format: string): Promise<void> {
    const res = await fetch(`/api/investigations/${invId}/export?format=${format}`, { headers: headers(false) });
    if (!res.ok) throw new ApiError(res.status, `Export failed (${res.status})`);
    const blob = await res.blob();
    const name = res.headers.get("Content-Disposition")?.match(/filename="(.+)"/)?.[1] ?? `export.${format}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  },
};
