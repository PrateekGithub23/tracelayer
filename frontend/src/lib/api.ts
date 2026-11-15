// Typed client for the TraceLayer API.
//
// * Authentication is a server-side session in an HttpOnly cookie: JavaScript never sees a credential,
//   and nothing secret is written to localStorage (v1 stored a bearer token there).
// * State-changing requests carry the session's CSRF token in X-CSRF-Token. The token is held in memory
//   only and re-fetched from /api/auth/me after a reload.
// * Requests go through a pluggable Transport: HTTP for the real backend, or the browser-local demo
//   transport (src/demo/) for the public read-only demo. Pages and components cannot tell the difference,
//   which keeps the two experiences identical.
// * 401s with a session reason (expired / revoked) raise a window event the AuthProvider turns into the
//   "session expired" screen, instead of every page showing a generic error.

import type {
  Analysis, AuditEntry, Batch, Claim, Detection, EventDetail, EventPage, Graph, InvestigationDetail,
  InvestigationListItem, Overview, Report, Run, SystemStatus, Timeline,
} from "./types";
import type {
  ActivityEntry, AdminUser, AppSettings, AuthConfig, CaseComment, DatasetInfo, DirectoryUser, Invitation, LlmStatus,
  LoginRecord, Me, PinnedEvidence, Queues, SavedFilter, SessionInfo,
} from "./types-v2";

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
  }
}

export interface TransportResponse { status: number; body: unknown; blob?: Blob; filename?: string }
export type Transport = (method: string, path: string, init: { json?: unknown; form?: FormData; headers: Record<string, string>; raw?: boolean }) => Promise<TransportResponse>;

let csrfToken = "";
export function setCsrfToken(token: string): void { csrfToken = token; }

const httpTransport: Transport = async (method, path, init) => {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      headers: init.json !== undefined ? { ...init.headers, "Content-Type": "application/json" } : init.headers,
      body: init.form ?? (init.json !== undefined ? JSON.stringify(init.json) : undefined),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the TraceLayer API. Is the backend running?");
  }
  if (init.raw && res.ok) {
    const name = res.headers.get("Content-Disposition")?.match(/filename="(.+)"/)?.[1];
    return { status: res.status, body: null, blob: await res.blob(), filename: name };
  }
  let body: unknown = null;
  try { body = await res.json(); } catch { body = { detail: res.statusText }; }
  return { status: res.status, body };
};

let transport: Transport = httpTransport;
export function setTransport(t: Transport): void { transport = t; }
export const isDemoTransport = () => transport !== httpTransport;

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d: any) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`).join("; ");
  if (detail && typeof detail === "object" && "message" in detail) return String((detail as any).message);
  return "Request failed";
}

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function call(method: string, path: string, json?: unknown, form?: FormData, raw = false): Promise<TransportResponse> {
  const headers: Record<string, string> = {};
  if (UNSAFE.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await transport(method, path, { json, form, headers, raw });
  if (res.status >= 400) {
    const detail = (res.body as any)?.detail ?? res.body;
    const reason = typeof detail === "object" && detail ? (detail as any).reason : undefined;
    if (res.status === 401 && reason && reason !== "missing" && !path.startsWith("/auth/login")) {
      window.dispatchEvent(new CustomEvent("tl:auth-lost", { detail: reason }));
    }
    if (res.status === 403 && reason === "must_change_password") {
      window.dispatchEvent(new CustomEvent("tl:must-change-password"));
    }
    throw new ApiError(res.status, describe(detail), detail);
  }
  return res;
}

async function request<T>(method: string, path: string, body?: unknown, form?: FormData): Promise<T> {
  return (await call(method, path, body, form)).body as T;
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

export interface InvestigationQuery {
  view?: "all" | "open" | "mine" | "needs_review" | "unassigned" | "recent";
  status?: string; severity?: string; priority?: string; q?: string; assignee_id?: string;
  sort?: "score" | "updated" | "created" | "priority";
}

export interface CasePatch {
  expected_version: number; status?: string; priority?: string; assignee_id?: string; reviewer_id?: string;
  resolution?: string; reason?: string;
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

  investigations: (p: InvestigationQuery = {}) =>
    request<InvestigationListItem[]>("GET", `/investigations${qs(p as Record<string, unknown>)}`),
  investigation: (id: string) => request<InvestigationDetail>("GET", `/investigations/${id}`),
  updateCase: (id: string, body: CasePatch) => request<InvestigationListItem>("PATCH", `/investigations/${id}`, body),
  assignToMe: (id: string, version: number) =>
    request<InvestigationListItem>("POST", `/investigations/${id}/assign-to-me?expected_version=${version}`),
  queues: () => request<Queues>("GET", "/queues"),
  activity: (id: string) => request<ActivityEntry[]>("GET", `/investigations/${id}/activity`),
  comments: (id: string) => request<CaseComment[]>("GET", `/investigations/${id}/comments`),
  addComment: (id: string, kind: "comment" | "note", body: string) =>
    request<CaseComment>("POST", `/investigations/${id}/comments`, { kind, body }),
  editComment: (id: string, cid: string, body: string) =>
    request<CaseComment>("PATCH", `/investigations/${id}/comments/${cid}`, { body }),
  deleteComment: (id: string, cid: string) => request<{ ok: boolean }>("DELETE", `/investigations/${id}/comments/${cid}`),
  pins: (id: string) => request<PinnedEvidence[]>("GET", `/investigations/${id}/evidence`),
  pin: (id: string, event_id: string, note?: string) =>
    request<{ ok: boolean }>("POST", `/investigations/${id}/evidence`, { event_id, note }),
  unpin: (id: string, event_id: string) => request<{ ok: boolean }>("DELETE", `/investigations/${id}/evidence/${event_id}`),
  directory: () => request<DirectoryUser[]>("GET", "/users/directory"),
  filters: (scope?: string) => request<SavedFilter[]>("GET", `/filters${qs({ scope })}`),
  saveFilter: (name: string, scope: string, params: Record<string, unknown>) =>
    request<SavedFilter>("POST", "/filters", { name, scope, params }),
  deleteFilter: (fid: string) => request<{ ok: boolean }>("DELETE", `/filters/${fid}`),
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

  // ---- auth + account
  authConfig: () => request<AuthConfig>("GET", "/auth/config"),
  me: () => request<Me>("GET", "/auth/me"),
  login: (email: string, password: string) => request<Me>("POST", "/auth/login", { email, password }),
  logout: () => request<{ ok: boolean }>("POST", "/auth/logout"),
  updateProfile: (display_name: string) => request<Me["user"]>("PATCH", "/auth/me", { display_name }),
  changePassword: (current_password: string, new_password: string) =>
    request<Me>("POST", "/auth/password", { current_password, new_password }),
  sessions: () => request<SessionInfo[]>("GET", "/auth/sessions"),
  revokeSession: (sid: string) => request<{ ok: boolean }>("DELETE", `/auth/sessions/${sid}`),
  revokeOtherSessions: () => request<{ revoked: number }>("POST", "/auth/sessions/revoke-others"),
  loginHistory: () => request<LoginRecord[]>("GET", "/auth/login-history"),
  register: (body: { invite_token?: string; email: string; display_name: string; password: string }) =>
    request<{ user: Me["user"] }>("POST", "/auth/register", body),
  recover: (email: string, code: string, new_password: string) =>
    request<{ ok: boolean }>("POST", "/auth/recover", { email, code, new_password }),

  // ---- administration
  users: () => request<AdminUser[]>("GET", "/admin/users"),
  createUser: (body: { email: string; display_name?: string; role: string; password: string; must_change_password: boolean }) =>
    request<AdminUser>("POST", "/admin/users", body),
  patchUser: (uid: string, body: { role?: string; status?: string; display_name?: string }) =>
    request<AdminUser>("PATCH", `/admin/users/${uid}`, body),
  revokeUserSessions: (uid: string) => request<{ revoked: number }>("POST", `/admin/users/${uid}/revoke-sessions`),
  recoveryCode: (uid: string) => request<{ code: string; expires_at: string; email: string }>("POST", `/admin/users/${uid}/recovery-code`),
  userLoginHistory: (uid: string) => request<LoginRecord[]>("GET", `/admin/users/${uid}/login-history`),
  invitations: () => request<Invitation[]>("GET", "/admin/invitations"),
  invite: (email: string | null, role: string) =>
    request<Invitation & { token: string }>("POST", "/admin/invitations", { email: email || null, role }),
  revokeInvitation: (iid: string) => request<{ ok: boolean }>("DELETE", `/admin/invitations/${iid}`),
  settings: () => request<AppSettings>("GET", "/admin/settings"),
  patchSettings: (body: Partial<AppSettings>) => request<AppSettings>("PATCH", "/admin/settings", body),
  auditLog: (p: { before_id?: number; action?: string } = {}) =>
    request<{ items: AuditEntry[]; next_before_id: number | null }>("GET", `/admin/audit${qs(p)}`),

  // ---- datasets + LLM
  datasets: () => request<DatasetInfo[]>("GET", "/datasets"),
  dataset: (did: string) => request<DatasetInfo>("GET", `/datasets/${did}`),
  importDataset: (did: string) => request<Run>("POST", `/datasets/${did}/import`),
  llmStatus: () => request<LlmStatus>("GET", "/llm/status"),
  llmTest: () => request<Record<string, any>>("POST", "/llm/test"),
  /** Demo transport only: validator examples whose results were recorded from the real engine. */
  demoExamples: () => request<{ title: string; investigation_id: string; output: string; result: any }[]>("GET", "/demo/examples"),

  /** Exports go through the transport (not a plain link) so the session and CSRF rules apply. */
  async download(invId: string, format: string): Promise<void> {
    const res = await call("GET", `/investigations/${invId}/export?format=${format}`, undefined, undefined, true);
    const blob = res.blob!;
    const name = res.filename ?? `export.${format}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  },
};
