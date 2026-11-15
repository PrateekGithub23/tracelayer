// Browser-local transport for the public, read-only demo.
//
// Reads are served from a snapshot of *real* API responses recorded from a real TraceLayer backend
// (backend/app/demo/build_snapshot.py). Writes the demo allows (case workflow, comments, pins, claim
// reviews, saved filters) are applied to in-memory state using the same rules the server enforces
// (mirrored from backend/app/cases.py and api/investigations.py), so the workflow behaves like the real app.
// Nothing is persisted: state lives in this tab and resets on reload. Operations that need the Python
// backend (generating analyses, validating arbitrary text, imports, admin) are refused with an explanation.

import type { Transport, TransportResponse } from "../lib/api";

type Json = any;
interface Snapshot {
  generated_at: string;
  main_investigation: string;
  responses: Record<string, Json>;
  events: Json[];
  event_details: Record<string, Json>;
  validator_examples: { title: string; investigation_id: string; output: string; result: Json }[];
  llm_analysis: boolean;
  attribution: string | null;
}

const TRANSITIONS: Record<string, string[]> = {
  new: ["triaged", "investigating"], triaged: ["investigating", "resolved"], investigating: ["awaiting_review", "resolved"],
  awaiting_review: ["investigating", "resolved"], resolved: ["closed", "investigating"], closed: ["investigating"],
};
const OPEN = ["new", "triaged", "investigating", "awaiting_review"];
const RESOLUTIONS = ["true_positive", "benign_true_positive", "false_positive", "duplicate", "unspecified"];
const UNSAFE = ["unsupported_claim", "contradictory_finding"];

let snap: Snapshot | null = null;
let loading: Promise<Snapshot> | null = null;
const state = {
  signedIn: true,
  invs: new Map<string, Json>(),
  details: new Map<string, Json>(),
  activity: new Map<string, Json[]>(),
  comments: new Map<string, Json[]>(),
  pins: new Map<string, Json[]>(),
  analyses: new Map<string, Json[]>(),
  filters: [] as Json[],
  seq: 1,
};

async function load(): Promise<Snapshot> {
  if (snap) return snap;
  loading ??= fetch(`${import.meta.env.BASE_URL}demo-data/snapshot.json`).then((r) => {
    if (!r.ok) throw new Error(`demo data missing (${r.status})`);
    return r.json();
  });
  snap = await loading;
  const r = snap.responses;
  for (const inv of r["/investigations?view=all"] ?? []) {
    state.invs.set(inv.id, structuredClone(inv));
    state.details.set(inv.id, structuredClone(r[`/investigations/${inv.id}`]));
    state.activity.set(inv.id, structuredClone(r[`/investigations/${inv.id}/activity`] ?? []));
    state.comments.set(inv.id, structuredClone(r[`/investigations/${inv.id}/comments`] ?? []));
    state.pins.set(inv.id, structuredClone(r[`/investigations/${inv.id}/evidence`] ?? []));
    state.analyses.set(inv.id, structuredClone(r[`/investigations/${inv.id}/analyses`] ?? []));
  }
  state.filters = structuredClone(r["/filters"] ?? []);
  return snap;
}

const ok = (body: Json): TransportResponse => ({ status: 200, body });
const fail = (status: number, detail: Json): TransportResponse => ({ status, body: { detail } });
const DEMO_ONLY = "Not available in the public demo, which runs entirely in your browser. Run TraceLayer locally (docker compose up) for the full application.";

function me(): Json {
  return snap!.responses["/auth/me"];
}
const actor = () => `${me().user.email} (${me().user.id})`;
const now = () => new Date().toISOString();

function addActivity(invId: string, action: string, details: Json, comment: string | null = null): void {
  const list = state.activity.get(invId) ?? [];
  list.unshift({ id: 1_000_000 + state.seq++, timestamp: now(), actor: actor(), action, target_id: invId, details, comment,
    entry_hash: "local-demo-entry-not-hash-chained" });
  state.activity.set(invId, list);
}

function syncCase(invId: string, patch: Json): Json {
  const inv = { ...state.invs.get(invId), ...patch, updated_at: now() };
  inv.version += 1;
  state.invs.set(invId, inv);
  state.details.set(invId, { ...state.details.get(invId), ...inv });
  return inv;
}

function nameOf(uid: string | null): string | null {
  return (snap!.responses["/users/directory"] as Json[]).find((u) => u.id === uid)?.display_name ?? null;
}

function updateCase(invId: string, body: Json): TransportResponse {
  const inv = state.invs.get(invId);
  if (!inv) return fail(404, "investigation not found");
  if (body.expected_version !== inv.version)
    return fail(409, { message: "this case was changed by someone else; reload and try again", current_version: inv.version });
  const uid = me().user.id;
  if (!(inv.assignee_id == null || inv.assignee_id === uid || (inv.status === "awaiting_review" && inv.reviewer_id === uid)))
    return fail(403, "this case is assigned to someone else; ask them or an administrator");
  const changes: Json = {};
  const patch: Json = {};
  if (body.assignee_id !== undefined && (body.assignee_id || null) !== inv.assignee_id) {
    if (inv.assignee_id && inv.assignee_id !== uid) return fail(403, "only an administrator can take a case from another analyst");
    patch.assignee_id = body.assignee_id || null; patch.assignee_name = nameOf(patch.assignee_id);
    changes.assignee_id = [inv.assignee_id, patch.assignee_id];
  }
  if (body.reviewer_id !== undefined && (body.reviewer_id || null) !== inv.reviewer_id) {
    patch.reviewer_id = body.reviewer_id || null; patch.reviewer_name = nameOf(patch.reviewer_id);
    changes.reviewer_id = [inv.reviewer_id, patch.reviewer_id];
  }
  if (body.priority && body.priority !== inv.priority) { patch.priority = body.priority; changes.priority = [inv.priority, body.priority]; }
  const reason = (body.reason ?? "").trim();
  if (body.status && body.status !== inv.status) {
    if (reason.length < 3) return fail(422, "say why the status is changing (reason, at least 3 characters)");
    if (!(TRANSITIONS[inv.status] ?? []).includes(body.status))
      return fail(409, `cannot move a case from ${inv.status} to ${body.status}`);
    const reviewer = patch.reviewer_id ?? inv.reviewer_id;
    const assignee = patch.assignee_id ?? inv.assignee_id;
    if (body.status === "resolved" && !RESOLUTIONS.includes(body.resolution ?? inv.resolution)) return fail(422, "resolving needs a resolution");
    if (body.status === "awaiting_review" && !reviewer) return fail(422, "choose a reviewer before requesting review");
    if (body.status === "awaiting_review" && reviewer === assignee) return fail(422, "the reviewer must be someone other than the assignee");
    if (inv.status === "awaiting_review" && uid !== inv.reviewer_id) return fail(403, "only the assigned reviewer can complete or return a review");
    if (body.status === "resolved") { patch.resolution = body.resolution ?? inv.resolution; patch.resolved_at = now(); }
    if (body.status === "closed") patch.closed_at = now();
    if (body.status === "investigating" && ["resolved", "closed"].includes(inv.status)) {
      patch.reopen_count = inv.reopen_count + 1; patch.resolved_at = null; patch.closed_at = null; changes.reopened = true;
    }
    changes.status = [inv.status, body.status];
    patch.status = body.status;
  }
  if (!Object.keys(changes).length) return ok(inv);
  const updated = syncCase(invId, patch);
  addActivity(invId, changes.reopened ? "case.reopened" : changes.status ? "case.status_changed" : "case.updated",
    { changes, reason: reason || null, version: updated.version });
  return ok(updated);
}

function listInvestigations(params: URLSearchParams): Json[] {
  const uid = me().user.id;
  let xs = [...state.invs.values()];
  const view = params.get("view") ?? "all";
  if (view === "open") xs = xs.filter((i) => OPEN.includes(i.status));
  if (view === "mine") xs = xs.filter((i) => i.assignee_id === uid && OPEN.includes(i.status));
  if (view === "needs_review") xs = xs.filter((i) => i.reviewer_id === uid && i.status === "awaiting_review");
  if (view === "unassigned") xs = xs.filter((i) => !i.assignee_id && OPEN.includes(i.status));
  for (const k of ["status", "severity", "priority"] as const) {
    const v = params.get(k);
    if (v) xs = xs.filter((i) => i[k] === v);
  }
  const q = params.get("q")?.toLowerCase();
  if (q) xs = xs.filter((i) => i.title.toLowerCase().includes(q));
  const sort = view === "recent" ? "updated" : params.get("sort") ?? "score";
  const by: Record<string, (a: Json, b: Json) => number> = {
    score: (a, b) => b.score - a.score, updated: (a, b) => b.updated_at.localeCompare(a.updated_at),
    created: (a, b) => b.created_at.localeCompare(a.created_at), priority: (a, b) => a.priority.localeCompare(b.priority) || b.score - a.score,
  };
  return xs.sort(by[sort] ?? by.score);
}

function listEvents(p: URLSearchParams): Json {
  let xs = snap!.events;
  const q = p.get("q")?.toLowerCase();
  if (q) xs = xs.filter((e) => [e.command_line, e.username, e.host, e.src_ip, e.dst_ip, e.message, e.process, e.id].some((v) => v && String(v).toLowerCase().includes(q)));
  const types = p.getAll("event_type");
  if (types.length) xs = xs.filter((e) => types.includes(e.event_type));
  const eq: [string, string][] = [["host", "host"], ["user", "username"], ["outcome", "outcome"]];
  for (const [param, field] of eq) { const v = p.get(param); if (v) xs = xs.filter((e) => e[field] === v); }
  const ip = p.get("ip"); if (ip) xs = xs.filter((e) => e.src_ip === ip || e.dst_ip === ip);
  const tag = p.get("tag"); if (tag) xs = xs.filter((e) => e.tags.includes(tag));
  const inv = p.get("investigation_id"); const role = p.get("role");
  if (inv) xs = xs.filter((e) => e._inv[inv] && (!role || e._inv[inv] === role));
  const det = p.get("detection_id"); if (det) xs = xs.filter((e) => e._det.includes(det));
  const start = p.get("start"); if (start) xs = xs.filter((e) => e.timestamp >= start);
  const end = p.get("end"); if (end) xs = xs.filter((e) => e.timestamp <= end);
  const asc = p.get("order") === "asc";
  xs = [...xs].sort((a, b) => (asc ? 1 : -1) * (a.timestamp.localeCompare(b.timestamp) || a.id.localeCompare(b.id)));
  const limit = Number(p.get("limit") ?? 50); const offset = Number(p.get("cursor") ?? 0);
  const page = xs.slice(offset, offset + limit).map(({ _inv, _det, ...e }) => e);
  return { items: page, total: xs.length, next_cursor: offset + limit < xs.length ? String(offset + limit) : null };
}

function reviewClaim(analysisId: string, claimId: string, body: Json): TransportResponse {
  for (const [invId, list] of state.analyses) {
    const a = list.find((x) => x.id === analysisId);
    if (!a) continue;
    if (a.status !== "pending_review") return fail(409, `analysis is already ${a.status}`);
    const c = a.claims.find((x: Json) => x.id === claimId);
    if (!c) return fail(404, "claim not found");
    if (body.decision === "accept" && UNSAFE.includes(c.verdict) && !(body.note ?? "").trim())
      return fail(422, "accepting an unsupported/contradictory claim requires a justification note");
    c.review_status = { accept: "accepted", reject: "rejected", pending: "pending" }[body.decision as string];
    c.review_note = body.note ?? null;
    addActivity(invId, `claim.${c.review_status}`, { claim_id: c.id, verdict: c.verdict, note: body.note ?? null });
    return ok(c);
  }
  return fail(404, "analysis not found");
}

function reviewAnalysis(analysisId: string, body: Json): TransportResponse {
  for (const [invId, list] of state.analyses) {
    const a = list.find((x) => x.id === analysisId);
    if (!a) continue;
    if (a.status !== "pending_review") return fail(409, `analysis is already ${a.status}`);
    if (body.decision === "approve") {
      const blocking = a.claims.filter((c: Json) => UNSAFE.includes(c.verdict) && c.review_status === "pending");
      if (blocking.length) return fail(409, { message: "every unsupported or contradictory claim must be reviewed first", blocking_claim_ids: blocking.map((c: Json) => c.id) });
      for (const c of a.claims) if (c.review_status === "pending") c.review_status = "accepted";
      a.status = "approved";
      syncCase(invId, { approved_analysis_id: a.id });
    } else a.status = "rejected";
    Object.assign(a, { reviewed_by: me().user.email, reviewed_at: now(), review_note: body.note ?? null });
    addActivity(invId, `analysis.${a.status}`, { note: body.note ?? null });
    return ok(a);
  }
  return fail(404, "analysis not found");
}

export const demoTransport: Transport = async (method, rawPath, init) => {
  const s = await load();
  const [path, query = ""] = rawPath.split("?");
  const params = new URLSearchParams(query);
  const body = init.json as Json;
  const seg = path.split("/").filter(Boolean);
  const R = s.responses;

  if (method === "GET") {
    if (path === "/auth/me") return state.signedIn ? ok(me()) : fail(401, { message: "authentication required", reason: "missing" });
    if (path === "/auth/config") return ok({ ...R["/auth/config"], registration_mode: "disabled", demo: true });
    if (path === "/investigations") return ok(listInvestigations(params));
    if (path === "/queues") {
      const uid = me().user.id; const xs = [...state.invs.values()];
      return ok({ open: xs.filter((i) => OPEN.includes(i.status)).length, mine: xs.filter((i) => i.assignee_id === uid && OPEN.includes(i.status)).length,
        needs_review: xs.filter((i) => i.reviewer_id === uid && i.status === "awaiting_review").length, unassigned: xs.filter((i) => !i.assignee_id && OPEN.includes(i.status)).length });
    }
    if (seg[0] === "investigations" && seg[1]) {
      const id = seg[1];
      if (!state.invs.has(id)) return fail(404, "investigation not found");
      if (seg.length === 2) {
        const d = state.details.get(id);
        return ok({ ...d, analyses: (state.analyses.get(id) ?? []).map((a) => ({ id: a.id, engine: a.engine, model: a.model, status: a.status, created_at: a.created_at, integrity: a.integrity })) });
      }
      const sub = seg[2];
      if (sub === "activity") return ok(state.activity.get(id));
      if (sub === "comments") return ok(state.comments.get(id));
      if (sub === "evidence") return ok(state.pins.get(id));
      if (sub === "analyses") return ok(state.analyses.get(id));
      if (sub === "export") {
        const fmt = params.get("format");
        if (fmt === "md" && R[`/investigations/${id}/export?format=md`])
          return { status: 200, body: null, blob: new Blob([R[`/investigations/${id}/export?format=md`].__text__], { type: "text/markdown" }), filename: `tracelayer-${id}.md` };
        if (fmt === "zip" && id === s.main_investigation) {
          const r = await fetch(`${import.meta.env.BASE_URL}demo-data/tracelayer-${id}.zip`);
          if (r.ok) return { status: 200, body: null, blob: await r.blob(), filename: `tracelayer-${id}.zip` };
        }
        return fail(404, "This export was not recorded for the demo. The Markdown report and the main case's evidence bundle are available.");
      }
      const key = `/investigations/${id}/${sub}`;
      return key in R ? ok(R[key]) : fail(404, "not recorded in the demo snapshot");
    }
    if (path === "/events") return ok(listEvents(params));
    if (seg[0] === "events" && seg[1] && seg[1] !== "facets") {
      const d = s.event_details[seg[1]];
      if (!d) return fail(404, "event not in the demo snapshot (the demo ships events that belong to an investigation)");
      if (seg[2] === "verify") return ok({ event_id: d.id, ok: true, issues: [], content_hash: d.content_hash, demo_note: "verified when the snapshot was built" });
      return ok(d);
    }
    if (path === "/filters") return ok(state.filters.filter((f) => !params.get("scope") || f.scope === params.get("scope")));
    if (path === "/demo/examples") return ok(s.validator_examples);
    const key = query ? `${path}?${query}` : path;
    if (key in R) return ok(R[key]);
    if (path in R) return ok(R[path]);
    if (path === "/events/facets") return ok(R[`/events/facets?investigation_id=${params.get("investigation_id")}`] ?? R["/events/facets"]);
    if (seg[0] === "pipeline" || seg[0] === "reports") return ok(seg.length > 2 ? null : []);
    return fail(404, "not available in the demo");
  }

  // ---- writes
  if (path === "/auth/login") { state.signedIn = true; return ok(me()); }
  if (path === "/auth/logout") { state.signedIn = false; return ok({ ok: true }); }
  if (seg[0] === "investigations" && seg[1]) {
    const id = seg[1];
    if (method === "PATCH" && seg.length === 2) return updateCase(id, body);
    if (seg[2] === "assign-to-me") return updateCase(id, { expected_version: Number(params.get("expected_version")), assignee_id: me().user.id });
    if (seg[2] === "comments") {
      const list = state.comments.get(id) ?? [];
      if (method === "POST") {
        const c = { id: `cmt_demo${state.seq++}`, kind: body.kind, author_id: me().user.id, author_name: me().user.display_name, body: body.body, created_at: now(), edited_at: null, deleted: false };
        list.push(c); state.comments.set(id, list); addActivity(id, `${body.kind}.added`, { comment_id: c.id }, body.body); return ok(c);
      }
      const c = list.find((x) => x.id === seg[3]);
      if (!c) return fail(404, "comment not found");
      if (c.author_id !== me().user.id) return fail(403, "you can only change your own comments");
      if (method === "PATCH") { c.body = body.body; c.edited_at = now(); addActivity(id, `${c.kind}.edited`, { comment_id: c.id }, c.body); return ok(c); }
      if (method === "DELETE") { c.deleted = true; c.body = null; addActivity(id, `${c.kind}.deleted`, { comment_id: c.id }); return ok({ ok: true }); }
    }
    if (seg[2] === "evidence") {
      const list = state.pins.get(id) ?? [];
      if (method === "POST") {
        const e = s.event_details[body.event_id];
        if (!e) return fail(404, "event not found");
        if (list.some((p) => p.event_id === e.id)) return fail(409, "event is already pinned to this case");
        list.push({ event_id: e.id, note: body.note ?? null, added_by: me().user.display_name, created_at: now(), event_type: e.event_type, timestamp: e.timestamp, host: e.host, username: e.username, content_hash: e.content_hash });
        state.pins.set(id, list); addActivity(id, "evidence.pinned", { event_id: e.id, note: body.note ?? null }); return ok({ ok: true });
      }
      if (method === "DELETE") { state.pins.set(id, list.filter((p) => p.event_id !== seg[3])); addActivity(id, "evidence.unpinned", { event_id: seg[3] }); return ok({ ok: true }); }
    }
    if (seg[2] === "analyses") return fail(501, "Analyses in the demo were generated in advance by the real backend (see the AI analysis tab). Generating new ones needs the Python backend and, optionally, a local LLM.");
  }
  if (seg[0] === "analyses" && seg[2] === "claims") return reviewClaim(seg[1], seg[3], body);
  if (seg[0] === "analyses" && seg[2] === "review") return reviewAnalysis(seg[1], body);
  if (path === "/integrity/validate") {
    const norm = (t: string) => { try { return JSON.stringify(JSON.parse(t)); } catch { return t.trim(); } };
    const hit = s.validator_examples.find((x) => norm(x.output) === norm(body.output));
    return hit ? ok(hit.result) : fail(501, "The validator runs in the Python backend. In the demo, load one of the prepared examples (their results were produced by the real engine), or run TraceLayer locally to validate any text.");
  }
  if (path === "/filters" && method === "POST") { const f = { id: `flt_demo${state.seq++}`, ...body, created_at: now() }; state.filters.push(f); return ok(f); }
  if (seg[0] === "filters" && method === "DELETE") { state.filters = state.filters.filter((f) => f.id !== seg[1]); return ok({ ok: true }); }
  return fail(403, DEMO_ONLY);
};
