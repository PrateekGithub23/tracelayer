// Investigation queue: work views (mine / needs my review / unassigned / recent), filters,
// private saved filters, and priority + ownership at a glance.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bookmark, CheckCircle2, Search, Siren, Trash2, UserPlus } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { useToast } from "../components/Toast";
import { Button, Card, EmptyState, ErrorState, PageHeader, Pill, Select, SeverityBadge, Spinner, Tabs } from "../components/ui";
import { api, ApiError, type InvestigationQuery } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PRIORITY_META, STATUS_META } from "../lib/cases";
import { fmtRelative, fmtTime, SEVERITY_STYLE, TACTIC_LABEL } from "../lib/format";
import type { InvestigationListItem } from "../lib/types";

type View = NonNullable<InvestigationQuery["view"]>;
const FILTER_KEYS = ["status", "severity", "priority", "q", "sort"] as const;

export function StatusBadge({ status }: { status: string }) {
  const m = STATUS_META[status] ?? { label: status, tone: "bg-ink-700 text-fg-muted ring-ink-600", help: "" };
  return <span title={m.help} className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold ring-1 ${m.tone}`}>{m.label}</span>;
}

export default function Investigations() {
  const [params, setParams] = useSearchParams();
  const view = (params.get("view") as View) || "open";
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""])) as Record<(typeof FILTER_KEYS)[number], string>;
  const set = (k: string, v: string) => setParams((p) => { if (v) p.set(k, v); else p.delete(k); return p; }, { replace: true });
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const queues = useQuery({ queryKey: ["queues"], queryFn: api.queues });
  const list = useQuery({
    queryKey: ["investigations", view, filters],
    queryFn: () => api.investigations({ view, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) } as InvestigationQuery),
  });
  const saved = useQuery({ queryKey: ["filters", "investigations"], queryFn: () => api.filters("investigations") });
  const saveFilter = useMutation({
    mutationFn: (name: string) => api.saveFilter(name, "investigations", { view, ...filters }),
    onSuccess: () => { toast("success", "Filter saved"); qc.invalidateQueries({ queryKey: ["filters"] }); },
    onError: (e) => toast("error", (e as Error).message),
  });
  const delFilter = useMutation({ mutationFn: api.deleteFilter, onSuccess: () => qc.invalidateQueries({ queryKey: ["filters"] }) });
  const take = useMutation({
    mutationFn: (i: InvestigationListItem) => api.assignToMe(i.id, i.version),
    onSuccess: () => { toast("success", "Assigned to you"); qc.invalidateQueries({ queryKey: ["investigations"] }); qc.invalidateQueries({ queryKey: ["queues"] }); },
    onError: (e) => toast("error", e instanceof ApiError && e.status === 409 ? "Someone changed this case a moment ago; the list was refreshed." : (e as Error).message),
    onSettled: () => qc.invalidateQueries({ queryKey: ["investigations"] }),
  });
  const active = Object.values(filters).some(Boolean);

  return (
    <>
      <PageHeader title="Investigations" subtitle="Correlated detections become cases. Take one, work it, and send it for review." />
      <Tabs<View> value={view} onChange={(v) => set("view", v)} tabs={[
        { id: "open", label: "All open", count: queues.data?.open },
        { id: "mine", label: "My investigations", count: queues.data?.mine },
        { id: "needs_review", label: "Needs my review", count: queues.data?.needs_review },
        { id: "unassigned", label: "Unassigned", count: queues.data?.unassigned },
        { id: "recent", label: "Recently updated" },
        { id: "all", label: "Everything" },
      ]} />
      <Card pad={false} className="mt-4">
        <div className="flex flex-wrap items-end gap-3 border-b border-ink-700 p-4">
          <label className="relative min-w-[220px] flex-1">
            <span className="sr-only">Search titles</span>
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-fg-faint" />
            <input value={filters.q} onChange={(e) => set("q", e.target.value)} placeholder="Search titles"
              className="h-9 w-full rounded-lg border border-ink-600 bg-ink-800 pl-9 pr-3 text-[13px] focus:border-sky-500 focus:outline-none" />
          </label>
          <Select label="Status" value={filters.status} onChange={(v) => set("status", v)} className="w-40"
            options={[{ value: "", label: "Any" }, ...Object.entries(STATUS_META).map(([value, m]) => ({ value, label: m.label }))]} />
          <Select label="Priority" value={filters.priority} onChange={(v) => set("priority", v)} className="w-32"
            options={[{ value: "", label: "Any" }, ...["P1", "P2", "P3", "P4"].map((p) => ({ value: p, label: p }))]} />
          <Select label="Severity" value={filters.severity} onChange={(v) => set("severity", v)} className="w-32" options={[
            { value: "", label: "Any" }, { value: "critical", label: "Critical" }, { value: "high", label: "High" },
            { value: "medium", label: "Medium" }, { value: "low", label: "Low" }]} />
          <Select label="Sort" value={filters.sort || "score"} onChange={(v) => set("sort", v === "score" ? "" : v)} className="w-36" options={[
            { value: "score", label: "Risk score" }, { value: "priority", label: "Priority" }, { value: "updated", label: "Last updated" }, { value: "created", label: "Newest" }]} />
          <Button size="sm" variant="ghost" disabled={!active && view === "open"} title="Save the current view and filters"
            onClick={() => { const n = window.prompt("Name this filter"); if (n?.trim()) saveFilter.mutate(n.trim()); }}>
            <Bookmark className="h-3.5 w-3.5" />Save
          </Button>
        </div>
        {!!saved.data?.length && (
          <div className="flex flex-wrap items-center gap-2 border-b border-ink-700 px-4 py-2.5 text-[12px]">
            <span className="text-fg-faint">Saved:</span>
            {saved.data.map((f) => (
              <span key={f.id} className="inline-flex items-center gap-1 rounded-md bg-ink-700/70 ring-1 ring-ink-600">
                <button className="px-2 py-1 hover:text-sky-200" onClick={() => setParams(new URLSearchParams(Object.entries(f.params).filter(([, v]) => v).map(([k, v]) => [k, String(v)])), { replace: true })}>{f.name}</button>
                <button aria-label={`Delete filter ${f.name}`} className="pr-1.5 text-fg-faint hover:text-rose-300" onClick={() => delFilter.mutate(f.id)}><Trash2 className="h-3 w-3" /></button>
              </span>
            ))}
          </div>
        )}
        {list.isLoading ? <Spinner /> : list.error ? <div className="p-4"><ErrorState error={list.error} onRetry={() => list.refetch()} /></div> :
          !list.data?.length ? (
            <EmptyState title={view === "mine" ? "Nothing assigned to you" : view === "needs_review" ? "Nothing waiting for your review" : "No investigations match"} icon={<Siren className="h-5 w-5" />}>
              {view === "mine" ? "Pick a case from Unassigned and choose “Assign to me”." : "Ingest data and run the detection pipeline, or relax the filters."}
            </EmptyState>
          ) : (
            <ul className="divide-y divide-ink-700">
              {list.data.map((i) => (
                <li key={i.id} className="grid gap-3 px-4 py-4 hover:bg-ink-800/40 md:grid-cols-[64px_1fr_auto]">
                  <Link to={`/investigations/${i.id}`} aria-label={`Open ${i.title}`} className="flex h-14 w-14 flex-col items-center justify-center rounded-xl ring-1" style={{ background: `${SEVERITY_STYLE[i.severity].hex}14`, boxShadow: `inset 0 0 0 1px ${SEVERITY_STYLE[i.severity].hex}55` }}>
                    <span className="text-lg font-semibold tabular-nums" style={{ color: SEVERITY_STYLE[i.severity].hex }}>{Math.round(i.score)}</span>
                    <span className="text-[9px] uppercase tracking-wider text-fg-faint">score</span>
                  </Link>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[11px] font-bold ${PRIORITY_META[i.priority]?.tone}`}>{i.priority}</span>
                      <SeverityBadge severity={i.severity} />
                      <StatusBadge status={i.status} />
                      <Link to={`/investigations/${i.id}`} className="truncate text-[14px] font-medium hover:text-sky-200">{i.title}</Link>
                      {i.approved_analysis_id && <span className="inline-flex items-center gap-1 text-[11px] text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" />analysis approved</span>}
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">{i.tactics.map((t) => <Pill key={t}>{TACTIC_LABEL(t)}</Pill>)}</div>
                    <div className="mt-1.5 flex flex-wrap gap-x-3 text-[11.5px] text-fg-faint">
                      <span>{i.detection_count} detections</span><span>{i.event_count} events</span>
                      <span>{fmtTime(i.first_seen)} → {fmtTime(i.last_seen, false)} UTC</span>
                      <span className="font-mono">{i.entities.slice(0, 4).map((e) => e.value).join(" · ")}</span>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1.5 text-right text-xs text-fg-muted">
                    <div>{i.assignee_name ? <>owner <b className="text-fg">{i.assignee_name}</b></> : <span className="text-fg-faint">unassigned{i.legacy_assignee ? ` (v1: ${i.legacy_assignee})` : ""}</span>}</div>
                    {i.reviewer_name && <div className="text-fg-faint">reviewer {i.reviewer_name}</div>}
                    <div className="text-fg-faint">updated {fmtRelative(i.updated_at)}</div>
                    {!i.assignee_id && can("investigations:write") && ["new", "triaged", "investigating"].includes(i.status) && (
                      <Button size="sm" onClick={() => take.mutate(i)}><UserPlus className="h-3.5 w-3.5" />Assign to me</Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
      </Card>
    </>
  );
}
