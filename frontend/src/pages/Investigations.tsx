// Investigation queue: filter by status/severity, search titles, triage by score.

import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Search, Siren } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, EmptyState, ErrorState, PageHeader, Pill, Select, SeverityBadge, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { fmtRelative, fmtTime, SEVERITY_STYLE, TACTIC_LABEL } from "../lib/format";

export default function Investigations() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const list = useQuery({ queryKey: ["investigations", status, severity, q], queryFn: () => api.investigations({ status, severity, q }) });
  return (
    <>
      <PageHeader title="Investigations" subtitle="Correlated detections grouped by shared entities and time. Ordered by risk score." />
      <Card pad={false}>
        <div className="flex flex-wrap items-end gap-3 border-b border-ink-700 p-4">
          <label className="relative min-w-[220px] flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-fg-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search titles"
              className="h-9 w-full rounded-lg border border-ink-600 bg-ink-800 pl-9 pr-3 text-[13px] focus:border-sky-500 focus:outline-none" />
          </label>
          <Select label="Status" value={status} onChange={setStatus} className="w-40" options={[
            { value: "", label: "Any" }, { value: "open", label: "Open" }, { value: "in_review", label: "In review" },
            { value: "closed", label: "Closed" }, { value: "false_positive", label: "False positive" }]} />
          <Select label="Severity" value={severity} onChange={setSeverity} className="w-36" options={[
            { value: "", label: "Any" }, { value: "critical", label: "Critical" }, { value: "high", label: "High" },
            { value: "medium", label: "Medium" }, { value: "low", label: "Low" }]} />
        </div>
        {list.isLoading ? <Spinner /> : list.error ? <div className="p-4"><ErrorState error={list.error} onRetry={() => list.refetch()} /></div> :
          !list.data?.length ? (
            <EmptyState title="No investigations match" icon={<Siren className="h-5 w-5" />}>Ingest data and run the detection pipeline, or relax the filters.</EmptyState>
          ) : (
            <ul className="divide-y divide-ink-700">
              {list.data.map((i) => (
                <li key={i.id}>
                  <Link to={`/investigations/${i.id}`} className="grid gap-3 px-4 py-4 hover:bg-ink-800/50 md:grid-cols-[64px_1fr_auto]">
                    <div className="flex h-14 w-14 flex-col items-center justify-center rounded-xl ring-1" style={{ background: `${SEVERITY_STYLE[i.severity].hex}14`, boxShadow: `inset 0 0 0 1px ${SEVERITY_STYLE[i.severity].hex}55` }}>
                      <span className="text-lg font-semibold tabular-nums" style={{ color: SEVERITY_STYLE[i.severity].hex }}>{Math.round(i.score)}</span>
                      <span className="text-[9px] uppercase tracking-wider text-fg-faint">score</span>
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={i.severity} />
                        <span className="truncate text-[14px] font-medium">{i.title}</span>
                        {i.approved_analysis_id && <span className="inline-flex items-center gap-1 text-[11px] text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" />analysis approved</span>}
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {i.tactics.map((t) => <Pill key={t}>{TACTIC_LABEL(t)}</Pill>)}
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-x-3 text-[11.5px] text-fg-faint">
                        <span>{i.detection_count} detections</span><span>{i.event_count} events</span>
                        <span>{fmtTime(i.first_seen)} → {fmtTime(i.last_seen, false)} UTC</span>
                        <span className="font-mono">{i.entities.slice(0, 4).map((e) => e.value).join(" · ")}</span>
                      </div>
                    </div>
                    <div className="text-right text-xs text-fg-muted">
                      <div className="capitalize">{i.status.replace("_", " ")}</div>
                      <div className="text-fg-faint">{i.assignee ?? "unassigned"}</div>
                      <div className="text-fg-faint">updated {fmtRelative(i.updated_at)}</div>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
      </Card>
    </>
  );
}
