// Investigation workspace: header (score, entities, status), kill-chain strip, and tabs for
// AI analysis, timeline, entity graph, evidence table, detections, coverage gaps and audit trail.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, EyeOff, ListChecks } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { AnalysisPanel } from "../components/AnalysisPanel";
import { ActivityFeed, CaseControls, CommentsPanel, PinsPanel } from "../components/CasePanel";
import { EvidenceGraph } from "../components/EvidenceGraph";
import { useInspector } from "../components/EvidenceInspector";
import { EventTable } from "../components/EventTable";
import { Timeline } from "../components/Timeline";
import { useToast } from "../components/Toast";
import { Button, Card, ErrorState, Pill, Select, SeverityBadge, Spinner, Tabs } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PRIORITY_META } from "../lib/cases";
import { fmtTime, SEVERITY_STYLE, TACTIC_LABEL } from "../lib/format";

type Tab = "analysis" | "timeline" | "graph" | "evidence" | "detections" | "collaborate" | "activity";
const KILL_CHAIN = ["credential-access", "initial-access", "discovery", "execution", "privilege-escalation", "defense-evasion", "lateral-movement", "exfiltration"];

export default function InvestigationDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const { openEvents } = useInspector();
  // The active tab lives in the URL (?tab=graph) so views are shareable and survive reloads.
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) || "analysis";
  const setTab = (t: Tab) => setParams((p) => { p.set("tab", t); return p; }, { replace: true });
  const [role, setRole] = useState("evidence");
  const { can } = useAuth();
  const toast = useToast();
  const inv = useQuery({ queryKey: ["investigation", id], queryFn: () => api.investigation(id) });
  const timeline = useQuery({ queryKey: ["timeline", id], queryFn: () => api.timeline(id) });
  const graph = useQuery({ queryKey: ["graph", id], queryFn: () => api.graph(id), enabled: tab === "graph" });
  // Short refs (E1..En) shared with the validator, so citations in claims and tables read the same.
  const refByEvent = useMemo(() => new Map((timeline.data?.events ?? []).map((e) => [e.id, e.ref])), [timeline.data]);

  if (inv.isLoading) return <Spinner label="Loading investigation" />;
  if (inv.error) return <ErrorState error={inv.error} onRetry={() => inv.refetch()} />;
  const i = inv.data!;
  const sev = SEVERITY_STYLE[i.severity];
  const download = async (fmt: string) => {
    try { await api.download(id, fmt); qc.invalidateQueries({ queryKey: ["activity", id] }); } catch (e) { toast("error", (e as Error).message); }
  };

  return (
    <div className="space-y-5">
      <Link to="/investigations" className="inline-flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg"><ArrowLeft className="h-3.5 w-3.5" /> Investigations</Link>
      <section className="relative overflow-hidden rounded-2xl border border-ink-700 bg-ink-850/80 p-5 shadow-panel">
        <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full blur-3xl" style={{ background: `${sev.hex}22` }} />
        <div className="relative flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`text-[12px] font-bold ${PRIORITY_META[i.priority]?.tone}`}>{PRIORITY_META[i.priority]?.label}</span>
              <SeverityBadge severity={i.severity} />
              <Pill mono>{i.id}</Pill>
              {i.approved_analysis_id && <Pill className="text-emerald-300">analysis approved</Pill>}
            </div>
            <h1 className="mt-2 text-xl font-semibold tracking-tight">{i.title}</h1>
            <p className="mt-1 text-[13px] text-fg-muted">
              {fmtTime(i.first_seen)} → {fmtTime(i.last_seen)} UTC · {i.detections.length} detections · {i.event_counts.evidence} evidence + {i.event_counts.context} context events
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {i.entities.slice(0, 12).map((e) => (
                <span key={`${e.type}:${e.value}`} className="inline-flex items-center gap-1 rounded-md bg-ink-700/60 px-2 py-0.5 font-mono text-[11.5px] ring-1 ring-ink-600">
                  <span className="text-fg-faint">{e.type}</span>{e.value}
                </span>
              ))}
            </div>
          </div>
          <div className="flex shrink-0 flex-col gap-3 xl:items-end">
            <div className="xl:text-right">
              <div className="text-4xl font-semibold tabular-nums" style={{ color: sev.hex }}>{Math.round(i.score)}</div>
              <div className="text-[11px] text-fg-faint" title={String(i.score_breakdown.formula ?? "")}>
                risk score · base {String(i.score_breakdown.max_severity_weight)} + stages {String(i.score_breakdown.kill_chain_stage_bonus)} + volume {String(i.score_breakdown.volume_bonus)}
              </div>
            </div>
            {can("export:create") && <div className="flex flex-wrap items-end gap-2 xl:justify-end">
              <Button onClick={() => download("zip")} title="ZIP: JSON + events + CSV + report + SHA-256 manifest"><Download className="h-4 w-4" /> Evidence bundle</Button>
              <Button variant="ghost" onClick={() => download("md")}>Report .md</Button>
              <Button variant="ghost" onClick={() => download("csv")}>CSV</Button>
            </div>}
          </div>
        </div>
        <div className="relative mt-4"><CaseControls inv={i} /></div>
        <div className="relative mt-5 grid grid-cols-4 gap-1.5 md:grid-cols-8">
          {KILL_CHAIN.map((t) => {
            const hit = i.tactics.includes(t);
            const dets = i.detections.filter((d) => d.tactic === t);
            return (
              <div key={t} title={dets.map((d) => d.rule_name).join("\n") || "not observed"}
                className={`rounded-lg px-2 py-2 text-center text-[10.5px] font-medium ring-1 ${hit ? "bg-sky-500/10 text-sky-200 ring-sky-500/40" : "text-fg-faint ring-ink-700"}`}>
                {TACTIC_LABEL(t)}
                <div className="mt-0.5 text-[10px] tabular-nums opacity-70">{hit ? `${dets.length} det.` : "—"}</div>
              </div>
            );
          })}
        </div>
      </section>

      {i.coverage_gaps.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-amber-400/25 bg-amber-400/5 px-4 py-3 text-[12.5px] text-amber-100">
          <EyeOff className="h-4 w-4" /> <span className="font-medium">Telemetry blind spots:</span>
          {i.coverage_gaps.map((g) => <span key={g.host} className="rounded-md bg-amber-400/10 px-2 py-0.5 font-mono text-[11.5px]">{g.host}: no {g.missing.join(", ")}</span>)}
          <span className="text-amber-100/70">Activity on these hosts after logon cannot be verified.</span>
        </div>
      )}

      <Tabs<Tab> value={tab} onChange={setTab} tabs={[
        { id: "analysis", label: "AI analysis", count: i.analyses.length },
        { id: "timeline", label: "Timeline", count: timeline.data?.events.length },
        { id: "graph", label: "Entity graph" },
        { id: "evidence", label: "Events", count: i.event_counts.evidence + i.event_counts.context },
        { id: "detections", label: "Detections", count: i.detections.length },
        { id: "collaborate", label: "Notes & pinned evidence" },
        { id: "activity", label: "Activity" },
      ]} />

      {tab === "analysis" && <AnalysisPanel investigationId={id} refByEvent={refByEvent} />}
      {tab === "timeline" && (timeline.isLoading ? <Spinner /> : timeline.error ? <ErrorState error={timeline.error} /> : <Timeline data={timeline.data!} />)}
      {tab === "graph" && (graph.isLoading ? <Spinner label="Building graph" /> : graph.error ? <ErrorState error={graph.error} /> : <EvidenceGraph graph={graph.data!} />)}
      {tab === "evidence" && (
        <Card pad={false} title="Events in scope" actions={
          <Select label="" value={role} onChange={setRole} className="w-44" options={[
            { value: "evidence", label: "Detection evidence" }, { value: "context", label: "Correlated context" }, { value: "", label: "All" }]} />}>
          <EventTable query={{ investigation_id: id, role: role || undefined, order: "asc" }} refByEvent={refByEvent} />
        </Card>
      )}
      {tab === "detections" && (
        <div className="space-y-2.5">
          {i.detections.map((d) => (
            <Card key={d.id}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={d.severity} /><span className="font-medium">{d.rule_name}</span><Pill mono>{d.rule_id}</Pill><Pill>{d.technique}</Pill><Pill>{TACTIC_LABEL(d.tactic)}</Pill></div>
                  <p className="mt-2 text-[13px] text-fg-muted">{d.summary}</p>
                  <p className="mt-1 text-[11.5px] text-fg-faint">{fmtTime(d.first_seen)} → {fmtTime(d.last_seen, false)} UTC · confidence {Math.round(d.confidence * 100)}%</p>
                </div>
                <Button size="sm" onClick={async () => {
                  const page = await api.events({ detection_id: d.id, limit: 500, order: "asc" });
                  openEvents(d.rule_name, page.items.map((e) => e.id));
                }}><ListChecks className="h-3.5 w-3.5" /> {d.evidence_count} evidence events</Button>
              </div>
            </Card>
          ))}
        </div>
      )}
      {tab === "collaborate" && <div className="space-y-4"><CommentsPanel invId={id} /><PinsPanel invId={id} /></div>}
      {tab === "activity" && <ActivityFeed invId={id} />}
    </div>
  );
}
