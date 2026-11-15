// Public dataset management: provenance, licensing, import status, field mapping, and measured
// detection results. Everything shown comes from the catalogue or from the stored import record.
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Download, ExternalLink, FlaskConical, Play, Scale, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useToast } from "../components/Toast";
import { Button, Card, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge, Spinner, Stat, Tabs } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useRun } from "../lib/useRun";
import { fmtRelative, fmtTime, shortHash } from "../lib/format";
import type { DatasetInfo } from "../lib/types-v2";

type Tab = "overview" | "results" | "mapping";

export default function Datasets() {
  const q = useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
  const [sel, setSel] = useState<string | null>(null);
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const list = q.data!;
  const current = list.find((d) => d.id === sel) ?? list[0];
  return (
    <>
      <PageHeader title="Datasets" subtitle="Public, licensed security telemetry processed by the same pipeline as any other source. Lab-recorded attack data, not enterprise production logs." />
      <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
        <div className="space-y-2">
          {list.map((d) => (
            <button key={d.id} onClick={() => setSel(d.id)}
              className={`w-full rounded-xl border p-3.5 text-left transition-colors ${current?.id === d.id ? "border-sky-500/50 bg-sky-500/5" : "border-ink-700 bg-ink-850/80 hover:border-ink-600"}`}>
              <div className="flex items-center justify-between gap-2"><span className="text-[13.5px] font-medium">{d.name}</span><Pill>{d.license}</Pill></div>
              <div className="mt-1 font-mono text-[11px] text-fg-faint">{d.id}</div>
              <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
                <Pill className={d.role === "held-out" ? "text-violet-200" : "text-sky-200"}>{d.role}</Pill>
                <Pill className={d.status === "succeeded" ? "text-emerald-300" : d.status === "failed" ? "text-rose-300" : undefined}>{d.status.replace("_", " ")}</Pill>
                {d.event_count != null && <Pill>{d.event_count.toLocaleString()} events</Pill>}
              </div>
            </button>
          ))}
        </div>
        {current ? <DatasetDetail d={current} /> : <EmptyState title="No datasets catalogued" />}
      </div>
    </>
  );
}

function DatasetDetail({ d }: { d: DatasetInfo & Record<string, any> }) {
  const [tab, setTab] = useState<Tab>(d.results ? "results" : "overview");
  const { can } = useAuth();
  const toast = useToast();
  const { run, active, start } = useRun([["datasets"], ["investigations"], ["queues"]]);
  const launch = useMutation({
    mutationFn: () => api.importDataset(d.id),
    onSuccess: (r) => { start(r.id); toast("info", "Import started: verifying hash, ingesting and running detection"); },
    onError: (e) => toast("error", e instanceof ApiError ? e.message : "Import failed"),
  });
  const r = d.results;
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 max-w-3xl">
            <h2 className="text-lg font-semibold">{d.name}</h2>
            <p className="mt-1 text-[13px] text-fg-muted">{d.description}</p>
          </div>
          <div className="flex gap-2">
            {can("datasets:manage") && (
              <Button variant="primary" disabled={active || launch.isPending} onClick={() => launch.mutate()}>
                <Play className="h-4 w-4" />{active ? `Importing (${run?.status})…` : d.status === "succeeded" ? "Re-import" : "Import & evaluate"}
              </Button>
            )}
            {d.status === "succeeded" && d.redistribution.startsWith("MIT") && (
              <a href={`/api/datasets/${d.id}/sample`}><Button><Download className="h-4 w-4" />Sample (200 records)</Button></a>
            )}
          </div>
        </div>
        {run?.status === "failed" && <div className="mt-3"><ErrorState error={new Error(d.error ?? run.error ?? "import failed")} /></div>}
      </Card>
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Provenance & licence" }, { id: "results", label: "Detection results" }, { id: "mapping", label: "Field mapping" }]} />
      {tab === "overview" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title={<span className="flex items-center gap-2"><Scale className="h-4 w-4" />Licence and attribution</span>}>
            <dl className="space-y-2 text-[13px]">
              <div><dt className="text-fg-faint">Licence</dt><dd><a className="inline-flex items-center gap-1 text-sky-300 hover:underline" href={d.license_url} target="_blank" rel="noreferrer noopener">{d.license}<ExternalLink className="h-3 w-3" /></a></dd></div>
              <div><dt className="text-fg-faint">Redistribution</dt><dd>{d.redistribution}</dd></div>
              <div><dt className="text-fg-faint">Attribution</dt><dd className="text-fg-muted">{d.attribution}</dd></div>
              <div><dt className="text-fg-faint">Source</dt><dd className="break-all font-mono text-[11.5px]"><a className="text-sky-300 hover:underline" href={d.source_url} target="_blank" rel="noreferrer noopener">{d.source_url}</a></dd></div>
              <div><dt className="text-fg-faint">Pinned SHA-256</dt><dd className="break-all font-mono text-[11.5px]">{d.expected_sha256}</dd></div>
            </dl>
          </Card>
          <Card title={<span className="flex items-center gap-2"><FlaskConical className="h-4 w-4" />What this data is, and isn't</span>}>
            <dl className="space-y-2 text-[13px]">
              <div><dt className="text-fg-faint">Environment</dt><dd className="text-fg-muted">{d.environment}</dd></div>
              <div><dt className="text-fg-faint">Labels</dt><dd className="text-fg-muted">{d.labels}</dd></div>
              <div><dt className="text-fg-faint">Labelled techniques</dt><dd className="flex gap-1.5">{(d as any).techniques?.map((t: string) => <Pill key={t} mono>{t}</Pill>)}</dd></div>
              <div><dt className="text-fg-faint">Role in evaluation</dt><dd className="text-fg-muted">{d.role === "held-out" ? "Held-out: imported only to measure detection; its events were not inspected while rules were written." : "Development: inspected while building the adapter and the v2 rules, so results here are optimistic."}</dd></div>
              <div><dt className="text-fg-faint">Format</dt><dd>{d.format}</dd></div>
              {d.imported_at && <div><dt className="text-fg-faint">Last import</dt><dd>{fmtTime(d.imported_at)} UTC ({fmtRelative(d.imported_at)}) · {d.processing_ms?.toLocaleString()} ms · archive {shortHash(d.archive_sha256 ?? "", 12)}</dd></div>}
            </dl>
          </Card>
        </div>
      )}
      {tab === "results" && (!r ? <EmptyState title="Not imported yet" icon={<Database className="h-5 w-5" />}>Import the dataset to measure what the detection rules find.</EmptyState> : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Events imported" value={r.events.toLocaleString()} hint={`${d.rejected ?? 0} rejected · ${d.duplicates ?? 0} duplicates`} />
            <Stat label="Technique recall" value={r.technique_recall == null ? "—" : `${Math.round(r.technique_recall * 100)}%`} hint={`${r.techniques_detected.length}/${r.techniques_labelled.length} labelled techniques`} accent={r.technique_recall === 1 ? "#34d399" : "#fbbf24"} />
            <Stat label="Alerts" value={r.alert_count} hint={`${r.alerts_matching_labels} match a labelled technique`} />
            <Stat label="Throughput" value={`${(r.timings_ms?.events_per_sec ?? 0).toLocaleString()}/s`} hint={`detect + correlate ${r.timings_ms?.detect_and_correlate} ms`} />
          </div>
          <div className="rounded-lg border border-amber-400/25 bg-amber-400/5 px-4 py-2.5 text-[12.5px] text-amber-100"><b>Precision / false-positive rate:</b> {r.precision_note}</div>
          <Card pad={false} title="Alerts on this dataset" subtitle="‘Labelled’ means the alert's ATT&CK technique is in the dataset's metadata. Unlabelled alerts are not automatically false positives.">
            {!r.alerts.length ? <EmptyState title="No alerts" /> : (
              <ul className="divide-y divide-ink-700">
                {r.alerts.map((a: any) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]">
                    <SeverityBadge severity={a.severity} /><Pill mono>{a.rule_id}</Pill><Pill mono>{a.technique}</Pill>
                    <span className="min-w-0 flex-1 text-fg-muted">{a.summary}</span>
                    {a.matches_label ? <span className="text-[12px] text-emerald-300">labelled</span> : <span className="text-[12px] text-fg-faint">not in labels</span>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Missed and detected techniques">
              <div className="space-y-2 text-[13px]">
                <div>Detected: {r.techniques_detected.length ? r.techniques_detected.map((t: string) => <Pill key={t} mono className="ml-1 text-emerald-300">{t}</Pill>) : "none"}</div>
                <div>Missed: {r.techniques_missed.length ? r.techniques_missed.map((t: string) => <Pill key={t} mono className="ml-1 text-rose-300">{t}</Pill>) : "none"}</div>
                <div className="pt-2 text-fg-muted">Correlated into {r.correlations.length} investigation(s){r.cross_source_correlations ? `, ${r.cross_source_correlations} mixing this dataset with other sources (check these)` : ", none mixing sources"}.</div>
              </div>
            </Card>
            <Card title="What the schema loses" subtitle={`${Math.round((r.unmapped_share ?? 0) * 100)}% of events have no typed mapping (kept as ‘other’ with the full raw record).`}>
              <ul className="space-y-1 text-[12.5px]">
                {r.top_unmapped.slice(0, 8).map((u: any) => <li key={u.source} className="flex justify-between gap-3"><span className="font-mono text-fg-muted">{u.source}</span><span className="tabular-nums">{u.count.toLocaleString()}</span></li>)}
              </ul>
              <p className="mt-3 text-[12px] text-fg-faint"><ShieldCheck className="mr-1 inline h-3.5 w-3.5" />{r.credential_redactions} command lines had credentials redacted. Local-time offsets seen in EventTime: {Object.entries(r.local_time_offsets).map(([k, v]) => `${k} (${v})`).join(", ") || "none"}.</p>
            </Card>
          </div>
        </div>
      ))}
      {tab === "mapping" && (
        <Card pad={false} title="How source fields map into TraceLayer's schema" subtitle="Every event keeps its unmodified raw record; normalised fields are re-derived and checked during integrity verification.">
          <table className="w-full text-[12.5px]">
            <thead className="text-left text-[11px] uppercase tracking-wider text-fg-faint"><tr><th className="px-4 py-2">Source field</th><th>TraceLayer field</th><th className="px-4">Note</th></tr></thead>
            <tbody className="divide-y divide-ink-700">
              {d.field_mapping.map((m) => <tr key={m.source}><td className="px-4 py-2 font-mono text-[11.5px]">{m.source}</td><td className="font-mono text-[11.5px] text-sky-200">{m.target}</td><td className="px-4 text-fg-muted">{m.note ?? ""}</td></tr>)}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
