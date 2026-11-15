// Telemetry normalisation coverage: what became typed, queryable, detectable data, and what did not, and why.
// Raw-only events are never hidden: they are counted, attributed to their source type, and explained.
import { useQuery } from "@tanstack/react-query";
import { Layers } from "lucide-react";
import { api } from "../lib/api";
import type { Coverage, CoverageStatus } from "../lib/types-v2";
import { Card, EmptyState, ErrorState, Pill, Spinner, Stat } from "./ui";

const META: Record<CoverageStatus, { label: string; color: string; help: string }> = {
  full: { label: "Fully normalised", color: "#34d399", help: "Typed, with every field the source event provides" },
  partial: { label: "Partially normalised", color: "#fbbf24", help: "Typed, but some expected fields were missing in the source" },
  raw_only: { label: "Raw only", color: "#94a3b8", help: "No typed mapping; the raw record is stored and searchable" },
  typed_unassessed: { label: "Typed (pre-v3 parser)", color: "#60a5fa", help: "Typed by an older parser that did not record completeness" },
};
const ORDER: CoverageStatus[] = ["full", "partial", "typed_unassessed", "raw_only"];

function Bar({ row }: { row: Record<CoverageStatus, number> & { total: number } }) {
  return (
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-ink-700" role="img"
      aria-label={ORDER.map((s) => `${META[s].label} ${row[s]}`).join(", ")}>
      {ORDER.map((s) => row[s] ? <div key={s} style={{ width: `${(100 * row[s]) / row.total}%`, background: META[s].color }} title={`${META[s].label}: ${row[s].toLocaleString()}`} /> : null)}
    </div>
  );
}

export function CoveragePanel() {
  const q = useQuery({ queryKey: ["coverage"], queryFn: api.coverage });
  if (q.isLoading) return <Spinner label="Measuring coverage" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const c: Coverage = q.data!;
  if (!c.total_events) return <EmptyState title="No telemetry yet" icon={<Layers className="h-5 w-5" />}>Import a dataset or ingest data to measure coverage.</EmptyState>;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Events stored" value={c.total_events.toLocaleString()} hint={`${c.rejected_records.toLocaleString()} records rejected at parse`} />
        {(["full", "partial", "raw_only", "typed_unassessed"] as CoverageStatus[]).map((s) => (
          <Stat key={s} label={META[s].label} value={`${c.percent[s] ?? 0}%`} hint={`${c.statuses[s].toLocaleString()} events · ${META[s].help}`} accent={META[s].color} />
        ))}
      </div>
      <Card pad={false} title="Coverage by source" subtitle="Each source is normalised by a versioned parser. Older parsers did not record completeness, so their typed events are shown separately rather than counted as full.">
        <ul className="divide-y divide-ink-700">
          {c.by_source.map((r) => (
            <li key={r.source + r.parser} className="grid gap-2 px-4 py-3 text-[13px] md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] md:items-center">
              <div className="min-w-0"><div className="truncate font-mono text-[12px]">{r.source}</div><div className="text-[11.5px] text-fg-faint">parser {r.parser}</div></div>
              <Bar row={r} />
              <div className="text-right text-[12px] tabular-nums text-fg-muted">{r.total.toLocaleString()} events{r.rejected ? ` · ${r.rejected} rejected` : ""}</div>
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap gap-3 border-t border-ink-700 px-4 py-2.5 text-[11.5px] text-fg-muted">
          {ORDER.map((s) => <span key={s} className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: META[s].color }} />{META[s].label}</span>)}
        </div>
      </Card>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card pad={false} title="Unsupported source types" subtitle="Raw-only events, by channel and event id">
          {!c.unsupported_source_types.length ? <EmptyState title="Every source type is mapped" /> : (
            <ul className="divide-y divide-ink-700 text-[12.5px]">{c.unsupported_source_types.map((u) => <li key={u.source_type} className="flex justify-between gap-3 px-4 py-2"><span className="font-mono text-fg-muted">{u.source_type}</span><span className="tabular-nums">{u.count.toLocaleString()}</span></li>)}</ul>
          )}
        </Card>
        <Card pad={false} title="Fields lost during normalisation" subtitle="Expected fields absent in partially normalised events">
          {!c.fields_missing.length ? <EmptyState title="No missing fields recorded" /> : (
            <ul className="divide-y divide-ink-700 text-[12.5px]">{c.fields_missing.map((m) => <li key={m.field} className="flex justify-between gap-3 px-4 py-2"><span className="font-mono text-fg-muted">{m.field}</span><span className="tabular-nums">{m.count.toLocaleString()}</span></li>)}</ul>
          )}
        </Card>
        <Card pad={false} title="Why events were not fully normalised">
          {!c.reasons.length ? <EmptyState title="No reasons recorded" /> : (
            <ul className="divide-y divide-ink-700 text-[12.5px]">{c.reasons.map((r) => <li key={r.reason} className="flex justify-between gap-3 px-4 py-2"><span className="text-fg-muted">{r.reason}</span><span className="tabular-nums">{r.count.toLocaleString()}</span></li>)}</ul>
          )}
        </Card>
      </div>
      <Card title="Event types" subtitle="Normalised event classes across all sources">
        <div className="flex flex-wrap gap-1.5">{Object.entries(c.event_types).map(([t, n]) => <Pill key={t} mono>{t} · {n.toLocaleString()}</Pill>)}</div>
      </Card>
    </div>
  );
}
