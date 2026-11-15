// Overview dashboard. Every number comes from /api/metrics/overview (SQL aggregates over stored rows).

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Fingerprint, ShieldCheck, ShieldX, Siren } from "lucide-react";
import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { VerdictBar } from "../components/AnalysisPanel";
import { Card, EmptyState, ErrorState, PageHeader, SeverityBadge, Spinner, Stat } from "../components/ui";
import { api } from "../lib/api";
import { EVENT_TYPE_COLOR, fmtNum, fmtRelative, fmtTime, SEVERITY_ORDER, SEVERITY_STYLE, shortHash } from "../lib/format";

const tooltipStyle = { background: "#0a0e14", border: "1px solid #243041", borderRadius: 8, fontSize: 12 };

export default function Overview() {
  const q = useQuery({ queryKey: ["overview"], queryFn: api.overview, refetchInterval: 20_000 });
  if (q.isLoading) return <Spinner label="Loading dashboard" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const o = q.data!;
  if (!o.totals.events) {
    return (
      <>
        <PageHeader title="Overview" />
        <Card>
          <EmptyState title="No telemetry ingested yet" icon={<Fingerprint className="h-5 w-5" />}>
            Upload logs or generate the seeded attack scenario from <Link className="text-sky-300 hover:underline" to="/ingest">Ingest &amp; system</Link>.
            Detection, correlation and the integrity engine run on whatever you ingest.
          </EmptyState>
        </Card>
      </>
    );
  }
  const types = Array.from(new Set(o.event_volume.flatMap((b) => Object.keys(b).filter((k) => k !== "bucket"))));
  const openInv = SEVERITY_ORDER.reduce((s, k) => s + (o.open_investigations_by_severity[k] ?? 0), 0);
  const verify = o.ledger.last_verification;
  const totalClaims = Object.values(o.claim_verdicts).reduce((a, b) => a + (b ?? 0), 0);
  const unsafe = (o.claim_verdicts.unsupported_claim ?? 0) + (o.claim_verdicts.contradictory_finding ?? 0);

  return (
    <>
      <PageHeader title="Security overview"
        subtitle={<>Latest telemetry {fmtTime(o.latest_event)} UTC · {fmtNum(o.totals.batches)} ingest batches · ledger head #{o.ledger.seq}</>} />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Events" value={fmtNum(o.totals.events)} hint={`${fmtNum(o.totals.duplicates_rejected)} duplicates dropped`} />
        <Stat label="Detections" value={fmtNum(o.totals.detections)} hint={`${o.detections_by_severity.critical ?? 0} critical · ${o.detections_by_severity.high ?? 0} high`} />
        <Stat label="Open investigations" value={fmtNum(openInv)} accent={openInv ? SEVERITY_STYLE.critical.hex : undefined}
          hint={`${o.investigations_by_status.closed ?? 0} closed`} />
        <Stat label="AI claims validated" value={fmtNum(totalClaims)} hint={`${unsafe} unsafe caught`} />
        <Stat label="Injection attempts" value={fmtNum(o.totals.injection_tagged_events)} accent={o.totals.injection_tagged_events ? "#fbbf24" : undefined} hint="events targeting AI analysts" />
        <Stat label="Evidence ledger" value={verify ? (verify.ok ? "Intact" : "Tampered") : "Unverified"}
          accent={verify ? (verify.ok ? "#34d399" : "#fb7185") : "#93a1b4"} hint={verify ? `checked ${fmtRelative(verify.at)}` : "run verification"} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="Event volume" subtitle="Hourly, by type · last 24h of telemetry" className="xl:col-span-2">
          <div className="h-64">
            <ResponsiveContainer>
              <AreaChart data={o.event_volume} margin={{ left: -12, right: 8, top: 8 }}>
                <CartesianGrid stroke="#1a2331" vertical={false} />
                <XAxis dataKey="bucket" tickFormatter={(v) => String(v).slice(11, 16)} stroke="#5f6d80" fontSize={11} />
                <YAxis stroke="#5f6d80" fontSize={11} />
                <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => `${String(v).replace("T", " ")} UTC`} />
                {types.map((t) => (
                  <Area isAnimationActive={false} key={t} type="monotone" dataKey={t} stackId="1" stroke={EVENT_TYPE_COLOR[t] ?? "#64748b"} fill={EVENT_TYPE_COLOR[t] ?? "#64748b"} fillOpacity={0.25} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Priority investigations" actions={<Link to="/investigations" className="text-xs text-sky-300 hover:underline">All</Link>} pad={false}>
          {o.top_investigations.length === 0 ? <EmptyState title="No investigations">Run the detection pipeline after ingesting data.</EmptyState> : (
            <ul className="divide-y divide-ink-700">
              {o.top_investigations.map((i) => (
                <li key={i.id}>
                  <Link to={`/investigations/${i.id}`} className="group flex items-center gap-3 px-4 py-3 hover:bg-ink-800/60">
                    <Siren className="h-4 w-4 shrink-0" style={{ color: SEVERITY_STYLE[i.severity].hex }} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium">{i.title}</div>
                      <div className="mt-0.5 flex items-center gap-2 text-[11px] text-fg-faint"><SeverityBadge severity={i.severity} /> score {i.score} · {i.status.replace("_", " ")}</div>
                    </div>
                    <ArrowRight className="h-4 w-4 text-fg-faint opacity-0 transition-opacity group-hover:opacity-100" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <Card title="Detections by rule">
          {o.detections_by_rule.length === 0 ? <EmptyState title="No detections yet" /> : (
            <div className="h-64">
              <ResponsiveContainer>
                <BarChart data={o.detections_by_rule} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <XAxis type="number" stroke="#5f6d80" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="rule_id" width={92} stroke="#5f6d80" fontSize={10.5} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v, _n, p) => [v, (p.payload as { rule_name: string }).rule_name]} cursor={{ fill: "#111823" }} />
                  <Bar isAnimationActive={false} dataKey="count" fill="#38bdf8" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
        <Card title="AI claim verdicts" subtitle="Every statement made by any analysis, as classified by the integrity engine">
          {totalClaims === 0 ? <EmptyState title="No analyses yet">Open an investigation and generate an analysis.</EmptyState> : (
            <div className="space-y-4">
              <VerdictBar verdicts={o.claim_verdicts} />
              <div className="grid grid-cols-2 gap-3 text-[13px]">
                <div className="rounded-lg bg-emerald-500/5 p-3 ring-1 ring-emerald-500/20"><ShieldCheck className="mb-1 h-4 w-4 text-emerald-300" />{(o.claim_verdicts.verified_observation ?? 0) + (o.claim_verdicts.heuristic_correlation ?? 0)} evidence-backed</div>
                <div className="rounded-lg bg-rose-500/5 p-3 ring-1 ring-rose-500/20"><ShieldX className="mb-1 h-4 w-4 text-rose-300" />{unsafe} blocked as unsafe</div>
              </div>
              <div className="text-xs text-fg-muted">Analyses: {Object.entries(o.analyses_by_status).map(([k, v]) => `${v} ${k.replace("_", " ")}`).join(" · ") || "none"}</div>
            </div>
          )}
        </Card>
        <Card title="Top failed-login sources" pad={false}>
          {o.top_failed_login_sources.length === 0 ? <EmptyState title="No failed logins" /> : (
            <ul className="divide-y divide-ink-700">
              {o.top_failed_login_sources.map((s) => {
                const max = o.top_failed_login_sources[0].count;
                return (
                  <li key={s.ip}>
                    <Link to={`/events?ip=${encodeURIComponent(s.ip)}&outcome=failure`} className="block px-4 py-2.5 hover:bg-ink-800/60">
                      <div className="flex justify-between font-mono text-[12.5px]"><span>{s.ip}</span><span className="tabular-nums text-fg-muted">{s.count}</span></div>
                      <div className="mt-1.5 h-1 rounded-full bg-ink-700"><div className="h-1 rounded-full bg-orange-400/80" style={{ width: `${(s.count / max) * 100}%` }} /></div>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="border-t border-ink-700 px-4 py-3 font-mono text-[11px] text-fg-faint">chain head {shortHash(o.ledger.chain_head, 20)}</div>
        </Card>
      </div>
    </>
  );
}
