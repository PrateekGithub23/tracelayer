// Performance dashboard. Only measured data: pipeline runs, per-batch ingest timings,
// live API latency percentiles, and benchmark reports produced by the benchmark runner.

import { useMutation, useQuery } from "@tanstack/react-query";
import { Gauge, Play, Timer } from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, Card, EmptyState, ErrorState, PageHeader, Select, Spinner, Stat } from "../components/ui";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { fmtMs, fmtNum, fmtRelative } from "../lib/format";
import { useRun } from "../lib/useRun";

const tip = { background: "#0a0e14", border: "1px solid #243041", borderRadius: 8, fontSize: 12 };

export default function Performance() {
  const q = useQuery({ queryKey: ["performance"], queryFn: api.performance, refetchInterval: 10_000 });
  const [size, setSize] = useState("20000");
  const { run, start, active } = useRun([["performance"]]);
  const { can } = useAuth();
  const launch = useMutation({ mutationFn: () => api.runBenchmark(Number(size)), onSuccess: (r) => start(r.id) });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const p = q.data!;
  const bench = p.latest_benchmark;
  const runs = [...p.pipeline_runs].reverse().filter((r: any) => r.total_ms != null);
  const batches = [...p.ingest_batches].reverse();
  return (
    <>
      <PageHeader title="Performance" subtitle="Measured on this machine. Nothing on this page is estimated or hard-coded." />
      <Card title="Benchmark" subtitle="Generates the scenario at the chosen scale into an isolated temporary database and times every stage of the real pipeline."
        actions={<div className="flex items-end gap-2">
          <Select label="" value={size} onChange={setSize} className="w-40" options={[
            { value: "5000", label: "5k background" }, { value: "20000", label: "20k background" }, { value: "50000", label: "50k background" }, { value: "100000", label: "100k background" }]} />
          <Button variant="primary" disabled={active || launch.isPending || !can("benchmark:run")} title={can("benchmark:run") ? undefined : "Administrators only"} onClick={() => launch.mutate()}><Play className="h-4 w-4" />{active ? `Running (${run?.status})…` : "Run benchmark"}</Button>
        </div>}>
        {run?.status === "failed" && <ErrorState error={new Error(run.error ?? "benchmark failed")} />}
        {!bench ? <EmptyState title="No benchmark yet" icon={<Gauge className="h-5 w-5" />}>Run one here, or from the CLI: <code className="font-mono">tracelayer bench --events 100000</code></EmptyState> : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
              <Stat label="Total events" value={fmtNum(bench.summary.total_events)} />
              <Stat label="Ingest" value={fmtNum(bench.summary.ingest_records_per_sec)} hint="records / s" />
              <Stat label="Dedup replay" value={fmtNum(bench.summary.dedup_records_per_sec)} hint="records / s" />
              <Stat label="Detection" value={fmtNum(bench.summary.detection_events_per_sec)} hint={`events / s · ${fmtMs(bench.summary.detection_ms)}`} />
              <Stat label="Correlation" value={fmtMs(bench.summary.correlation_ms)} />
              <Stat label="Validation" value={fmtMs(bench.summary.validation_ms_per_claim)} hint="per claim (max)" />
              <Stat label="Ledger verify" value={fmtNum(bench.summary.ledger_verify_events_per_sec)} hint="events / s" />
              <Stat label="Rule recall" value={`${Math.round(bench.summary.rule_recall * 100)}%`} hint={`${bench.summary.false_positive_detections} false positives`} />
            </div>
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-ink-700 p-3">
                <div className="mb-2 text-xs font-medium text-fg-muted">Query latency (p50 / p95)</div>
                <table className="w-full text-[12.5px]"><tbody>
                  {Object.entries(bench.queries as Record<string, { p50_ms: number; p95_ms: number }>).map(([k, v]) => (
                    <tr key={k} className="border-t border-ink-700/70"><td className="py-1.5 text-fg-muted">{k.replace(/_/g, " ")}</td><td className="text-right tabular-nums">{fmtMs(v.p50_ms)}</td><td className="text-right tabular-nums text-fg-faint">{fmtMs(v.p95_ms)}</td></tr>
                  ))}
                </tbody></table>
              </div>
              <div className="rounded-lg border border-ink-700 p-3 text-[12.5px]">
                <div className="mb-2 text-xs font-medium text-fg-muted">Environment</div>
                {Object.entries(bench.environment as Record<string, string>).map(([k, v]) => <div key={k} className="flex justify-between border-t border-ink-700/70 py-1.5"><span className="text-fg-faint">{k}</span><span className="truncate pl-4 font-mono text-[11.5px]">{String(v)}</span></div>)}
                <div className="pt-2 text-[11px] text-fg-faint">Recorded {fmtRelative(bench.created_at)}</div>
              </div>
            </div>
          </div>
        )}
      </Card>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card title="Detection + correlation runs" subtitle="Wall time per pipeline run (ms)">
          {!runs.length ? <EmptyState title="No pipeline runs yet" /> : (
            <div className="h-56"><ResponsiveContainer>
              <BarChart data={runs.map((r: any) => ({ id: r.id.slice(4, 10), load: r.timings?.load, rules: r.timings?.rules, persist: r.timings?.persist, correlate: r.correlation_ms }))}>
                <CartesianGrid stroke="#1a2331" vertical={false} /><XAxis dataKey="id" stroke="#5f6d80" fontSize={10} /><YAxis stroke="#5f6d80" fontSize={11} />
                <Tooltip contentStyle={tip} cursor={{ fill: "#111823" }} />
                <Bar isAnimationActive={false} dataKey="load" stackId="a" fill="#64748b" /><Bar isAnimationActive={false} dataKey="rules" stackId="a" fill="#38bdf8" />
                <Bar isAnimationActive={false} dataKey="persist" stackId="a" fill="#a78bfa" /><Bar isAnimationActive={false} dataKey="correlate" stackId="a" fill="#34d399" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer></div>
          )}
        </Card>
        <Card title="Ingest throughput by batch" subtitle="Accepted events per second">
          {!batches.length ? <EmptyState title="No batches yet" /> : (
            <div className="h-56"><ResponsiveContainer>
              <LineChart data={batches}>
                <CartesianGrid stroke="#1a2331" vertical={false} /><XAxis dataKey="seq" stroke="#5f6d80" fontSize={11} /><YAxis stroke="#5f6d80" fontSize={11} />
                <Tooltip contentStyle={tip} formatter={(v: number) => fmtNum(v)} labelFormatter={(s) => `batch #${s}`} />
                <Line isAnimationActive={false} type="linear" dataKey="events_per_sec" stroke="#38bdf8" strokeWidth={2} dot={{ r: 2.5 }} />
              </LineChart>
            </ResponsiveContainer></div>
          )}
        </Card>
        <Card title="API latency" subtitle="Rolling window since server start (last 2,000 requests per route)" pad={false}>
          {!p.api_latency.length ? <EmptyState title="No requests recorded yet" /> : (
            <div className="overflow-x-auto"><table className="w-full min-w-[520px] text-[12.5px]">
              <thead className="text-[11px] uppercase tracking-wider text-fg-faint"><tr className="border-b border-ink-700"><th className="px-4 py-2 text-left font-medium">Route</th><th className="px-2 text-right font-medium">n</th><th className="px-2 text-right font-medium">p50</th><th className="px-2 text-right font-medium">p95</th><th className="px-4 text-right font-medium">p99</th></tr></thead>
              <tbody className="divide-y divide-ink-700/70">{p.api_latency.slice(0, 14).map((r: any) => (
                <tr key={r.route}><td className="px-4 py-1.5 font-mono text-[11.5px]">{r.route}</td><td className="px-2 text-right tabular-nums text-fg-muted">{r.count}</td><td className="px-2 text-right tabular-nums">{fmtMs(r.p50_ms)}</td><td className="px-2 text-right tabular-nums">{fmtMs(r.p95_ms)}</td><td className="px-4 text-right tabular-nums text-fg-faint">{fmtMs(r.p99_ms)}</td></tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <Card title="Analysis latency by engine" pad={false}>
          {!p.analysis_latency.length ? <EmptyState title="No analyses yet" icon={<Timer className="h-5 w-5" />} /> : (
            <ul className="divide-y divide-ink-700">{p.analysis_latency.map((a: any) => (
              <li key={a.engine} className="flex items-center justify-between px-4 py-3 text-[13px]"><span>{a.engine}</span><span className="text-fg-muted">{a.count} runs · avg <span className="text-fg">{fmtMs(a.avg_ms)}</span> · max {fmtMs(a.max_ms)}</span></li>
            ))}</ul>
          )}
        </Card>
      </div>
    </>
  );
}
