// Ingestion + system page: upload log files, generate the seeded scenario, run the pipeline,
// and see the local LLM status with exact setup commands.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, CheckCircle2, FileUp, Play, Terminal, Wand2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, Card, ErrorState, KV, PageHeader, Select, TextInput } from "../components/ui";
import { api } from "../lib/api";
import { fmtMs, fmtRelative } from "../lib/format";
import { useRun } from "../lib/useRun";

const REFRESH = [["overview"], ["investigations"], ["detections"], ["batches"], ["performance"], ["facets"], ["events"]];

function RunStatus({ run }: { run?: { status: string; stats: any; error: string | null } }) {
  if (!run) return null;
  if (run.status === "failed") return <ErrorState error={new Error(run.error ?? "pipeline failed")} />;
  if (run.status !== "succeeded") return <div className="text-[13px] text-fg-muted">Pipeline {run.status}…</div>;
  const s = run.stats;
  return (
    <div className="flex items-start gap-2 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-[13px] text-emerald-100 ring-1 ring-emerald-500/25">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
      <span>Scanned {s.detection.events_scanned.toLocaleString()} events: {s.detection.created} new detection(s), {s.correlation.investigations_created} new and {s.correlation.investigations_extended} extended investigation(s) in {fmtMs(s.total_ms)}. <Link to="/investigations" className="underline">View investigations</Link></span>
    </div>
  );
}

export default function Ingest() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["status"], queryFn: api.status });
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => api.runs("detect_correlate") });
  const { run, start, active } = useRun([...REFRESH, ["runs"]]);
  const [seed, setSeed] = useState("7");
  const [bg, setBg] = useState("3000");
  const [anchor, setAnchor] = useState("now");
  const synth = useMutation({
    mutationFn: () => api.synthetic({ seed: Number(seed), background_events: Number(bg), anchor, run_pipeline: true }),
    onSuccess: (r) => { REFRESH.forEach((k) => qc.invalidateQueries({ queryKey: k })); if (r.pipeline_run_id) start(r.pipeline_run_id); },
  });
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("upload");
  const [parser, setParser] = useState("native");
  const [year, setYear] = useState(String(new Date().getUTCFullYear()));
  const upload = useMutation({
    mutationFn: () => api.uploadFile(file!, source, parser, parser === "sshd" ? Number(year) : undefined),
    onSuccess: () => REFRESH.forEach((k) => qc.invalidateQueries({ queryKey: k })),
  });
  const pipeline = useMutation({ mutationFn: api.startPipeline, onSuccess: (r) => start(r.id) });
  const llm = status.data?.llm;

  return (
    <>
      <PageHeader title="Ingest & system" subtitle="Bring telemetry in, run detection + correlation, and check the local AI setup." />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Wand2 className="h-4 w-4 text-violet-300" /> Generate attack scenario</span>}
          subtitle="Seeded synthetic telemetry with a 7-stage intrusion, an unrelated SSH brute force, benign noise and duplicates. Runs through the real parsers (native JSON, sshd syslog, Windows Security).">
          <div className="grid gap-3 sm:grid-cols-3">
            <TextInput label="Seed" value={seed} onChange={setSeed} mono />
            <Select label="Background events" value={bg} onChange={setBg} options={["1000", "3000", "10000", "50000"].map((v) => ({ value: v, label: Number(v).toLocaleString() }))} />
            <Select label="Time anchor" value={anchor} onChange={setAnchor} options={[{ value: "now", label: "Ending now" }, { value: "fixed", label: "Fixed (2026-11-03)" }]} />
          </div>
          <div className="mt-4 flex items-center gap-3">
            <Button variant="primary" disabled={synth.isPending || active} onClick={() => synth.mutate()}><Play className="h-4 w-4" />{synth.isPending ? "Ingesting…" : "Generate, ingest & detect"}</Button>
            <span className="text-xs text-fg-faint">"Fixed" + same seed twice demonstrates deduplication.</span>
          </div>
          {synth.error && <div className="mt-3"><ErrorState error={synth.error} /></div>}
          {synth.data && (
            <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
              {Object.entries(synth.data.batches as Record<string, any>).map(([p, b]) => (
                <div key={p} className="rounded-lg bg-ink-800 p-2.5"><div className="font-mono text-fg-faint">{p}</div><div className="mt-1 tabular-nums">{b.accepted.toLocaleString()} accepted</div><div className="text-fg-faint">{b.duplicates} dup · {b.rejected} rejected · {fmtMs(b.duration_ms)}</div></div>
              ))}
            </div>
          )}
          <div className="mt-3"><RunStatus run={run} /></div>
        </Card>

        <Card title={<span className="flex items-center gap-2"><FileUp className="h-4 w-4 text-sky-300" /> Upload log file</span>}
          subtitle="NDJSON or JSON array (native / winsec), or raw auth.log lines (sshd). Max 25 MB per file.">
          <div className="space-y-3">
            <label className="flex cursor-pointer flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-ink-500 bg-ink-900/50 px-4 py-6 text-center text-[13px] text-fg-muted hover:border-sky-500/50">
              <FileUp className="h-5 w-5" />{file ? <span className="text-fg">{file.name} · {(file.size / 1024).toFixed(1)} KB</span> : "Choose a file"}
              <input type="file" className="hidden" accept=".json,.ndjson,.jsonl,.log,.txt" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <div className="grid gap-3 sm:grid-cols-3">
              <TextInput label="Source name" value={source} onChange={setSource} mono />
              <Select label="Format" value={parser} onChange={setParser} options={[{ value: "native", label: "TraceLayer JSON" }, { value: "sshd", label: "sshd auth.log" }, { value: "winsec", label: "Windows Security JSON" }]} />
              {parser === "sshd" && <TextInput label="Log year" value={year} onChange={setYear} mono />}
            </div>
            <div className="flex gap-2">
              <Button variant="primary" disabled={!file || upload.isPending} onClick={() => upload.mutate()}>{upload.isPending ? "Uploading…" : "Ingest file"}</Button>
              <Button disabled={pipeline.isPending || active} onClick={() => pipeline.mutate()}><Play className="h-4 w-4" /> Run detection + correlation</Button>
            </div>
            {upload.error && <ErrorState error={upload.error} />}
            {upload.data && (
              <div className="rounded-lg bg-ink-800 p-3 text-xs">
                Batch #{upload.data.seq}: <span className="text-emerald-300">{upload.data.accepted} accepted</span> · {upload.data.duplicates} duplicates · <span className={upload.data.rejected ? "text-orange-300" : ""}>{upload.data.rejected} rejected</span>
                {upload.data.errors?.slice(0, 5).map((e: any) => <div key={e.index} className="mt-1 font-mono text-fg-faint">record {e.index}: {e.error}</div>)}
              </div>
            )}
            <p className="text-[11.5px] text-fg-faint">Sample files live in <code className="font-mono">samples/</code> in the repository.</p>
          </div>
        </Card>

        <Card title={<span className="flex items-center gap-2"><Bot className="h-4 w-4 text-sky-300" /> Local AI (Ollama)</span>} subtitle="Optional. Free, runs on-device, no API keys. Without it, the deterministic analyst is used.">
          {status.error ? <ErrorState error={status.error} /> : llm && (
            <>
              <dl>
                <KV k="Mode" v={llm.mode} />
                <KV k="Endpoint" v={llm.url} mono />
                <KV k="Configured model" v={llm.configured_model} mono />
                <KV k="Reachable" v={llm.reachable ? <span className="text-emerald-300">yes</span> : <span className="text-amber-200">no</span>} />
                <KV k="Model pulled" v={llm.model_available ? <span className="text-emerald-300">yes</span> : <span className="text-amber-200">no</span>} />
                {llm.models && llm.models.length > 0 && <KV k="Installed" v={llm.models.join(", ")} mono />}
                {llm.error && <KV k="Last error" v={<span className="text-fg-muted">{llm.error}</span>} />}
              </dl>
              {!(llm.reachable && llm.model_available) && (
                <div className="mt-3 rounded-lg bg-ink-950 p-3 font-mono text-[12px] leading-relaxed text-fg-muted">
                  <div className="mb-1 flex items-center gap-1.5 text-fg-faint"><Terminal className="h-3.5 w-3.5" /> enable on Apple Silicon (~2 GB download, free)</div>
                  <div>brew install ollama</div><div>ollama serve &amp;</div><div>ollama pull {llm.configured_model}</div>
                </div>
              )}
            </>
          )}
        </Card>

        <Card title="Recent pipeline runs" pad={false}>
          <ul className="divide-y divide-ink-700">
            {(runs.data ?? []).slice(0, 8).map((r) => (
              <li key={r.id} className="flex items-center justify-between px-4 py-2.5 text-[12.5px]">
                <span className="font-mono text-[11.5px] text-fg-faint">{r.id}</span>
                <span className={r.status === "succeeded" ? "text-emerald-300" : r.status === "failed" ? "text-rose-300" : "text-fg-muted"}>{r.status}</span>
                <span className="text-fg-muted">{r.stats?.total_ms ? fmtMs(r.stats.total_ms) : "—"}</span>
                <span className="text-fg-faint">{fmtRelative(r.created_at)}</span>
              </li>
            ))}
            {!runs.data?.length && <li className="px-4 py-6 text-center text-sm text-fg-muted">No runs yet</li>}
          </ul>
        </Card>
      </div>
    </>
  );
}
