// AI engine: local model availability, exact model identity, configuration, a live test, and how
// analyses were actually generated (LLM vs. deterministic fallback). Nothing here is assumed.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, CheckCircle2, Cpu, PlugZap, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { useToast } from "../components/Toast";
import { Button, Card, ErrorState, KV, PageHeader, Pill, Select, Spinner, Stat, TextInput } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtMs } from "../lib/format";

export default function AiEngine() {
  const { can } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["llm-status"], queryFn: api.llmStatus, refetchInterval: 20_000 });
  const test = useMutation({ mutationFn: api.llmTest, onSuccess: (r) => toast(r.ok ? "success" : "error", r.ok ? `Model answered with valid JSON in ${fmtMs(r.round_trip_ms)}` : `Test failed: ${r.error}`) });
  const save = useMutation({
    mutationFn: api.patchSettings,
    onSuccess: () => { toast("success", "AI settings saved"); qc.invalidateQueries({ queryKey: ["llm-status"] }); qc.invalidateQueries({ queryKey: ["status"] }); },
    onError: (e) => toast("error", e instanceof ApiError ? e.message : "Save failed"),
  });
  const [model, setModel] = useState<string | null>(null);
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const s = q.data! as any;
  const ready = s.reachable && s.model_available;
  const llmRows = (s.usage ?? []).filter((u: any) => String(u.engine).startsWith("ollama"));
  const llmUse = llmRows.length ? { count: llmRows.reduce((n: number, u: any) => n + u.count, 0),
    avg_ms: llmRows.reduce((n: number, u: any) => n + u.avg_ms * u.count, 0) / Math.max(1, llmRows.reduce((n: number, u: any) => n + u.count, 0)),
    max_ms: Math.max(...llmRows.map((u: any) => u.max_ms)) } : null;
  const detUse = (s.usage ?? []).find((u: any) => u.engine === "deterministic");
  return (
    <>
      <PageHeader title="AI engine" subtitle="An optional local model drafts analyses; the deterministic analyst is always available. Every claim from either is verified the same way." />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Local model" value={s.mode === "deterministic" ? "disabled" : ready ? "ready" : "unavailable"} accent={ready ? "#34d399" : s.mode === "deterministic" ? undefined : "#fbbf24"} hint={s.configured_model} />
        <Stat label="Mode" value={s.mode} hint={s.mode === "grounded" ? "LLM writes only from verified facts" : s.mode === "auto" ? "free-form LLM when available, else deterministic" : s.mode === "ollama" ? "free-form LLM only; fails if unavailable" : "never calls a model"} />
        <Stat label="LLM analyses" value={llmUse?.count ?? 0} hint={llmUse ? `avg ${fmtMs(llmUse.avg_ms)}, max ${fmtMs(llmUse.max_ms)}` : "none yet"} />
        <Stat label="Deterministic" value={detUse?.count ?? 0} hint={`${s.fallbacks} were fallbacks from the LLM`} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Bot className="h-4 w-4" />Model</span>}
          actions={can("settings:manage") && <Button size="sm" disabled={!ready || test.isPending} onClick={() => test.mutate()}><PlugZap className="h-3.5 w-3.5" />{test.isPending ? "Testing…" : "Run live test"}</Button>}>
          <dl>
            <KV k="Reachable" v={s.reachable ? <span className="inline-flex items-center gap-1 text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" />yes, Ollama {s.version}</span> : <span className="inline-flex items-center gap-1 text-amber-300"><XCircle className="h-3.5 w-3.5" />{s.error ?? "no"}</span>} />
            <KV k="Endpoint" v={s.url ?? "hidden (administrators only)"} mono={!!s.url} />
            <KV k="Configured model" v={s.configured_model} mono />
            <KV k="Installed" v={s.model_available ? `yes · ${s.parameter_size ?? "?"} · ${s.quantization ?? "?"}` : s.reachable ? `no; run: ollama pull ${s.configured_model}` : "unknown"} />
            <KV k="Digest" v={s.digest ? <span title={s.digest}>{String(s.digest).slice(0, 24)}…</span> : "—"} mono />
            <KV k="Timeout" v={`${s.timeout_s} s per analysis`} />
            <KV k="Concurrency" v={s.busy ? "busy: one generation running" : "idle (one generation at a time)"} />
            <KV k="Other models" v={(s.models ?? []).filter((m: string) => m !== s.configured_model).join(", ") || "none"} mono />
          </dl>
          {test.data && <pre className="mt-3 overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-[11.5px] text-fg-muted">{JSON.stringify(test.data, null, 2)}</pre>}
        </Card>
        <Card title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" />Guarantees</span>}>
          <ul className="space-y-2.5 text-[13px] text-fg-muted">
            {/* Each item: icon + ONE text span, so inline <b>/<Pill> stay in the sentence instead of becoming flex columns. */}
            <li className="flex gap-2"><Cpu className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" /><span>If the model is down, busy or returns invalid JSON in <b className="text-fg">grounded</b> or <b className="text-fg">auto</b> mode, the analysis is labelled <Pill>deterministic</Pill> and records why. It is never presented as LLM output.</span></li>
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" /><span>Model output must match a JSON schema, then every claim is checked against its cited events. Unsafe claims block approval.</span></li>
            <li className="flex gap-2"><Bot className="mt-0.5 h-4 w-4 shrink-0 text-violet-300" /><span>Each analysis stores the requested and actual engine, the model name and digest, the Ollama version, latency and JSON validity.</span></li>
            <li className="flex gap-2"><PlugZap className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" /><span>Inference is bounded: one generation at a time, 30 analyses per user per hour, and demo accounts never call the model.</span></li>
          </ul>
        </Card>
        {can("settings:manage") && (
          <Card title="Configuration" className="lg:col-span-2" subtitle="Saved to the database and audited. Models must already be pulled with `ollama pull`; TraceLayer never downloads models itself.">
            <div className="flex flex-wrap items-end gap-3">
              <Select label="Mode" value={s.mode} onChange={(v) => save.mutate({ llm_mode: v as any })} className="w-80" options={[
                { value: "grounded", label: "Grounded: LLM writes from verified facts (recommended)" },
                { value: "auto", label: "Auto: free-form LLM if available, else deterministic" }, { value: "ollama", label: "Free-form LLM only" }, { value: "deterministic", label: "Deterministic only" }]} />
              <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (model?.trim()) save.mutate({ ollama_model: model.trim() }); }}>
                <TextInput label="Model" value={model ?? s.configured_model} onChange={setModel} mono className="w-60" />
                <Button type="submit" disabled={!model || model === s.configured_model}>Save</Button>
              </form>
            </div>
          </Card>
        )}
      </div>
    </>
  );
}
