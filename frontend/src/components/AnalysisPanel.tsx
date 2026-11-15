// AI analysis review workspace.
//
// Shows each generated claim with the integrity engine's verdict, the reasons for it,
// and clickable citations into the evidence inspector. Analysts accept/reject claims,
// and can only approve the analysis once every unsafe claim has been rejected (or
// explicitly overridden with a written justification) - the backend enforces this too.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, Bot, Check, ChevronDown, ChevronRight, Cpu, FileCheck2, Sparkles, X } from "lucide-react";
import { useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import { fmtMs, fmtRelative, shortHash, UNSAFE, VERDICT_META, VERDICTS } from "../lib/format";
import type { Analysis, Claim, Verdict } from "../lib/types";
import { useInspector } from "./EvidenceInspector";
import { Button, Card, EmptyState, ErrorState, Pill, Select, Spinner, VerdictBadge } from "./ui";

export function ScoreRing({ score, size = 76 }: { score: number; size?: number }) {
  const r = size / 2 - 6;
  const c = 2 * Math.PI * r;
  const color = score >= 80 ? "#34d399" : score >= 50 ? "#fbbf24" : "#fb7185";
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Integrity score ${score}`}>
      <circle cx={size / 2} cy={size / 2} r={r} stroke="#1a2331" strokeWidth={6} fill="none" />
      <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={6} fill="none" strokeLinecap="round"
        strokeDasharray={`${(score / 100) * c} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x="50%" y="52%" textAnchor="middle" dominantBaseline="middle" className="fill-fg text-[17px] font-semibold">{Math.round(score)}</text>
    </svg>
  );
}

export function VerdictBar({ verdicts }: { verdicts: Partial<Record<Verdict, number>> }) {
  const total = VERDICTS.reduce((s, v) => s + (verdicts[v] ?? 0), 0) || 1;
  return (
    <div className="space-y-2">
      <div className="flex h-2.5 overflow-hidden rounded-full bg-ink-700">
        {VERDICTS.map((v) => (verdicts[v] ? <div key={v} style={{ width: `${((verdicts[v] ?? 0) / total) * 100}%`, background: VERDICT_META[v].hex }} title={`${VERDICT_META[v].label}: ${verdicts[v]}`} /> : null))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-muted">
        {VERDICTS.map((v) => (
          <span key={v} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: VERDICT_META[v].hex }} />{VERDICT_META[v].short} <span className="tabular-nums text-fg">{verdicts[v] ?? 0}</span></span>
        ))}
      </div>
    </div>
  );
}

function ClaimCard({ claim, analysis, refByEvent }: { claim: Claim; analysis: Analysis; refByEvent: Map<string, string> }) {
  const qc = useQueryClient();
  const { openEvent, openEvents } = useInspector();
  const [open, setOpen] = useState(UNSAFE.includes(claim.verdict));
  const [note, setNote] = useState(claim.review_note ?? "");
  const [err, setErr] = useState<string | null>(null);
  const editable = analysis.status === "pending_review";
  const unsafe = UNSAFE.includes(claim.verdict);
  const review = useMutation({
    mutationFn: (decision: string) => api.reviewClaim(analysis.id, claim.id, decision, note || undefined),
    onSuccess: () => { setErr(null); qc.invalidateQueries({ queryKey: ["analyses", analysis.investigation_id] }); },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Review failed"),
  });
  const shown = claim.citations.slice(0, 12);
  const checks = claim.checks as Record<string, any>;
  return (
    <li className={clsx("rounded-xl border bg-ink-850/70 transition-colors",
      claim.review_status === "rejected" ? "border-ink-700 opacity-60" : unsafe ? "border-rose-500/30" : "border-ink-700")}>
      <div className="flex gap-3 p-3.5">
        <button onClick={() => setOpen((o) => !o)} className="mt-0.5 text-fg-faint hover:text-fg" aria-label="Toggle details">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictBadge verdict={claim.verdict} />
            <Pill>declared: {claim.declared_kind}</Pill>
            {claim.review_status !== "pending" && (
              <span className={clsx("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium",
                claim.review_status === "accepted" ? "bg-emerald-500/10 text-emerald-300" : "bg-rose-500/10 text-rose-300")}>
                {claim.review_status === "accepted" ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />} analyst {claim.review_status}
              </span>
            )}
          </div>
          <p className={clsx("text-[13.5px] leading-relaxed", claim.review_status === "rejected" && "line-through decoration-rose-400/60")}>{claim.text}</p>
          <div className="flex flex-wrap items-center gap-1.5">
            {claim.citations.length === 0 && <span className="text-xs text-fg-faint">No valid citations</span>}
            {shown.map((id) => (
              <button key={id} onClick={() => openEvent(id)} title={id}
                className="rounded-md bg-ink-700/70 px-1.5 py-0.5 font-mono text-[11px] text-sky-200 ring-1 ring-ink-600 hover:bg-sky-500/15 hover:ring-sky-500/40">
                {refByEvent.get(id) ?? id.slice(0, 10)}
              </button>
            ))}
            {claim.citations.length > shown.length && (
              <button onClick={() => openEvents("Cited evidence", claim.citations)} className="text-[11px] text-sky-300 hover:underline">
                +{claim.citations.length - shown.length} more
              </button>
            )}
            {claim.raw_citations.length > claim.citations.length && (
              <span className="text-[11px] text-rose-300">{claim.raw_citations.length - claim.citations.length} invalid citation(s) dropped</span>
            )}
          </div>
          {open && (
            <div className="space-y-2 rounded-lg bg-ink-900/70 p-3 text-[12.5px]">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">Why this verdict</div>
              <ul className="list-disc space-y-1 pl-4 text-fg-muted">{claim.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              {checks.extracted && (
                <div className="grid gap-1 pt-1 text-[11.5px] text-fg-faint sm:grid-cols-2">
                  <div>Entities: <span className="font-mono text-fg-muted">{[...checks.extracted.users, ...checks.extracted.hosts, ...checks.extracted.ips].join(", ") || "none"}</span></div>
                  <div>Activities: <span className="text-fg-muted">{checks.extracted.activities.join(", ") || "none recognised"}</span></div>
                  {checks.count_checks?.map((c: any, i: number) => (
                    <div key={i}>Quantity ({c.kind}): claimed <span className="text-fg-muted">{Math.round(c.claimed).toLocaleString()}</span>, evidence <span className="text-fg-muted">{c.evidence.map((x: number) => Math.round(x).toLocaleString()).join(" / ")}</span></div>
                  ))}
                  {checks.citations?.fabricated?.length > 0 && <div className="text-rose-300">Fabricated refs: {checks.citations.fabricated.join(", ")}</div>}
                </div>
              )}
              {editable && (
                <div className="flex flex-wrap items-end gap-2 border-t border-ink-700 pt-3">
                  <input value={note} onChange={(e) => setNote(e.target.value)} placeholder={unsafe ? "Justification required to accept" : "Optional note"}
                    className="h-8 min-w-[220px] flex-1 rounded-md border border-ink-600 bg-ink-800 px-2.5 text-xs" />
                  <Button size="sm" variant="success" disabled={review.isPending} onClick={() => review.mutate("accept")}><Check className="h-3.5 w-3.5" /> Accept</Button>
                  <Button size="sm" variant="danger" disabled={review.isPending} onClick={() => review.mutate("reject")}><X className="h-3.5 w-3.5" /> Reject</Button>
                  {claim.review_status !== "pending" && <Button size="sm" variant="ghost" onClick={() => review.mutate("pending")}>Undo</Button>}
                </div>
              )}
              {claim.review_note && !editable && <div className="text-xs text-fg-muted">Analyst note: {claim.review_note}</div>}
              {err && <div className="text-xs text-rose-300">{err}</div>}
            </div>
          )}
        </div>
        {editable && !open && (
          <div className="flex shrink-0 items-start gap-1">
            <button title="Accept" onClick={() => (unsafe ? setOpen(true) : review.mutate("accept"))} className="rounded-md p-1.5 text-fg-faint hover:bg-emerald-500/15 hover:text-emerald-300"><Check className="h-4 w-4" /></button>
            <button title="Reject" onClick={() => review.mutate("reject")} className="rounded-md p-1.5 text-fg-faint hover:bg-rose-500/15 hover:text-rose-300"><X className="h-4 w-4" /></button>
          </div>
        )}
      </div>
    </li>
  );
}

function AnalysisView({ analysis, refByEvent }: { analysis: Analysis; refByEvent: Map<string, string> }) {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<Verdict | "all" | "unsafe">("all");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const integ = analysis.integrity;
  const blocking = analysis.claims.filter((c) => UNSAFE.includes(c.verdict) && c.review_status === "pending");
  const decide = useMutation({
    mutationFn: (decision: string) => api.reviewAnalysis(analysis.id, decision, note || undefined),
    onSuccess: () => {
      setErr(null);
      qc.invalidateQueries({ queryKey: ["analyses", analysis.investigation_id] });
      qc.invalidateQueries({ queryKey: ["investigation", analysis.investigation_id] });
      qc.invalidateQueries({ queryKey: ["audit", analysis.investigation_id] });
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed"),
  });
  const claims = analysis.claims.filter((c) => filter === "all" || (filter === "unsafe" ? UNSAFE.includes(c.verdict) : c.verdict === filter));
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-4 rounded-xl border border-ink-700 bg-ink-850/80 p-4">
          <ScoreRing score={integ.integrity_score} />
          <div className="space-y-1 text-[12.5px]">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">Integrity score</div>
            <div><span className="tabular-nums text-fg">{integ.claims}</span> claims · <span className={integ.unsafe_claims ? "text-rose-300" : "text-emerald-300"}>{integ.unsafe_claims} unsafe</span></div>
            <div className="text-fg-muted">{integ.citations_given} citations · {integ.citations_fabricated} fabricated · {integ.citations_out_of_scope} out of scope</div>
          </div>
        </div>
        <div className="space-y-3 rounded-xl border border-ink-700 bg-ink-850/80 p-4">
          <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-muted">
            {analysis.engine === "ollama" ? <Bot className="h-4 w-4 text-sky-300" /> : <Cpu className="h-4 w-4 text-emerald-300" />}
            <span className="text-fg">{analysis.engine}</span> · <span className="font-mono">{analysis.model}</span> · generated in {fmtMs(integ.generation_ms)} · validated in {fmtMs(integ.validation_ms)} · {fmtRelative(analysis.created_at)}
            <span className="ml-auto font-mono text-[11px] text-fg-faint" title="SHA-256 of the evidence handed to the generator">pack {shortHash(analysis.evidence_pack_sha256)}</span>
          </div>
          <VerdictBar verdicts={integ.verdicts} />
        </div>
      </div>

      {analysis.fallback_reason && (
        <div className="flex items-start gap-2 rounded-lg bg-amber-400/10 px-3 py-2.5 text-[12.5px] text-amber-100 ring-1 ring-amber-400/25">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>Local LLM unavailable, so the deterministic analyst was used. Reason: <span className="font-mono">{analysis.fallback_reason}</span></span>
        </div>
      )}
      {(integ.summary_issues?.length ?? 0) > 0 && (
        <div className="rounded-lg bg-rose-500/10 px-3 py-2.5 text-[12.5px] text-rose-100 ring-1 ring-rose-500/30">
          Summary issues: {integ.summary_issues!.join("; ")}
        </div>
      )}

      <Card title="Summary" subtitle="Free text: not evidence. Facts are only trusted through the validated claims below.">
        <p className="text-[13.5px] leading-relaxed text-fg-muted">{analysis.summary || "—"}</p>
        {(integ.recommendations?.length ?? 0) > 0 && (
          <ul className="mt-3 space-y-1 border-t border-ink-700 pt-3 text-[13px]">
            {integ.recommendations!.map((r) => <li key={r} className="flex gap-2"><Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-300" />{r}</li>)}
          </ul>
        )}
      </Card>

      <div className="flex flex-wrap items-center gap-1.5">
        {(["all", "unsafe", ...VERDICTS] as const).map((f) => {
          const n = f === "all" ? analysis.claims.length : f === "unsafe" ? analysis.claims.filter((c) => UNSAFE.includes(c.verdict)).length : analysis.claims.filter((c) => c.verdict === f).length;
          if (n === 0 && f !== "all") return null;
          return (
            <button key={f} onClick={() => setFilter(f)}
              className={clsx("rounded-lg px-2.5 py-1 text-xs ring-1 transition-colors", filter === f ? "bg-sky-500/15 text-sky-200 ring-sky-500/40" : "text-fg-muted ring-ink-600 hover:bg-ink-800")}>
              {f === "all" ? "All" : f === "unsafe" ? "Needs attention" : VERDICT_META[f].short} <span className="tabular-nums opacity-70">{n}</span>
            </button>
          );
        })}
      </div>

      <ul className="space-y-2.5">{claims.map((c) => <ClaimCard key={c.id} claim={c} analysis={analysis} refByEvent={refByEvent} />)}</ul>

      <Card title="Analyst decision" subtitle="Approval requires every unsupported or contradictory claim to be rejected, or accepted with a written justification.">
        {analysis.status === "pending_review" ? (
          <div className="space-y-3">
            {blocking.length > 0 ? (
              <div className="flex items-center gap-2 text-[13px] text-amber-200"><AlertTriangle className="h-4 w-4" /> {blocking.length} unsafe claim(s) still need a decision before approval.</div>
            ) : (
              <div className="flex items-center gap-2 text-[13px] text-emerald-300"><FileCheck2 className="h-4 w-4" /> Ready for approval. Pending safe claims will be recorded as accepted.</div>
            )}
            <div className="flex flex-wrap gap-2">
              <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Decision note (recorded in the audit log)"
                className="h-9 min-w-[240px] flex-1 rounded-lg border border-ink-600 bg-ink-800 px-3 text-[13px]" />
              <Button variant="success" disabled={blocking.length > 0 || decide.isPending} onClick={() => decide.mutate("approve")}><Check className="h-4 w-4" /> Approve analysis</Button>
              <Button variant="danger" disabled={decide.isPending} onClick={() => decide.mutate("reject")}><X className="h-4 w-4" /> Reject</Button>
            </div>
            {err && <div className="text-xs text-rose-300">{err}</div>}
          </div>
        ) : (
          <div className="text-[13px] text-fg-muted">
            <span className={analysis.status === "approved" ? "text-emerald-300" : "text-rose-300"}>{analysis.status === "approved" ? "Approved" : "Rejected"}</span> by <span className="text-fg">{analysis.reviewed_by}</span> {fmtRelative(analysis.reviewed_at)}{analysis.review_note ? `: "${analysis.review_note}"` : ""}
          </div>
        )}
      </Card>
    </div>
  );
}

export function AnalysisPanel({ investigationId, refByEvent }: { investigationId: string; refByEvent: Map<string, string> }) {
  const qc = useQueryClient();
  const [engine, setEngine] = useState("auto");
  const [selected, setSelected] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["analyses", investigationId], queryFn: () => api.analyses(investigationId) });
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, staleTime: 15_000 });
  const create = useMutation({
    mutationFn: () => api.createAnalysis(investigationId, engine),
    onSuccess: (a) => {
      setSelected(a.id);
      qc.invalidateQueries({ queryKey: ["analyses", investigationId] });
      qc.invalidateQueries({ queryKey: ["audit", investigationId] });
    },
  });
  const current = useMemo(() => list.data?.find((a) => a.id === selected) ?? list.data?.[0], [list.data, selected]);
  const llm = status.data?.llm;
  const llmReady = !!llm?.reachable && !!llm?.model_available;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-ink-700 bg-gradient-to-r from-sky-500/5 to-transparent p-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold">Generate an AI analysis</div>
          <p className="mt-0.5 text-xs text-fg-muted">
            {llmReady ? <>Local model <span className="font-mono text-fg">{llm!.configured_model}</span> is ready via Ollama.</> :
              <>Local LLM not available{llm?.mode === "deterministic" ? " (disabled)" : ""}. "Auto" falls back to the deterministic analyst, and every claim is validated either way.</>}
          </p>
        </div>
        <Select label="Engine" value={engine} onChange={setEngine} className="w-48" options={[
          { value: "auto", label: "Auto (LLM → fallback)" }, { value: "ollama", label: "Ollama only" }, { value: "deterministic", label: "Deterministic" }]} />
        <Button variant="primary" disabled={create.isPending} onClick={() => create.mutate()}>
          <Sparkles className="h-4 w-4" /> {create.isPending ? (engine === "deterministic" ? "Generating…" : "Running model…") : "Generate"}
        </Button>
      </div>
      {create.error && <ErrorState error={create.error} />}
      {list.isLoading ? <Spinner /> : list.error ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : !list.data?.length ? (
        <EmptyState title="No analysis yet" icon={<Bot className="h-5 w-5" />}>
          Generate one to get a narrative with every statement checked against the evidence.
        </EmptyState>
      ) : (
        <>
          {list.data.length > 1 && (
            <div className="flex flex-wrap gap-2">
              {list.data.map((a) => (
                <button key={a.id} onClick={() => setSelected(a.id)}
                  className={clsx("rounded-lg px-2.5 py-1.5 text-left text-xs ring-1", a.id === current?.id ? "bg-ink-700 ring-sky-500/40" : "ring-ink-700 hover:bg-ink-800")}>
                  <div className="font-medium">{a.engine} · score {Math.round(a.integrity.integrity_score)}</div>
                  <div className="text-fg-faint">{a.status.replace("_", " ")} · {fmtRelative(a.created_at)}</div>
                </button>
              ))}
            </div>
          )}
          {current && <AnalysisView analysis={current} refByEvent={refByEvent} />}
        </>
      )}
    </div>
  );
}
