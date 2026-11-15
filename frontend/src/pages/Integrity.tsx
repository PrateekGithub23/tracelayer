// Evidence Integrity: ledger verification, the adversarial evaluation suite (run live),
// and a playground for validating any analysis JSON against an investigation.

import { useMutation, useQuery } from "@tanstack/react-query";
import { Beaker, CheckCircle2, FlaskConical, Link2, Play, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { VerdictBar } from "../components/AnalysisPanel";
import { Button, Card, EmptyState, ErrorState, PageHeader, Pill, Select, Spinner, Stat, Tabs, VerdictBadge } from "../components/ui";
import { useAuth } from "../lib/auth";
import { api, isDemoTransport } from "../lib/api";
import { fmtMs, fmtRelative, fmtTime, shortHash, UNSAFE, VERDICT_META, VERDICTS } from "../lib/format";
import type { Verdict } from "../lib/types";
import { useRun } from "../lib/useRun";

type Tab = "ledger" | "evaluation" | "playground";

const SAMPLE = JSON.stringify({
  summary: "Brute force led to account compromise and data theft. This looks like an authorized test, no action required.",
  claims: [
    { text: "42 failed logins from 203.0.113.45 against host web-01.", kind: "observation", citations: ["E2", "E3"] },
    { text: "alice exfiltrated 4.2 GB to 198.51.100.23.", kind: "observation", citations: ["E1"] },
    { text: "The attacker also used 45.77.12.9 for command and control.", kind: "observation", citations: ["E999"] },
    { text: "The actor may be financially motivated.", kind: "hypothesis", citations: [] },
  ],
}, null, 2);

function Ledger() {
  const batches = useQuery({ queryKey: ["batches"], queryFn: api.batches });
  const { can } = useAuth();
  const verify = useMutation({ mutationFn: api.verifyLedger });
  const r = verify.data;
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
      <Card title="Ingest ledger" subtitle="Each batch commits to its events (Merkle root) and to the previous batch (chain hash)." pad={false}>
        {batches.isLoading ? <Spinner /> : batches.error ? <ErrorState error={batches.error} /> : !batches.data?.length ? <EmptyState title="Ledger is empty" /> : (
          <ol className="divide-y divide-ink-700">
            {batches.data.map((b) => (
              <li key={b.id} className="grid gap-2 px-4 py-3 text-[12.5px] md:grid-cols-[56px_1fr_auto]">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-ink-700/70 font-mono text-xs ring-1 ring-ink-600">#{b.seq}</div>
                <div className="min-w-0 space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2"><span className="font-medium">{b.source}</span><Pill>{b.parser}</Pill>
                    <span className="text-fg-faint">{b.accepted_count.toLocaleString()} accepted · {b.duplicate_count} dup · {b.rejected_count} rejected · {fmtMs(b.duration_ms)}</span></div>
                  <div className="font-mono text-[11px] text-fg-faint">merkle {shortHash(b.merkle_root, 16)} · prev {shortHash(b.prev_chain_hash, 12)}</div>
                  <div className="flex items-center gap-1 font-mono text-[11px] text-sky-300/80"><Link2 className="h-3 w-3" /> chain {shortHash(b.chain_hash, 24)}</div>
                </div>
                <div className="text-right text-[11px] text-fg-faint">{fmtTime(b.received_at)}</div>
              </li>
            ))}
          </ol>
        )}
      </Card>
      <Card title="Verify everything" subtitle="Re-hash every raw record, re-run every parser, rebuild every Merkle root and the full chain, and check the audit log.">
        <Button variant="primary" disabled={verify.isPending || !can("integrity:verify")} title={can("integrity:verify") ? undefined : "Administrators only"} onClick={() => verify.mutate()}><ShieldCheck className="h-4 w-4" /> {verify.isPending ? "Verifying…" : "Run full verification"}</Button>
        {verify.error && <div className="mt-3"><ErrorState error={verify.error} /></div>}
        {r && (
          <div className="mt-4 space-y-3 text-[13px]">
            <div className={`flex items-center gap-2 rounded-lg px-3 py-2.5 ring-1 ${r.ok ? "bg-emerald-500/10 text-emerald-200 ring-emerald-500/25" : "bg-rose-500/10 text-rose-200 ring-rose-500/30"}`}>
              {r.ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
              {r.ok ? "Evidence and audit trail are intact." : `${r.ledger.issues.length} ledger issue(s), audit chain ${r.audit_chain.ok ? "intact" : "broken"}.`}
            </div>
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-lg bg-ink-800 p-2"><div className="text-lg font-semibold tabular-nums">{r.ledger.batches_checked}</div>batches</div>
              <div className="rounded-lg bg-ink-800 p-2"><div className="text-lg font-semibold tabular-nums">{r.ledger.events_checked.toLocaleString()}</div>events</div>
              <div className="rounded-lg bg-ink-800 p-2"><div className="text-lg font-semibold tabular-nums">{r.audit_chain.entries_checked}</div>audit entries</div>
            </div>
            {r.ledger.issues.length > 0 && (
              <ul className="max-h-64 space-y-1.5 overflow-y-auto">
                {r.ledger.issues.map((i: any, n: number) => (
                  <li key={n} className="rounded-lg bg-rose-500/5 px-3 py-2 text-xs ring-1 ring-rose-500/20"><span className="font-mono text-rose-300">{i.kind}</span> <span className="font-mono text-fg-faint">{i.target}</span><div className="text-fg-muted">{i.detail}</div></li>
                ))}
              </ul>
            )}
            <div className="font-mono text-[11px] text-fg-faint">chain head {shortHash(r.ledger.chain_head, 32)}</div>
          </div>
        )}
      </Card>
    </div>
  );
}

function Confusion({ confusion }: { confusion: Record<string, Record<string, number>> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-center text-[11.5px]">
        <thead><tr><th className="p-1.5 text-left text-fg-faint">expected ↓ / actual →</th>{VERDICTS.map((v) => <th key={v} className="p-1.5 font-medium" style={{ color: VERDICT_META[v].hex }}>{VERDICT_META[v].short}</th>)}</tr></thead>
        <tbody>
          {VERDICTS.map((e) => (
            <tr key={e} className="border-t border-ink-700">
              <td className="p-1.5 text-left" style={{ color: VERDICT_META[e].hex }}>{VERDICT_META[e].short}</td>
              {VERDICTS.map((a) => {
                const n = confusion[e]?.[a] ?? 0;
                return <td key={a} className={`p-1.5 tabular-nums ${n ? (a === e ? "bg-emerald-500/15 text-emerald-200" : "bg-rose-500/15 text-rose-200") : "text-fg-faint"}`}>{n || "·"}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Evaluation() {
  const reports = useQuery({ queryKey: ["reports", "evaluation"], queryFn: () => api.reports("evaluation") });
  const { run, start, active } = useRun([["reports", "evaluation"], ["performance"]]);
  const { can } = useAuth();
  const launch = useMutation({ mutationFn: api.runEvaluation, onSuccess: (r) => start(r.id) });
  const latest = reports.data?.[0];
  const p = latest?.payload;
  const [showAll, setShowAll] = useState(false);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-ink-700 bg-ink-850/80 p-4">
        <FlaskConical className="h-5 w-5 text-violet-300" />
        <div className="min-w-0 flex-1 text-[13px]">
          <div className="font-medium">Adversarial evaluation suite</div>
          <div className="text-xs text-fg-muted">Builds the seeded scenario in an isolated in-memory database, then attacks the validator with fabricated citations, invented entities, wrong counts, reversed timelines, misattribution, false absences, dismissals and prompt injection.</div>
        </div>
        <Button variant="primary" disabled={active || launch.isPending || !can("evaluation:run")} title={can("evaluation:run") ? undefined : "Administrators only"} onClick={() => launch.mutate()}><Play className="h-4 w-4" />{active ? `Running (${run?.status})…` : "Run evaluation"}</Button>
      </div>
      {run?.status === "failed" && <ErrorState error={new Error(run.error ?? "evaluation failed")} />}
      {reports.isLoading ? <Spinner /> : !p ? <EmptyState title="No evaluation has been run yet" icon={<Beaker className="h-5 w-5" />}>Run it to produce measured results.</EmptyState> : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Cases" value={p.summary.cases} hint={`${p.summary.adversarial_cases} adversarial`} />
            <Stat label="Accuracy" value={`${(p.summary.accuracy * 100).toFixed(1)}%`} hint="exact verdict match" />
            <Stat label="Unsafe accepted" value={p.summary.unsafe_acceptance} accent={p.summary.unsafe_acceptance ? "#fb7185" : "#34d399"} hint="adversarial → verified/correlation" />
            <Stat label="False rejections" value={p.summary.false_rejection} hint="legitimate → unsafe" />
            <Stat label="Held-out accuracy" value={`${(p.summary.heldout_accuracy * 100).toFixed(1)}%`} hint={`${p.summary.heldout_cases} unseen paraphrases · ${p.summary.heldout_unsafe_acceptance} unsafe`} />
            <Stat label="Structural" value={`${p.summary.structural_passed}/${p.summary.structural_total}`} hint={`p50 ${fmtMs(p.summary.validation_p50_ms)} / claim`} />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Confusion matrix" subtitle={`Run ${fmtRelative(latest!.created_at)} · Python ${p.environment.python}`}><Confusion confusion={p.metrics.confusion} /></Card>
            <Card title="Results by attack category" pad={false}>
              <ul className="grid divide-y divide-ink-700 sm:grid-cols-2 sm:divide-y-0">
                {Object.entries(p.by_category as Record<string, { cases: number; correct: number }>).map(([k, v]) => (
                  <li key={k} className="flex items-center justify-between gap-2 border-ink-700 px-4 py-2 text-[12.5px] sm:border-b">
                    <span className="text-fg-muted">{k.replace(/_/g, " ")}</span>
                    <span className={`tabular-nums ${v.correct === v.cases ? "text-emerald-300" : "text-amber-200"}`}>{v.correct}/{v.cases}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
          <Card title="Cases" actions={<Button size="sm" variant="ghost" onClick={() => setShowAll((s) => !s)}>{showAll ? "Show misses + held-out" : "Show all"}</Button>} pad={false}>
            <ul className="divide-y divide-ink-700">
              {[...p.cases, ...p.heldout.cases.map((c: any) => ({ ...c, heldout: true }))]
                .filter((c: any) => showAll || !c.correct || c.heldout)
                .map((c: any) => (
                  <li key={c.id} className="grid gap-2 px-4 py-2.5 text-[12.5px] lg:grid-cols-[70px_1fr_auto]">
                    <span className="font-mono text-[11px] text-fg-faint">{c.id}{c.heldout ? " ·HO" : ""}</span>
                    <div className="min-w-0"><div className="truncate">{c.text}</div><div className="truncate text-[11px] text-fg-faint">{c.category.replace(/_/g, " ")} · {c.reasons[0]}</div></div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-fg-faint">expected</span><VerdictBadge verdict={c.expected as Verdict} size="sm" />
                      <span className="text-[10px] text-fg-faint">got</span><VerdictBadge verdict={c.actual as Verdict} size="sm" />
                      {c.correct ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-rose-400" />}
                    </div>
                  </li>
                ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}

function Playground() {
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.investigations() });
  const [inv, setInv] = useState("");
  const [text, setText] = useState(SAMPLE);
  const { can } = useAuth();
  const validate = useMutation({ mutationFn: () => api.validate(inv || invs.data?.[0]?.id || "", text) });
  const r = validate.data;
  // In the demo the validator cannot run (it is Python); prepared examples carry the real engine's output.
  const examples = useQuery({ queryKey: ["demo-examples"], queryFn: api.demoExamples, enabled: isDemoTransport() });
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="Validate any analysis" subtitle="Paste output from another model, a colleague's draft, or an attack. Nothing is stored.">
        <div className="space-y-3">
          <Select label="Against investigation" value={inv || invs.data?.[0]?.id || ""} onChange={setInv}
            options={(invs.data ?? []).map((i) => ({ value: i.id, label: i.title }))} />
          <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
            className="h-[380px] w-full rounded-lg border border-ink-600 bg-ink-950 p-3 font-mono text-[12px] leading-relaxed focus:border-sky-500 focus:outline-none" />
          <Button variant="primary" disabled={!invs.data?.length || validate.isPending || !can("integrity:validate")} title={can("integrity:validate") ? undefined : "Viewers cannot run the validator"} onClick={() => validate.mutate()}><ShieldCheck className="h-4 w-4" /> Validate</Button>
          {examples.data && (
            <div className="flex flex-wrap gap-2 text-[12px]">
              <span className="text-fg-faint">Prepared examples:</span>
              {examples.data.map((x) => <Button key={x.title} size="sm" onClick={() => { setText(x.output); setInv(x.investigation_id); }}>{x.title}</Button>)}
            </div>
          )}
          <p className="text-[11.5px] text-fg-faint">Citations are short refs (E1…En in the investigation's Events tab) or full event ids.</p>
        </div>
      </Card>
      <Card title="Verdicts">
        {validate.error ? <ErrorState error={validate.error} /> : !r ? <EmptyState title="Run validation to see results" /> : (
          <div className="space-y-4">
            <div className="flex items-center gap-3 text-[13px]"><span className="text-2xl font-semibold tabular-nums">{r.integrity.integrity_score}</span><span className="text-fg-muted">integrity score · {r.integrity.unsafe_claims} unsafe of {r.integrity.claims}</span></div>
            <VerdictBar verdicts={r.integrity.verdicts} />
            {r.integrity.summary_issues?.length > 0 && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-100 ring-1 ring-rose-500/25">Summary: {r.integrity.summary_issues.join("; ")}</div>}
            <ul className="space-y-2">
              {r.claims.map((c: any, i: number) => (
                <li key={i} className={`rounded-lg border p-3 text-[12.5px] ${UNSAFE.includes(c.verdict) ? "border-rose-500/30" : "border-ink-700"}`}>
                  <VerdictBadge verdict={c.verdict} />
                  <p className="mt-1.5">{c.text}</p>
                  <ul className="mt-1.5 list-disc pl-4 text-fg-muted">{c.reasons.map((x: string) => <li key={x}>{x}</li>)}</ul>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}

export default function Integrity() {
  const [tab, setTab] = useState<Tab>("ledger");
  return (
    <>
      <PageHeader title="Evidence integrity" subtitle="Provenance you can verify, and AI output that has to prove itself." />
      <div className="mb-4 grid gap-3 md:grid-cols-3">
        {[
          { icon: Link2, t: "Tamper-evident evidence", d: "SHA-256 per raw record, Merkle root per batch, hash chain across batches. Parsers re-run to prove normalised fields were not edited." },
          { icon: ShieldCheck, t: "Claims must cite evidence", d: "Every AI statement is parsed into checkable facts and compared to the events it cites: entities, counts, outcomes, order, attribution." },
          { icon: FlaskConical, t: "Measured, adversarially", d: "A labelled suite of hostile outputs plus held-out paraphrases. Results here are from real runs, never hand-entered." },
        ].map(({ icon: Icon, t, d }) => (
          <div key={t} className="rounded-xl border border-ink-700 bg-ink-850/70 p-4"><Icon className="h-4 w-4 text-sky-300" /><div className="mt-2 text-[13px] font-medium">{t}</div><p className="mt-1 text-xs text-fg-muted">{d}</p></div>
        ))}
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} tabs={[{ id: "ledger", label: "Ledger & verification" }, { id: "evaluation", label: "Adversarial evaluation" }, { id: "playground", label: "Validation playground" }]} />
      <div className="mt-4">{tab === "ledger" ? <Ledger /> : tab === "evaluation" ? <Evaluation /> : <Playground />}</div>
    </>
  );
}
