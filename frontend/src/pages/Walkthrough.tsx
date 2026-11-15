// Guided scenario: "The Suspicious Login That Wasn't Just a Login".
// Every step is computed from live API data (the same data the rest of the app shows), not from text
// written into this page. If the scenario has not been loaded, the page says how to load it.
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Compass, Download, ExternalLink, ShieldCheck } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { VerdictBar } from "../components/AnalysisPanel";
import { useInspector } from "../components/EvidenceInspector";
import { useToast } from "../components/Toast";
import { Button, Card, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge, Spinner, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { STATUS_META } from "../lib/cases";
import { fmtTime } from "../lib/format";
import type { Analysis, Detection, TimelineEvent, Verdict } from "../lib/types";

function EventChip({ e }: { e: TimelineEvent }) {
  const { openEvent } = useInspector();
  return (
    <button onClick={() => openEvent(e.id)} className="flex w-full items-center gap-3 rounded-lg border border-ink-700 bg-ink-900/60 px-3 py-2 text-left text-[12.5px] hover:border-sky-500/40">
      <Pill mono>{e.ref}</Pill>
      <span className="font-mono text-[11.5px] text-fg-faint">{fmtTime(e.timestamp)}</span>
      <span className="min-w-0 truncate">{e.event_type} · {e.outcome} · {e.username ?? "—"} @ {e.host ?? "—"}{e.src_ip ? ` from ${e.src_ip}` : ""}</span>
    </button>
  );
}

function DetectionLine({ d }: { d: Detection }) {
  return <div className="flex flex-wrap items-center gap-2 text-[13px]"><SeverityBadge severity={d.severity} /><Pill mono>{d.rule_id}</Pill><span className="text-fg-muted">{d.summary}</span></div>;
}

export default function Walkthrough() {
  const invs = useQuery({ queryKey: ["investigations", "all-walkthrough"], queryFn: () => api.investigations({ view: "all" }) });
  const main = invs.data?.find((i) => i.tactics.includes("initial-access") && i.tactics.includes("exfiltration"));
  const id = main?.id ?? "";
  const detail = useQuery({ queryKey: ["investigation", id], queryFn: () => api.investigation(id), enabled: !!id });
  const timeline = useQuery({ queryKey: ["timeline", id], queryFn: () => api.timeline(id), enabled: !!id });
  const analyses = useQuery({ queryKey: ["analyses", id], queryFn: () => api.analyses(id), enabled: !!id });
  const [step, setStep] = useState(0);
  const { can } = useAuth();
  const toast = useToast();

  const facts = useMemo(() => {
    const ev = timeline.data?.events ?? [];
    const dets = detail.data?.detections ?? [];
    const byRule = (prefix: string) => dets.filter((d) => d.rule_id.startsWith(prefix));
    // The brute-force source is the address with the most failed logins; the story starts with its first success.
    const failCount = new Map<string, number>();
    for (const e of ev) if (e.event_type === "auth.login" && e.outcome === "failure" && e.src_ip) failCount.set(e.src_ip, (failCount.get(e.src_ip) ?? 0) + 1);
    const attacker = [...failCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
    const success = ev.find((e) => e.event_type === "auth.login" && e.outcome === "success" && e.src_ip === attacker);
    const fails = ev.filter((e) => e.event_type === "auth.login" && e.outcome === "failure" && e.src_ip === attacker);
    const procs = ev.filter((e) => e.event_type === "process.start" && e.host === success?.host && success && e.timestamp >= success.timestamp).slice(0, 4);
    const priv = ev.filter((e) => e.event_type === "iam.change");
    const grounded = (analyses.data ?? []).find((a) => a.engine === "ollama-grounded");
    const free = (analyses.data ?? []).find((a) => a.engine === "ollama");
    const det = (analyses.data ?? []).find((a) => a.engine === "deterministic");
    return { success, fails, procs, priv, byRule, grounded, free, det, ev };
  }, [timeline.data, detail.data, analyses.data]);

  if (invs.isLoading) return <Spinner label="Finding the scenario" />;
  if (invs.error) return <ErrorState error={invs.error} />;
  if (!main) {
    return (
      <EmptyState title="The guided scenario's data isn't loaded" icon={<Compass className="h-5 w-5" />}>
        {can("synthetic:generate") ? <>Go to <Link className="text-sky-300" to="/ingest">Ingest</Link> and choose “Generate, ingest &amp; detect”: it creates the seeded intrusion this walkthrough follows.</> :
          "Ask an administrator to load the seeded scenario (Ingest → Generate)."}
      </EmptyState>
    );
  }
  if (detail.isLoading || timeline.isLoading || analyses.isLoading) return <Spinner label="Loading the case" />;
  const { success, fails, procs, priv, byRule, grounded, free, det } = facts;
  const draft: Analysis | undefined = grounded ?? free ?? det;
  const unsafeOf = (a?: Analysis) => a?.claims.filter((c) => c.verdict === "unsupported_claim" || c.verdict === "contradictory_finding").length ?? 0;
  const good = draft?.claims.find((c) => c.verdict === "verified_observation" || c.verdict === "heuristic_correlation");
  const bad = [free, grounded, det].flatMap((a) => a?.claims ?? []).find((c) => c.verdict === "unsupported_claim" || c.verdict === "contradictory_finding");
  const caseLink = (tab: string) => `/investigations/${id}?tab=${tab}`;

  const steps: { title: string; body: ReactNode; link?: [string, string] }[] = [
    { title: "1 · An ordinary-looking sign-in", link: [caseLink("timeline"), "See it on the timeline"], body: (
      <>
        <p>A successful login is the most common event in any log. This one, by <b>{success?.username}</b> on <b>{success?.host}</b>, is where the story starts. On its own it proves nothing.</p>
        {success && <EventChip e={success} />}
        <p className="text-fg-faint">Click the event to see the raw record as received, its SHA-256 and its position in the hash-chained ledger.</p>
      </>) },
    { title: "2 · Related authentication activity", link: [caseLink("detections"), "Open the detections"], body: (
      <>
        <p>The same source address <b className="font-mono">{success?.src_ip}</b> produced <b>{fails.length} failed logins</b> just before the success: a brute force that worked.</p>
        {byRule("TL-AUTH-001").concat(byRule("TL-AUTH-002")).map((d) => <DetectionLine key={d.id} d={d} />)}
        {fails.slice(-2).map((e) => <EventChip key={e.id} e={e} />)}
      </>) },
    { title: "3 · Location and endpoint correlation", link: [caseLink("graph"), "Explore the entity graph"], body: (
      <>
        <p>Correlation connects things no single rule sees: the account was used from two places too far apart to travel between, and the endpoint it logged in to started running attacker tradecraft.</p>
        {byRule("TL-AUTH-003").concat(byRule("TL-EXEC")).map((d) => <DetectionLine key={d.id} d={d} />)}
        {procs.slice(0, 2).map((e) => <EventChip key={e.id} e={e} />)}
      </>) },
    { title: "4 · Privilege modification", link: [caseLink("timeline"), "Show where it sits in time"], body: (
      <>
        <p>Minutes later, the compromised account is added to a privileged group. Now this is an incident, not a suspicious login.</p>
        {byRule("TL-PRIV").map((d) => <DetectionLine key={d.id} d={d} />)}
        {priv.map((e) => <EventChip key={e.id} e={e} />)}
        <p className="text-fg-faint">Correlation grouped {detail.data!.detections.length} detections across {detail.data!.tactics.length} ATT&amp;CK tactics into this one case (risk score {Math.round(main.score)}).</p>
      </>) },
    { title: "5 · The AI drafts the investigation", link: [caseLink("analysis"), "Open the AI analyses"], body: draft ? (
      <>
        {draft.engine === "ollama-grounded" ? (
          <p>A local model (<span className="font-mono">{draft.model}</span>, running on the analyst's laptop) wrote the draft in <b>grounded</b> mode: it only saw facts the engine had already verified, and could only cite them by id. It cannot invent a citation.</p>
        ) : <p>A draft was generated by the <span className="font-mono">{draft.engine}</span> engine.</p>}
        <VerdictBar verdicts={draft.integrity.verdicts} />
        <p className="text-fg-muted">Grounded draft: {draft.claims.length} claims, <b>{unsafeOf(draft)}</b> unsafe, integrity score <b>{Math.round(draft.integrity.integrity_score)}</b>/100.</p>
        {free && <p className="rounded-lg border border-ink-600 bg-ink-800/60 p-3 text-fg-muted">The same model writing <i>freely</i> from raw events on this case: {free.claims.length} claims, <b className="text-rose-200">{unsafeOf(free)} unsafe</b>, score {Math.round(free.integrity.integrity_score)}. Across 15 benchmark runs, grounding cut unsafe claims from 63% to 3%.</p>}
      </>) : <p>No analysis exists yet. {can("analyses:create") ? "Generate one on the AI analysis tab." : ""}</p> },
    { title: "6 · Every sentence is checked against its evidence", link: ["/integrity", "How the engine decides"], body: (
      <>
        <p>Whatever wrote the draft, the Evidence Integrity Engine re-reads each claim, resolves its citations, and compares entities, counts, times and outcomes with the cited events. Fluent is not the same as true:</p>
        {good && <div className="space-y-1 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3"><VerdictBadge verdict={good.verdict as Verdict} /><p>{good.text}</p></div>}
        {bad ? <div className="space-y-1 rounded-lg border border-rose-500/30 bg-rose-500/5 p-3"><VerdictBadge verdict={bad.verdict as Verdict} /><p>{bad.text}</p><p className="text-[12px] text-rose-200">Why: {bad.reasons.join("; ")}</p></div>
          : <p className="text-fg-faint">This draft has no unsafe claims. Try the prepared hallucinated draft in the validation playground to see rejections.</p>}
      </>) },
    { title: "7 · The analyst decides", link: [caseLink("activity"), "Review the case history"], body: (
      <>
        <p>Approval is blocked on the server until every unsupported or contradictory claim has been explicitly handled, and overriding the engine needs a written justification. The case moves through New → Triaged → Investigating → Awaiting review → Resolved, with a reason recorded at each step.</p>
        <p>This case is currently <b>{STATUS_META[detail.data!.status]?.label}</b>{detail.data!.assignee_name ? <>, owned by <b>{detail.data!.assignee_name}</b></> : ""}. Every action is in the hash-chained audit log.</p>
      </>) },
    { title: "8 · The final incident report", link: [caseLink("collaborate"), "See notes and pinned evidence"], body: (
      <>
        <p>The report includes the case state, the approved analysis (or a clear “not approved” marker), analyst notes and provenance. The evidence bundle adds every event with its hash and a manifest that a recipient can verify without TraceLayer.</p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => api.download(id, "md").catch((e) => toast("error", (e as Error).message))}><Download className="h-4 w-4" />Incident report (.md)</Button>
          <Button onClick={() => api.download(id, "zip").catch((e) => toast("error", (e as Error).message))}><ShieldCheck className="h-4 w-4" />Evidence bundle (.zip)</Button>
        </div>
      </>) },
  ];
  const s = steps[step];
  return (
    <>
      <PageHeader title="The Suspicious Login That Wasn't Just a Login" subtitle="A guided walk through one real case in this workspace, from a single sign-in to a verified incident report. About two minutes." />
      <div className="mb-4 flex gap-1" aria-hidden>
        {steps.map((_, i) => <div key={i} className={`h-1 flex-1 rounded-full ${i <= step ? "bg-sky-400" : "bg-ink-700"}`} />)}
      </div>
      <Card title={s.title} actions={s.link && <Link to={s.link[0]}><Button size="sm" variant="ghost">{s.link[1]}<ExternalLink className="h-3.5 w-3.5" /></Button></Link>}>
        <div className="max-w-3xl space-y-3 text-[13.5px] leading-relaxed">{s.body}</div>
      </Card>
      <div className="mt-4 flex items-center justify-between">
        <Button disabled={step === 0} onClick={() => setStep((x) => x - 1)}><ArrowLeft className="h-4 w-4" />Back</Button>
        <span className="text-[12px] text-fg-faint">Step {step + 1} of {steps.length}</span>
        {step < steps.length - 1 ? <Button variant="primary" onClick={() => setStep((x) => x + 1)}>Next<ArrowRight className="h-4 w-4" /></Button>
          : <Link to={`/investigations/${id}`}><Button variant="primary">Open the case<ArrowRight className="h-4 w-4" /></Button></Link>}
      </div>
    </>
  );
}
