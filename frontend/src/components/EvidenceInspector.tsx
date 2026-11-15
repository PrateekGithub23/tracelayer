// Evidence inspector: a global drawer that shows one event (raw record, hashes,
// ledger position, linked detections) or a list of events (e.g. behind a graph edge
// or a claim's citations). Any component can open it through useInspector().

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileJson, Link2, Pin, ShieldAlert, XCircle } from "lucide-react";
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from "react";
import { Link, useMatch } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useToast } from "./Toast";
import { EVENT_TYPE_COLOR, fmtBytes, fmtTime, shortHash } from "../lib/format";
import type { EventItem } from "../lib/types";
import { Button, Drawer, ErrorState, KV, Pill, SeverityBadge, Spinner } from "./ui";

interface InspectorState { eventId?: string; list?: { title: string; ids: string[] } }
interface InspectorApi { openEvent: (id: string) => void; openEvents: (title: string, ids: string[]) => void }

const Ctx = createContext<InspectorApi>({ openEvent: () => undefined, openEvents: () => undefined });
export const useInspector = () => useContext(Ctx);

export function InspectorProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<InspectorState>({});
  const openEvent = useCallback((id: string) => setState((s) => ({ ...s, eventId: id })), []);
  const openEvents = useCallback((title: string, ids: string[]) => setState({ list: { title, ids } }), []);
  const value = useMemo(() => ({ openEvent, openEvents }), [openEvent, openEvents]);
  const close = () => setState((s) => (s.eventId && s.list ? { list: s.list } : {}));
  return (
    <Ctx.Provider value={value}>
      {children}
      <Drawer open={!!state.eventId || !!state.list} onClose={close}
        title={state.eventId ? "Evidence inspector" : state.list?.title ?? ""}>
        {state.eventId ? (
          <EventPanel id={state.eventId} onBack={state.list ? () => setState({ list: state.list }) : undefined} />
        ) : state.list ? (
          <EventList ids={state.list.ids} onPick={openEvent} />
        ) : null}
      </Drawer>
    </Ctx.Provider>
  );
}

export function EventTypeDot({ type }: { type: string }) {
  return <span className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ background: EVENT_TYPE_COLOR[type] ?? "#475569" }} />;
}

export function eventSummary(e: Pick<EventItem, "event_type" | "outcome" | "username" | "host" | "src_ip" | "dst_ip" | "bytes_out" | "process">): string {
  switch (e.event_type) {
    case "auth.login":
      return `${e.outcome === "failure" ? "Failed" : "Successful"} login · ${e.username ?? "?"} → ${e.host ?? "?"}${e.src_ip ? ` from ${e.src_ip}` : ""}`;
    case "process.start":
      return `${e.process ?? "process"} on ${e.host ?? "?"} by ${e.username ?? "?"}`;
    case "network.flow":
      return `${e.host ?? "?"} → ${e.dst_ip ?? "?"} · ${fmtBytes(e.bytes_out)}`;
    case "iam.change":
      return `Group change on ${e.host ?? "?"} by ${e.username ?? "?"}`;
    case "log.cleared":
      return `Log cleared on ${e.host ?? "?"} by ${e.username ?? "?"}`;
    default:
      return `${e.event_type} · ${e.host ?? e.username ?? ""}`;
  }
}

function EventList({ ids, onPick }: { ids: string[]; onPick: (id: string) => void }) {
  const shown = ids.slice(0, 200);
  return (
    <div>
      <p className="mb-3 text-xs text-fg-muted">{ids.length} event(s){ids.length > 200 ? " · showing first 200" : ""}. Select one to inspect the raw record and its provenance.</p>
      <ul className="divide-y divide-ink-700 rounded-lg border border-ink-700">
        {shown.map((id) => <EventRow key={id} id={id} onPick={onPick} />)}
      </ul>
    </div>
  );
}

function EventRow({ id, onPick }: { id: string; onPick: (id: string) => void }) {
  const q = useQuery({ queryKey: ["event", id], queryFn: () => api.event(id), staleTime: 60_000 });
  return (
    <li>
      <button onClick={() => onPick(id)} className="flex w-full items-center gap-3 px-3 py-2 text-left text-[13px] hover:bg-ink-800">
        {q.data ? <EventTypeDot type={q.data.event_type} /> : <span className="h-2 w-2" />}
        <span className="w-36 shrink-0 font-mono text-[11px] text-fg-faint">{q.data ? fmtTime(q.data.timestamp) : "…"}</span>
        <span className="truncate">{q.data ? eventSummary(q.data) : id}</span>
      </button>
    </li>
  );
}

/** Pins the event to the case currently open in the workspace (only shown on a case page, for analysts). */
function PinButton({ eventId }: { eventId: string }) {
  const match = useMatch("/investigations/:id");
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const invId = match?.params.id;
  const pin = useMutation({
    mutationFn: () => api.pin(invId!, eventId, window.prompt("Why is this event important? (optional)") ?? undefined),
    onSuccess: () => { toast("success", "Pinned to the case"); qc.invalidateQueries({ queryKey: ["pins", invId] }); qc.invalidateQueries({ queryKey: ["activity", invId] }); },
    onError: (err) => toast(err instanceof ApiError && err.status === 409 ? "info" : "error", (err as Error).message),
  });
  if (!invId || !can("evidence:pin")) return null;
  return <Button size="sm" onClick={() => pin.mutate()} disabled={pin.isPending}><Pin className="h-3.5 w-3.5" />Pin to this case</Button>;
}

function EventPanel({ id, onBack }: { id: string; onBack?: () => void }) {
  const q = useQuery({ queryKey: ["event", id], queryFn: () => api.event(id) });
  const verify = useQuery({ queryKey: ["verify", id], queryFn: () => api.verifyEvent(id) });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const e = q.data!;
  const injected = e.tags.includes("llm_injection_suspected");
  return (
    <div className="space-y-5">
      {onBack && <Button size="sm" variant="ghost" onClick={onBack}>← Back to list</Button>}
      <div className="flex items-start gap-3">
        <EventTypeDot type={e.event_type} />
        <div className="min-w-0">
          <div className="font-medium">{eventSummary(e)}</div>
          <div className="mt-0.5 font-mono text-xs text-fg-faint">{e.id} · {fmtTime(e.timestamp)} UTC</div>
        </div>
      </div>

      <div className={`flex items-start gap-2 rounded-lg px-3 py-2.5 text-[13px] ring-1 ${verify.data?.ok === false ? "bg-rose-500/10 text-rose-200 ring-rose-500/30" : "bg-emerald-500/10 text-emerald-200 ring-emerald-500/25"}`}>
        {verify.isLoading ? <Spinner label="Verifying" /> : verify.data?.ok ? (
          <><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /><span>Integrity verified: raw record matches its SHA-256 and re-parsing reproduces every normalised field.</span></>
        ) : (
          <><XCircle className="mt-0.5 h-4 w-4 shrink-0" /><span>Integrity check failed: {verify.data?.issues.join("; ")}</span></>
        )}
      </div>

      <PinButton eventId={e.id} />

      {injected && (
        <div className="flex items-start gap-2 rounded-lg bg-amber-400/10 px-3 py-2.5 text-[13px] text-amber-100 ring-1 ring-amber-400/30">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          This event contains text addressed to AI systems. It is passed to models strictly as quoted data, and any
          claim relying on it is downgraded by the integrity engine.
        </div>
      )}

      <dl className="rounded-lg border border-ink-700 px-3 py-1">
        <KV k="Type / outcome" v={<span className="flex gap-1.5"><Pill>{e.event_type}</Pill><Pill>{e.outcome}</Pill></span>} />
        <KV k="User" v={e.username} />
        <KV k="Host" v={e.host} />
        <KV k="Source → dest" v={`${e.src_ip ?? "—"} → ${e.dst_ip ?? "—"}${e.dst_port ? `:${e.dst_port}` : ""}`} mono />
        {e.country && <KV k="Geo" v={e.country} />}
        {e.process && <KV k="Process" v={e.process} mono />}
        {e.command_line && <KV k="Command line" v={<code className="whitespace-pre-wrap break-all">{e.command_line}</code>} mono />}
        {e.bytes_out ? <KV k="Bytes out" v={`${fmtBytes(e.bytes_out)} (${e.bytes_out.toLocaleString()})`} /> : null}
        {Object.keys(e.attributes).length > 0 && <KV k="Attributes" v={<code>{JSON.stringify(e.attributes)}</code>} mono />}
        {e.tags.length > 0 && <KV k="Tags" v={e.tags.map((t) => <Pill key={t}>{t}</Pill>)} />}
      </dl>

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-fg-faint"><Link2 className="h-3.5 w-3.5" /> Provenance</h3>
        <dl className="rounded-lg border border-ink-700 px-3 py-1">
          <KV k="Source / parser" v={`${e.source} · ${e.parser}`} />
          <KV k="Content SHA-256" v={e.content_hash} mono />
          <KV k="Ingest batch" v={`#${e.batch.seq} · ${e.batch.id}`} mono />
          <KV k="Batch Merkle root" v={shortHash(e.batch.merkle_root, 24)} mono />
          <KV k="Ledger chain hash" v={shortHash(e.batch.chain_hash, 24)} mono />
          <KV k="Ingested" v={`${fmtTime(e.ingested_at)} UTC`} />
        </dl>
      </section>

      {(e.detections.length > 0 || e.investigations.length > 0) && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-faint">Used as evidence in</h3>
          <div className="space-y-1.5">
            {e.detections.map((d) => (
              <div key={d.id} className="flex items-center gap-2 text-[13px]"><SeverityBadge severity={d.severity} /> {d.rule_name}</div>
            ))}
            {e.investigations.map((i) => (
              <Link key={i.id} to={`/investigations/${i.id}`} className="block text-[13px] text-sky-300 hover:underline">
                {i.title} <span className="text-fg-faint">({i.role})</span>
              </Link>
            ))}
          </div>
        </section>
      )}

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-fg-faint"><FileJson className="h-3.5 w-3.5" /> Raw record (as received)</h3>
        {(e as any).raw_omitted ? (
          <p className="rounded-lg border border-ink-700 bg-ink-950 p-3 text-[12px] text-fg-faint">Omitted from the public demo to keep it small (this is a context event from a public dataset). The full application stores and shows every raw record; the content hash above was computed from it.</p>
        ) : <pre className="max-h-72 overflow-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[11.5px] leading-relaxed text-fg-muted">{JSON.stringify(e.raw, null, 2)}</pre>}
      </section>
    </div>
  );
}
