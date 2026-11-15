// Case collaboration UI: workflow controls, activity feed, comments/notes and pinned evidence.
//
// Concurrency: every update sends the version the analyst was looking at. If someone else changed the
// case in between, the server answers 409; we tell the analyst, show the fresh state, and let them retry
// instead of silently overwriting the other person's change.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Hash, MessageSquare, NotebookPen, Pencil, Pin, PinOff, Trash2, UserPlus } from "lucide-react";
import { useState } from "react";
import { api, ApiError, type CasePatch } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ACTION_LABEL, ACTIVITY_LABEL, PRIORITY_META, RESOLUTIONS, STATUS_META, TRANSITIONS } from "../lib/cases";
import { fmtRelative, fmtTime, shortHash } from "../lib/format";
import type { InvestigationDetail } from "../lib/types";
import { useInspector } from "./EvidenceInspector";
import { useToast } from "./Toast";
import { Button, Card, EmptyState, ErrorState, Modal, Select, Spinner, TextArea } from "./ui";

function useCaseMutation(inv: InvestigationDetail) {
  const qc = useQueryClient();
  const toast = useToast();
  const refresh = () => {
    for (const k of ["investigation", "activity", "investigations", "queues"]) qc.invalidateQueries({ queryKey: [k] });
  };
  return useMutation({
    mutationFn: (body: Omit<CasePatch, "expected_version">) => api.updateCase(inv.id, { expected_version: inv.version, ...body }),
    onSuccess: () => { toast("success", "Case updated"); refresh(); },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409 && typeof e.detail === "object") {
        toast("error", "Someone else changed this case while you were looking at it. The latest version is shown; review it and try again.");
      } else toast("error", e instanceof ApiError ? e.message : "Update failed");
      refresh();
    },
  });
}

export function CaseControls({ inv }: { inv: InvestigationDetail }) {
  const { me, can } = useAuth();
  const dir = useQuery({ queryKey: ["directory"], queryFn: api.directory, staleTime: 60_000 });
  const m = useCaseMutation(inv);
  const [target, setTarget] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [resolution, setResolution] = useState(inv.resolution ?? "true_positive");
  const [reviewer, setReviewer] = useState(inv.reviewer_id ?? "");
  const uid = me?.user.id;
  const manageAny = can("investigations:manage_any");
  const writable = can("investigations:write") && (manageAny || !inv.assignee_id || inv.assignee_id === uid ||
    (inv.status === "awaiting_review" && inv.reviewer_id === uid));
  const assignable = (dir.data ?? []).filter((u) => u.assignable);
  const reviewers = assignable.filter((u) => u.id !== inv.assignee_id);
  // Leaving review is the reviewer's decision (segregation of duties), so others see no transition buttons.
  const reviewLocked = inv.status === "awaiting_review" && !manageAny && uid !== inv.reviewer_id;
  const next = reviewLocked ? [] : TRANSITIONS[inv.status] ?? [];
  const submit = () => {
    if (!target) return;
    const body: Omit<CasePatch, "expected_version"> = { status: target, reason };
    if (target === "resolved") body.resolution = resolution;
    if (target === "awaiting_review") body.reviewer_id = reviewer;
    m.mutate(body, { onSuccess: () => { setTarget(null); setReason(""); } });
  };

  return (
    <div className="space-y-3 rounded-xl border border-ink-700 bg-ink-900/50 p-3.5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[12.5px]">
        <span title={STATUS_META[inv.status]?.help} className={`rounded-md px-2 py-0.5 text-[11.5px] font-semibold ring-1 ${STATUS_META[inv.status]?.tone}`}>{STATUS_META[inv.status]?.label ?? inv.status}</span>
        {inv.resolution && <span className="text-fg-muted">resolution: <b className="text-fg">{inv.resolution.replaceAll("_", " ")}</b></span>}
        <span className="text-fg-muted">owner: <b className="text-fg">{inv.assignee_name ?? "unassigned"}</b></span>
        {inv.reviewer_name && <span className="text-fg-muted">reviewer: <b className="text-fg">{inv.reviewer_name}</b></span>}
        {inv.reopen_count > 0 && <span className="text-amber-300">reopened {inv.reopen_count}×</span>}
        <span className="font-mono text-[11px] text-fg-faint" title="Optimistic-locking version: changes are rejected if someone else saved first">v{inv.version}</span>
      </div>
      {can("investigations:write") ? (
        <div className="flex flex-wrap items-end gap-2">
          {!inv.assignee_id && <Button size="sm" variant="primary" onClick={() => m.mutate({ assignee_id: uid })}><UserPlus className="h-3.5 w-3.5" />Assign to me</Button>}
          <Select label="Priority" value={inv.priority} onChange={(v) => m.mutate({ priority: v })} className={`w-32 ${!writable ? "pointer-events-none opacity-50" : ""}`}
            options={Object.entries(PRIORITY_META).map(([value, p]) => ({ value, label: p.label }))} />
          {(manageAny || inv.assignee_id === uid || !inv.assignee_id) && (
            <Select label="Owner" value={inv.assignee_id ?? ""} onChange={(v) => m.mutate({ assignee_id: v })} className="w-44"
              options={[{ value: "", label: "Unassigned" }, ...assignable.map((u) => ({ value: u.id, label: u.display_name }))]} />
          )}
          {writable && next.map((t) => (
            <Button key={t} size="sm" variant={t === "resolved" ? "success" : "default"} onClick={() => { setTarget(t); setReason(""); }}>{ACTION_LABEL(inv.status, t)}</Button>
          ))}
          {!writable && <span className="text-[12px] text-fg-faint">This case belongs to {inv.assignee_name ?? "someone else"}. You can comment; an administrator can reassign it.</span>}
        </div>
      ) : <p className="text-[12px] text-fg-faint">Viewers can read cases but not change them.</p>}

      <Modal open={!!target} onClose={() => setTarget(null)} title={target ? `${ACTION_LABEL(inv.status, target)}: ${STATUS_META[inv.status]?.label} → ${STATUS_META[target]?.label}` : ""}
        footer={<><Button onClick={() => setTarget(null)}>Cancel</Button><Button variant="primary" disabled={reason.trim().length < 3 || (target === "awaiting_review" && !reviewer) || m.isPending} onClick={submit}>Confirm</Button></>}>
        <div className="space-y-3">
          {target === "awaiting_review" && (
            <Select label="Reviewer (must be someone else)" value={reviewer} onChange={setReviewer}
              options={[{ value: "", label: "Choose a reviewer" }, ...reviewers.map((u) => ({ value: u.id, label: u.display_name }))]} />
          )}
          {target === "resolved" && <Select label="Resolution" value={resolution} onChange={setResolution} options={RESOLUTIONS} />}
          <TextArea label="Why? (recorded in the audit trail)" value={reason} onChange={setReason} rows={3}
            placeholder={target === "investigating" && (inv.status === "resolved" || inv.status === "closed") ? "What new information justifies reopening?" : "Brief justification"} />
          {target === "closed" && <p className="text-[12px] text-fg-faint">Closing never deletes or alters evidence. The case can be reopened later.</p>}
        </div>
      </Modal>
    </div>
  );
}

export function ActivityFeed({ invId }: { invId: string }) {
  const q = useQuery({ queryKey: ["activity", invId], queryFn: () => api.activity(invId) });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} />;
  if (!q.data!.length) return <EmptyState title="No activity yet" />;
  return (
    <Card pad={false} title="Case activity" subtitle="Assembled from the hash-chained audit log: who did what, when, and why.">
      <ol className="relative divide-y divide-ink-700">
        {q.data!.map((a) => {
          const ch = a.details?.changes ?? {};
          const actor = a.actor.split(" (")[0];
          return (
            <li key={a.id} className="grid gap-1 px-4 py-3 text-[13px] md:grid-cols-[150px_1fr_auto]">
              <span className="font-mono text-[11.5px] text-fg-faint" title={`${fmtTime(a.timestamp)} UTC`}>{fmtRelative(a.timestamp)}</span>
              <div className="min-w-0">
                <span className="font-medium">{actor}</span> <span className="text-fg-muted">{ACTIVITY_LABEL[a.action] ?? a.action}</span>
                {ch.status && <span className="text-fg-muted">: {STATUS_META[ch.status[0]]?.label ?? ch.status[0]} → <b className="text-fg">{STATUS_META[ch.status[1]]?.label ?? ch.status[1]}</b></span>}
                {ch.priority && <span className="text-fg-muted">: priority {ch.priority[0]} → <b className="text-fg">{ch.priority[1]}</b></span>}
                {ch.assignee_id && <span className="text-fg-muted">: {ch.assignee_id[1] ? "assigned" : "unassigned"}</span>}
                {ch.reviewer_id && <span className="text-fg-muted">, reviewer set</span>}
                {a.details?.reason && <div className="mt-1 rounded-md bg-ink-800/70 px-2.5 py-1.5 text-[12.5px] text-fg-muted">“{a.details.reason}”</div>}
                {a.comment && <div className="mt-1 whitespace-pre-wrap rounded-md bg-ink-800/70 px-2.5 py-1.5 text-[12.5px] text-fg-muted">{a.comment}</div>}
                {a.details?.note && !a.details?.reason && <div className="mt-1 text-[12px] text-fg-faint">note: {String(a.details.note)}</div>}
                {a.details?.format && <span className="text-fg-faint"> ({a.details.format})</span>}
              </div>
              <span className="flex items-center gap-1 font-mono text-[10.5px] text-fg-faint" title={a.entry_hash}><Hash className="h-3 w-3" />{shortHash(a.entry_hash, 10)}</span>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

export function CommentsPanel({ invId }: { invId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const { me, can } = useAuth();
  const q = useQuery({ queryKey: ["comments", invId], queryFn: () => api.comments(invId) });
  const [kind, setKind] = useState<"comment" | "note">("comment");
  const [text, setText] = useState("");
  const [editing, setEditing] = useState<{ id: string; body: string } | null>(null);
  const done = () => { qc.invalidateQueries({ queryKey: ["comments", invId] }); qc.invalidateQueries({ queryKey: ["activity", invId] }); };
  const onError = (e: unknown) => toast("error", (e as Error).message);
  const add = useMutation({ mutationFn: () => api.addComment(invId, kind, text), onSuccess: () => { setText(""); done(); }, onError });
  const edit = useMutation({ mutationFn: (x: { id: string; body: string }) => api.editComment(invId, x.id, x.body), onSuccess: () => { setEditing(null); done(); }, onError });
  const del = useMutation({ mutationFn: (id: string) => api.deleteComment(invId, id), onSuccess: done, onError });
  const notes = (q.data ?? []).filter((c) => c.kind === "note" && !c.deleted);
  const thread = (q.data ?? []).filter((c) => c.kind === "comment");

  const item = (c: NonNullable<typeof q.data>[number]) => (
    <li key={c.id} className="px-4 py-3 text-[13px]">
      <div className="flex items-center justify-between gap-2">
        <span><b>{c.author_name ?? "?"}</b> <span className="text-[11.5px] text-fg-faint">{fmtRelative(c.created_at)}{c.edited_at && " · edited"}</span></span>
        {!c.deleted && c.author_id === me?.user.id && (
          <span className="flex gap-1">
            <button aria-label="Edit" className="rounded p-1 text-fg-faint hover:bg-ink-700 hover:text-fg" onClick={() => setEditing({ id: c.id, body: c.body ?? "" })}><Pencil className="h-3.5 w-3.5" /></button>
            <button aria-label="Delete" className="rounded p-1 text-fg-faint hover:bg-ink-700 hover:text-rose-300" onClick={() => del.mutate(c.id)}><Trash2 className="h-3.5 w-3.5" /></button>
          </span>
        )}
      </div>
      {editing?.id === c.id ? (
        <div className="mt-2 space-y-2"><TextArea value={editing.body} onChange={(b) => setEditing({ id: c.id, body: b })} />
          <div className="flex gap-2"><Button size="sm" variant="primary" onClick={() => edit.mutate(editing)}>Save</Button><Button size="sm" onClick={() => setEditing(null)}>Cancel</Button></div></div>
      ) : c.deleted ? <p className="mt-1 italic text-fg-faint">deleted (a hash of the original text remains in the audit log)</p> :
        <p className="mt-1 whitespace-pre-wrap text-fg-muted">{c.body}</p>}
    </li>
  );

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
      <Card pad={false} title={<span className="flex items-center gap-2"><MessageSquare className="h-4 w-4" />Discussion</span>}>
        {q.isLoading ? <Spinner /> : !thread.length ? <EmptyState title="No comments yet" /> : <ul className="divide-y divide-ink-700">{thread.map(item)}</ul>}
        {can("comments:write") && (
          <form className="space-y-2 border-t border-ink-700 p-4" onSubmit={(e) => { e.preventDefault(); if (text.trim()) add.mutate(); }}>
            <TextArea value={text} onChange={setText} placeholder={kind === "note" ? "A durable investigation note (findings, hypotheses, next steps)" : "Comment for the team"} />
            <div className="flex items-center justify-between">
              <Select label="" value={kind} onChange={(v) => setKind(v as "comment" | "note")} className="w-40" options={[{ value: "comment", label: "Comment" }, { value: "note", label: "Investigation note" }]} />
              <Button type="submit" variant="primary" disabled={!text.trim() || add.isPending}>Post</Button>
            </div>
          </form>
        )}
      </Card>
      <Card pad={false} title={<span className="flex items-center gap-2"><NotebookPen className="h-4 w-4" />Investigation notes</span>} subtitle="Included in exported reports.">
        {!notes.length ? <EmptyState title="No notes" /> : <ul className="divide-y divide-ink-700">{notes.map(item)}</ul>}
      </Card>
    </div>
  );
}

export function PinsPanel({ invId }: { invId: string }) {
  const qc = useQueryClient();
  const { can } = useAuth();
  const { openEvent } = useInspector();
  const q = useQuery({ queryKey: ["pins", invId], queryFn: () => api.pins(invId) });
  const unpin = useMutation({ mutationFn: (eid: string) => api.unpin(invId, eid), onSuccess: () => { qc.invalidateQueries({ queryKey: ["pins", invId] }); qc.invalidateQueries({ queryKey: ["activity", invId] }); } });
  return (
    <Card pad={false} title={<span className="flex items-center gap-2"><Pin className="h-4 w-4" />Pinned evidence</span>}
      subtitle="Key events an analyst has flagged for this case. Pin events from the evidence inspector (click any event).">
      {q.isLoading ? <Spinner /> : !q.data?.length ? <EmptyState title="Nothing pinned yet">Open an event and choose “Pin to case”.</EmptyState> : (
        <ul className="divide-y divide-ink-700">
          {q.data.map((p) => (
            <li key={p.event_id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
              <button className="min-w-0 text-left" onClick={() => openEvent(p.event_id)}>
                <span className="font-mono text-[12px] text-sky-200">{p.event_id}</span> <span className="text-fg-muted">{p.event_type} · {p.host ?? "—"} · {p.username ?? "—"} · {fmtTime(p.timestamp)}</span>
                {p.note && <div className="text-[12px] text-fg-faint">“{p.note}” by {p.added_by}</div>}
              </button>
              {can("evidence:pin") && <Button size="sm" variant="ghost" onClick={() => unpin.mutate(p.event_id)}><PinOff className="h-3.5 w-3.5" />Unpin</Button>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
