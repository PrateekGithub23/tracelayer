// Event table backed by the keyset-paginated /api/events endpoint.
// "Load more" appends the next page using the server's cursor (no OFFSET scans).

import { useInfiniteQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { api, type EventQuery } from "../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../lib/format";
import { EventTypeDot, useInspector } from "./EvidenceInspector";
import { Button, EmptyState, ErrorState, Spinner } from "./ui";

export function EventTable({ query, refByEvent }: { query: EventQuery; refByEvent?: Map<string, string> }) {
  const { openEvent } = useInspector();
  const q = useInfiniteQuery({
    queryKey: ["events", query],
    queryFn: ({ pageParam }) => api.events({ ...query, limit: 100, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  if (q.isLoading) return <Spinner label="Querying events" />;
  if (q.error) return <div className="p-4"><ErrorState error={q.error} onRetry={() => q.refetch()} /></div>;
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];
  const total = q.data?.pages[0]?.total ?? 0;
  if (!rows.length) return <EmptyState title="No events match these filters" />;
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[960px] text-left text-[12.5px]">
          <thead className="sticky top-0 bg-ink-850 text-[11px] uppercase tracking-wider text-fg-faint">
            <tr className="border-b border-ink-700">
              {refByEvent && <th className="px-3 py-2 font-medium">Ref</th>}
              <th className="px-3 py-2 font-medium">Time (UTC)</th>
              <th className="px-3 py-2 font-medium">Type</th>
              <th className="px-3 py-2 font-medium">Outcome</th>
              <th className="px-3 py-2 font-medium">User</th>
              <th className="px-3 py-2 font-medium">Host</th>
              <th className="px-3 py-2 font-medium">Source → Dest</th>
              <th className="px-3 py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700/70">
            {rows.map((e) => (
              <tr key={e.id} onClick={() => openEvent(e.id)} className="cursor-pointer hover:bg-ink-800/60">
                {refByEvent && <td className="px-3 py-2 font-mono text-[11px] text-sky-300">{refByEvent.get(e.id) ?? ""}</td>}
                <td className="whitespace-nowrap px-3 py-2 font-mono text-[11.5px] text-fg-muted">{fmtTime(e.timestamp)}</td>
                <td className="whitespace-nowrap px-3 py-2"><span className="flex items-center gap-2"><EventTypeDot type={e.event_type} />{e.event_type}</span></td>
                <td className={`px-3 py-2 ${e.outcome === "failure" ? "text-orange-300" : "text-fg-muted"}`}>{e.outcome}</td>
                <td className="px-3 py-2">{e.username ?? "—"}</td>
                <td className="px-3 py-2">{e.host ?? "—"}</td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-[11.5px] text-fg-muted">{e.src_ip ?? "—"} → {e.dst_ip ?? "—"}</td>
                <td className="max-w-[360px] truncate px-3 py-2 text-fg-muted">
                  {e.tags.includes("llm_injection_suspected") && <ShieldAlert className="mr-1 inline h-3.5 w-3.5 text-amber-300" />}
                  {e.command_line ?? (e.bytes_out ? fmtBytes(e.bytes_out) : (e.attributes as any)?.query ?? (e.attributes as any)?.group ?? e.message ?? "")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between border-t border-ink-700 px-4 py-3 text-xs text-fg-muted">
        <span>Showing {fmtNum(rows.length)} of {fmtNum(total)}</span>
        {q.hasNextPage && <Button size="sm" disabled={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>{q.isFetchingNextPage ? "Loading…" : "Load more"}</Button>}
      </div>
    </div>
  );
}
