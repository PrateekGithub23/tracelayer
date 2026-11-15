// Event explorer. Filters are synced to the URL (shareable, back-button friendly) and
// the dropdown options come from /api/events/facets, i.e. from values actually stored.

import { useQuery } from "@tanstack/react-query";
import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EventTable } from "../components/EventTable";
import { Button, Card, PageHeader, Select, TextInput } from "../components/ui";
import { api, type EventQuery } from "../lib/api";

const KEYS = ["q", "event_type", "host", "user", "ip", "outcome", "tag", "start", "end"] as const;

export default function Events() {
  const [params, setParams] = useSearchParams();
  const facets = useQuery({ queryKey: ["facets"], queryFn: () => api.facets(), staleTime: 30_000 });
  const [text, setText] = useState(params.get("q") ?? "");
  useEffect(() => setText(params.get("q") ?? ""), [params]);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };
  const query: EventQuery = { order: "desc" };
  for (const k of KEYS) {
    const v = params.get(k);
    if (!v) continue;
    if (k === "event_type") query.event_type = [v];
    else if (k === "start" || k === "end") (query as any)[k] = new Date(v).toISOString();
    else (query as any)[k] = v;
  }
  const opts = (name: string) => [{ value: "", label: "Any" }, ...(facets.data?.[name] ?? []).map((f) => ({ value: f.value, label: `${f.value} (${f.count.toLocaleString()})` }))];
  const active = KEYS.some((k) => params.get(k));

  return (
    <>
      <PageHeader title="Event explorer" subtitle="Query every normalised event. Click a row to inspect the raw record and its provenance." />
      <Card pad={false}>
        <form className="grid gap-3 border-b border-ink-700 p-4 md:grid-cols-2 xl:grid-cols-6" onSubmit={(e) => { e.preventDefault(); set("q", text.trim()); }}>
          <label className="relative xl:col-span-2">
            <span className="text-[11px] font-medium uppercase tracking-wider text-fg-faint">Search</span>
            <Search className="absolute left-3 top-[30px] h-4 w-4 text-fg-faint" />
            <input value={text} onChange={(e) => setText(e.target.value)} placeholder="command line, user, host, IP, event id…"
              className="mt-1 h-9 w-full rounded-lg border border-ink-600 bg-ink-800 pl-9 pr-3 text-[13px] focus:border-sky-500 focus:outline-none" />
          </label>
          <Select label="Event type" value={params.get("event_type") ?? ""} onChange={(v) => set("event_type", v)} options={opts("event_type")} />
          <Select label="Outcome" value={params.get("outcome") ?? ""} onChange={(v) => set("outcome", v)} options={opts("outcome")} />
          <Select label="Host" value={params.get("host") ?? ""} onChange={(v) => set("host", v)} options={opts("host")} />
          <Select label="User" value={params.get("user") ?? ""} onChange={(v) => set("user", v)} options={opts("username")} />
          <TextInput label="IP (src or dst)" value={params.get("ip") ?? ""} onChange={(v) => set("ip", v)} placeholder="203.0.113.45" mono />
          <TextInput label="From (UTC)" type="datetime-local" value={params.get("start") ?? ""} onChange={(v) => set("start", v)} />
          <TextInput label="To (UTC)" type="datetime-local" value={params.get("end") ?? ""} onChange={(v) => set("end", v)} />
          <Select label="Tag" value={params.get("tag") ?? ""} onChange={(v) => set("tag", v)} options={[{ value: "", label: "Any" }, { value: "llm_injection_suspected", label: "Prompt-injection suspected" }]} />
          <div className="flex items-end gap-2 xl:col-span-2">
            <Button type="submit" variant="primary"><Search className="h-4 w-4" /> Search</Button>
            {active && <Button variant="ghost" onClick={() => { setText(""); setParams(new URLSearchParams()); }}><X className="h-4 w-4" /> Clear filters</Button>}
          </div>
        </form>
        <EventTable query={query} />
      </Card>
    </>
  );
}
