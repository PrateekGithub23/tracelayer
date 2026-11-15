// Detection list plus the rule catalogue (what each rule looks for, with ATT&CK mapping).

import { useQuery } from "@tanstack/react-query";
import { ScanSearch } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useInspector } from "../components/EvidenceInspector";
import { Button, Card, EmptyState, ErrorState, PageHeader, Pill, Select, SeverityBadge, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, TACTIC_LABEL } from "../lib/format";
import type { Severity } from "../lib/types";

export default function Detections() {
  const { openEvents } = useInspector();
  const [severity, setSeverity] = useState("");
  const [unassigned, setUnassigned] = useState(false);
  const dets = useQuery({ queryKey: ["detections", severity, unassigned], queryFn: () => api.detections({ severity, unassigned }) });
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules, staleTime: Infinity });
  return (
    <>
      <PageHeader title="Detections" subtitle="Rule hits over normalised telemetry. Deduplicated by rule, entity and burst, so re-running never duplicates." />
      <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
        <Card pad={false} title="Detections" actions={
          <div className="flex items-end gap-2">
            <Select label="" value={severity} onChange={setSeverity} className="w-36" options={[{ value: "", label: "All severities" },
              ...(["critical", "high", "medium", "low"] as Severity[]).map((s) => ({ value: s, label: s }))]} />
            <Button size="sm" variant={unassigned ? "primary" : "default"} onClick={() => setUnassigned((u) => !u)}>Unassigned only</Button>
          </div>}>
          {dets.isLoading ? <Spinner /> : dets.error ? <div className="p-4"><ErrorState error={dets.error} /></div> : !dets.data?.length ? (
            <EmptyState title="No detections" icon={<ScanSearch className="h-5 w-5" />}>Run the pipeline after ingesting telemetry.</EmptyState>
          ) : (
            <ul className="divide-y divide-ink-700">
              {dets.data.map((d) => (
                <li key={d.id} className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={d.severity} /><span className="text-[13.5px] font-medium">{d.rule_name}</span><Pill>{d.technique}</Pill></div>
                    <p className="mt-1 text-[12.5px] text-fg-muted">{d.summary}</p>
                    <p className="mt-1 text-[11.5px] text-fg-faint">
                      {fmtTime(d.first_seen)} UTC · {TACTIC_LABEL(d.tactic)} ·{" "}
                      {d.investigation_id ? <Link className="text-sky-300 hover:underline" to={`/investigations/${d.investigation_id}`}>open investigation</Link> : "not correlated"}
                    </p>
                  </div>
                  <Button size="sm" onClick={async () => {
                    const page = await api.events({ detection_id: d.id, limit: 500, order: "asc" });
                    openEvents(d.rule_name, page.items.map((e) => e.id));
                  }}>{d.evidence_count} events</Button>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Rule catalogue" subtitle="Explainable, ATT&CK-mapped rules" pad={false}>
          <ul className="divide-y divide-ink-700">
            {rules.data?.map((r) => (
              <li key={r.id} className="px-4 py-3 text-[12.5px]">
                <div className="flex items-center gap-2"><span className="font-mono text-[11px] text-sky-300">{r.id}</span><span className="font-medium">{r.name}</span></div>
                <p className="mt-1 text-fg-muted">{r.description}</p>
                <div className="mt-1.5 flex gap-1.5"><Pill>{TACTIC_LABEL(r.tactic)}</Pill><Pill>{r.technique}</Pill></div>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  );
}
