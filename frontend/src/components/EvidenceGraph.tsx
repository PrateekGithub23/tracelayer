// Interactive entity graph (Cytoscape.js). Nodes are users / hosts / IPs; edges are
// aggregated from real events and carry their event ids, so clicking an edge opens
// exactly the evidence behind it. Edges that are detection evidence are highlighted.

import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { Crosshair, Maximize2, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { fmtBytes, fmtTime } from "../lib/format";
import type { Graph, GraphEdge, GraphNode } from "../lib/types";
import { useInspector } from "./EvidenceInspector";
import { Button, EmptyState, Pill } from "./ui";

const NODE_COLOR: Record<string, string> = { user: "#38bdf8", host: "#a78bfa", ip: "#64748b" };

function elements(g: Graph, evidenceOnly: boolean): ElementDefinition[] {
  const edges = evidenceOnly ? g.edges.filter((e) => e.flagged) : g.edges;
  const used = new Set(edges.flatMap((e) => [e.source, e.target]));
  const nodes = g.nodes.filter((n) => !evidenceOnly || used.has(n.id));
  return [
    ...nodes.map((n) => ({
      data: { id: n.id, label: n.label, type: n.type, weight: Math.log2(n.events + 1), flagged: n.detections.length > 0 ? 1 : 0,
        color: n.type === "ip" && n.external ? "#fb7185" : NODE_COLOR[n.type] ?? "#64748b" },
    })),
    ...edges.map((e) => ({
      data: { id: e.id, source: e.source, target: e.target, relation: e.relation, width: 1 + Math.log2(e.count + 1),
        flagged: e.flagged ? 1 : 0, label: e.relation + (e.count > 1 ? ` ×${e.count}` : "") },
    })),
  ];
}

export function EvidenceGraph({ graph }: { graph: Graph }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const { openEvents } = useInspector();
  const [evidenceOnly, setEvidenceOnly] = useState(true);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const edgesById = useMemo(() => new Map(graph.edges.map((e) => [e.id, e])), [graph]);
  const nodesById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

  useEffect(() => {
    if (!ref.current) return;
    const instance = cytoscape({
      container: ref.current,
      elements: elements(graph, evidenceOnly),
      wheelSensitivity: 0.25,
      minZoom: 0.2,
      maxZoom: 3,
      style: [
        { selector: "node", style: {
          "background-color": "data(color)", label: "data(label)", color: "#cbd5e1", "font-size": 10, "font-family": "JetBrains Mono, monospace",
          "text-valign": "bottom", "text-margin-y": 5, width: "mapData(weight, 0, 10, 16, 42)", height: "mapData(weight, 0, 10, 16, 42)",
          "border-width": 2, "border-color": "#0a0e14", "text-outline-color": "#0a0e14", "text-outline-width": 2 } },
        { selector: "node[type = 'host']", style: { shape: "round-rectangle" } },
        { selector: "node[type = 'ip']", style: { shape: "diamond" } },
        { selector: "node[flagged = 1]", style: { "border-color": "#fb923c", "border-width": 2.5 } },
        { selector: "edge", style: {
          width: "data(width)", "line-color": "#334155", "target-arrow-color": "#334155", "target-arrow-shape": "triangle",
          "curve-style": "bezier", "arrow-scale": 0.8, opacity: 0.8 } },
        { selector: "edge[flagged = 1]", style: { "line-color": "#fb923c", "target-arrow-color": "#fb923c", opacity: 0.95 } },
        { selector: "edge:selected, edge.hover", style: { label: "data(label)", "font-size": 9, color: "#e2e8f0",
          "text-background-color": "#0a0e14", "text-background-opacity": 0.9, "text-background-padding": "2px" } },
        { selector: "node:selected", style: { "border-color": "#f8fafc", "border-width": 3 } },
        { selector: ".faded", style: { opacity: 0.15 } },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 90, padding: 30 } as cytoscape.LayoutOptions,
    });
    instance.on("mouseover", "edge", (e) => e.target.addClass("hover"));
    instance.on("mouseout", "edge", (e) => e.target.removeClass("hover"));
    instance.on("tap", "edge", (e) => {
      const edge: GraphEdge | undefined = edgesById.get(e.target.id());
      if (edge) openEvents(`${edge.source.split(":")[1]} ${edge.relation} ${edge.target.split(":")[1]}`, edge.event_ids);
    });
    instance.on("tap", "node", (e) => {
      const n = e.target;
      setSelected(nodesById.get(n.id()) ?? null);
      instance.elements().addClass("faded");
      n.closedNeighborhood().removeClass("faded");
    });
    instance.on("tap", (e) => {
      if (e.target === instance) {
        setSelected(null);
        instance.elements().removeClass("faded");
      }
    });
    cy.current = instance;
    return () => instance.destroy();
  }, [graph, evidenceOnly, edgesById, nodesById, openEvents]);

  if (!graph.nodes.length) return <EmptyState title="No entity relationships in scope" />;

  const connected = selected ? graph.edges.filter((e) => e.source === selected.id || e.target === selected.id) : [];
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_300px]">
      <div className="relative overflow-hidden rounded-xl border border-ink-700 bg-[radial-gradient(circle_at_center,#111823_0%,#0a0e14_70%)]">
        <div className="absolute left-3 top-3 z-10 flex flex-wrap gap-2">
          <Button size="sm" variant={evidenceOnly ? "primary" : "default"} onClick={() => setEvidenceOnly((v) => !v)}>
            <Crosshair className="h-3.5 w-3.5" /> {evidenceOnly ? "Detection evidence only" : "All relationships"}
          </Button>
          <Button size="sm" onClick={() => cy.current?.fit(undefined, 30)}><Maximize2 className="h-3.5 w-3.5" /> Fit</Button>
          <Button size="sm" onClick={() => cy.current?.layout({ name: "cose", animate: true } as cytoscape.LayoutOptions).run()}><RefreshCw className="h-3.5 w-3.5" /> Re-layout</Button>
        </div>
        <div className="absolute bottom-3 left-3 z-10 flex flex-wrap gap-3 rounded-lg bg-ink-950/80 px-3 py-2 text-[11px] text-fg-muted ring-1 ring-ink-700">
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-sky-400" />user</span>
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-violet-400" />host</span>
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rotate-45 bg-slate-500" />internal IP</span>
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rotate-45 bg-rose-400" />external IP</span>
          <span className="flex items-center gap-1.5"><span className="h-0.5 w-4 bg-orange-400" />detection evidence</span>
        </div>
        <div ref={ref} className="h-[560px] w-full" data-testid="evidence-graph" />
      </div>
      <aside className="rounded-xl border border-ink-700 bg-ink-850/80 p-4 text-[13px]">
        {selected ? (
          <div className="space-y-3">
            <div>
              <Pill>{selected.type}</Pill>
              <div className="mt-2 break-all font-mono text-sm">{selected.label}</div>
              <div className="mt-1 text-xs text-fg-faint">{selected.events} event touch(es) · {selected.detections.length} detection(s)</div>
            </div>
            <ul className="space-y-1.5">
              {connected.map((e) => (
                <li key={e.id}>
                  <button className="w-full rounded-lg border border-ink-700 px-2.5 py-2 text-left hover:border-sky-500/40 hover:bg-ink-800"
                    onClick={() => openEvents(`${e.source.split(":")[1]} ${e.relation} ${e.target.split(":")[1]}`, e.event_ids)}>
                    <div className="flex items-center justify-between gap-2">
                      <span className={e.flagged ? "text-orange-300" : ""}>{e.relation}</span>
                      <span className="text-xs tabular-nums text-fg-faint">×{e.count}</span>
                    </div>
                    <div className="truncate font-mono text-[11px] text-fg-muted">{(e.source === selected.id ? e.target : e.source).split(":")[1]}</div>
                    <div className="mt-0.5 text-[11px] text-fg-faint">
                      {e.failures ? `${e.failures} failed · ` : ""}{e.bytes ? `${fmtBytes(e.bytes)} · ` : ""}{fmtTime(e.first_seen, false)}–{fmtTime(e.last_seen, false)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="space-y-2 text-fg-muted">
            <p className="font-medium text-fg">How to read this graph</p>
            <p>Every edge is aggregated from stored events. Nothing is inferred.</p>
            <p>Click a <span className="text-fg">node</span> to isolate its neighbourhood, or an <span className="text-fg">edge</span> to open the exact events behind it in the evidence inspector.</p>
            <p className="pt-2 text-xs text-fg-faint">{graph.nodes.length} entities · {graph.edges.length} relationships</p>
          </div>
        )}
      </aside>
    </div>
  );
}
