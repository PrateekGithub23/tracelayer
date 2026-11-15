// Investigation timeline: one swimlane per event type, detections drawn as spans on top.
// Drag horizontally to zoom into a time range; click a dot to inspect the event.
// Rendered as plain SVG (no chart library) so every mark maps 1:1 to a real event.

import { RotateCcw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { EVENT_TYPE_COLOR, fmtTime, SEVERITY_STYLE, TACTIC_LABEL } from "../lib/format";
import type { Timeline as TimelineData, TimelineEvent } from "../lib/types";
import { eventSummary, useInspector } from "./EvidenceInspector";
import { Button, EmptyState } from "./ui";

const LANE_H = 34;
const LEFT = 118;
const TOP_DET = 22;

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(900);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) => setW(entry.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

export function Timeline({ data }: { data: TimelineData }) {
  const { openEvent } = useInspector();
  const [wrap, width] = useWidth<HTMLDivElement>();
  const [contextShown, setContextShown] = useState(true);
  const [hover, setHover] = useState<{ e: TimelineEvent; x: number; y: number } | null>(null);
  const [drag, setDrag] = useState<{ x0: number; x1: number } | null>(null);

  const events = useMemo(() => data.events.filter((e) => contextShown || e.role === "evidence"), [data, contextShown]);
  const full = useMemo(() => {
    const ts = data.events.map((e) => +new Date(e.timestamp));
    const lo = Math.min(...ts, +new Date(data.first_seen));
    const hi = Math.max(...ts, +new Date(data.last_seen));
    const pad = Math.max((hi - lo) * 0.02, 60_000);
    return [lo - pad, hi + pad] as [number, number];
  }, [data]);
  const [domain, setDomain] = useState<[number, number]>(full);
  useEffect(() => setDomain(full), [full]);

  const lanes = useMemo(() => {
    const order = ["auth.login", "process.start", "iam.change", "network.flow", "log.cleared", "dns.query", "file.access", "other"];
    const present = new Set(events.map((e) => e.event_type));
    return order.filter((t) => present.has(t));
  }, [events]);

  if (!data.events.length) return <EmptyState title="No events in this investigation's scope" />;

  const detRows = data.detections.length;
  const detH = TOP_DET + detRows * 16 + 10;
  const plotW = Math.max(200, width - LEFT - 16);
  const height = detH + lanes.length * LANE_H + 28;
  const x = (t: number) => LEFT + ((t - domain[0]) / (domain[1] - domain[0])) * plotW;
  const inv = (px: number) => domain[0] + ((px - LEFT) / plotW) * (domain[1] - domain[0]);
  const ticks = Array.from({ length: 7 }, (_, i) => domain[0] + ((domain[1] - domain[0]) * i) / 6);
  const visible = events.filter((e) => {
    const t = +new Date(e.timestamp);
    return t >= domain[0] && t <= domain[1];
  });
  const zoomed = domain[0] !== full[0] || domain[1] !== full[1];

  const onUp = () => {
    if (drag && Math.abs(drag.x1 - drag.x0) > 8) {
      const a = inv(Math.min(drag.x0, drag.x1));
      const b = inv(Math.max(drag.x0, drag.x1));
      setDomain([a, b]);
    }
    setDrag(null);
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-fg-muted">
        <span>{visible.length.toLocaleString()} events in view · drag across the chart to zoom · click a point to inspect</span>
        <div className="flex gap-2">
          <Button size="sm" variant={contextShown ? "default" : "primary"} onClick={() => setContextShown((v) => !v)}>
            {contextShown ? "Showing evidence + context" : "Evidence only"}
          </Button>
          {zoomed && <Button size="sm" onClick={() => setDomain(full)}><RotateCcw className="h-3.5 w-3.5" /> Reset zoom</Button>}
        </div>
      </div>
      <div ref={wrap} className="relative select-none overflow-hidden rounded-xl border border-ink-700 bg-ink-900">
        <svg width={width} height={height} role="img" aria-label="Investigation timeline"
          onMouseDown={(ev) => { const px = ev.nativeEvent.offsetX; if (px > LEFT) setDrag({ x0: px, x1: px }); }}
          onMouseMove={(ev) => drag && setDrag({ ...drag, x1: ev.nativeEvent.offsetX })}
          onMouseUp={onUp} onMouseLeave={() => { setDrag(null); setHover(null); }}>
          {ticks.map((t, n) => (
            <g key={t}>
              <line x1={x(t)} x2={x(t)} y1={detH - 6} y2={height - 22} stroke="#1a2331" />
              <text x={x(t)} y={height - 8} textAnchor={n === ticks.length - 1 ? "end" : n === 0 ? "start" : "middle"} className="fill-fg-faint font-mono text-[10px]">{fmtTime(new Date(t).toISOString(), false)}</text>
            </g>
          ))}
          <text x={12} y={16} className="fill-fg-faint text-[10px] font-semibold uppercase tracking-wider">Detections</text>
          {data.detections.map((d, i) => {
            const a = Math.max(LEFT, x(+new Date(d.first_seen)));
            const b = Math.min(LEFT + plotW, Math.max(x(+new Date(d.last_seen)), a + 4));
            if (b < LEFT || a > LEFT + plotW) return null;
            const s = SEVERITY_STYLE[d.severity];
            const y = TOP_DET + i * 16;
            return (
              <g key={d.id}>
                <title>{`${d.rule_name}\n${d.summary}\n${TACTIC_LABEL(d.tactic)}`}</title>
                <rect x={a} y={y} width={b - a} height={10} rx={3} fill={s.hex} fillOpacity={0.35} stroke={s.hex} strokeOpacity={0.8} />
                <text x={Math.min(b + 6, LEFT + plotW - 4)} y={y + 9} textAnchor={b + 180 > LEFT + plotW ? "end" : "start"} className="fill-fg-muted text-[10px]">{d.rule_name}</text>
              </g>
            );
          })}
          {lanes.map((lane, i) => {
            const y = detH + i * LANE_H;
            return (
              <g key={lane}>
                <rect x={0} y={y} width={width} height={LANE_H} fill={i % 2 ? "#0d121a" : "transparent"} />
                <text x={12} y={y + LANE_H / 2 + 4} className="fill-fg-muted font-mono text-[11px]">{lane}</text>
              </g>
            );
          })}
          {visible.map((e) => {
            const lane = lanes.indexOf(e.event_type);
            if (lane < 0) return null;
            const cx = x(+new Date(e.timestamp));
            const cy = detH + lane * LANE_H + LANE_H / 2 + (e.outcome === "failure" ? -6 : e.role === "context" ? 6 : 0);
            const color = e.tags.includes("llm_injection_suspected") ? "#fbbf24" : EVENT_TYPE_COLOR[e.event_type] ?? "#64748b";
            const evidence = e.role === "evidence";
            return (
              <circle key={e.id} cx={cx} cy={cy} r={evidence ? 3.6 : 2.2} fill={e.outcome === "failure" ? "transparent" : color}
                stroke={color} strokeWidth={e.outcome === "failure" ? 1.4 : 0} opacity={evidence ? 0.95 : 0.35}
                className="cursor-pointer" onClick={() => openEvent(e.id)}
                onMouseEnter={() => setHover({ e, x: cx, y: cy })} onMouseLeave={() => setHover(null)} />
            );
          })}
          {drag && <rect x={Math.min(drag.x0, drag.x1)} y={detH - 6} width={Math.abs(drag.x1 - drag.x0)} height={height - detH - 16} fill="#38bdf8" fillOpacity={0.12} stroke="#38bdf8" strokeOpacity={0.5} />}
        </svg>
        {hover && (
          <div className="pointer-events-none absolute z-10 max-w-xs rounded-lg border border-ink-600 bg-ink-950/95 px-3 py-2 text-xs shadow-xl"
            style={{ left: Math.min(hover.x + 10, width - 260), top: hover.y + 12 }}>
            <div className="font-mono text-[10.5px] text-fg-faint">{fmtTime(hover.e.timestamp)} · {hover.e.role}</div>
            <div className="mt-0.5 text-fg">{eventSummary(hover.e)}</div>
          </div>
        )}
      </div>
      <div className="flex flex-wrap gap-4 text-[11px] text-fg-faint">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-sky-400" /> success / evidence</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-sky-400" /> failure</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-sky-400/40" /> context event</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-amber-400" /> prompt-injection content</span>
      </div>
    </div>
  );
}
