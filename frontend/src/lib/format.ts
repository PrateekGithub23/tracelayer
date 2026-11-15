// Formatting helpers and the semantic colour/label maps used across the UI.

import type { Severity, Verdict } from "./types";

export const fmtTime = (iso: string | null | undefined, withDate = true): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC" });
  if (!withDate) return time;
  const date = d.toLocaleDateString("en-CA", { timeZone: "UTC" });
  return `${date} ${time}`;
};

export const fmtRelative = (iso: string | null | undefined): string => {
  if (!iso) return "—";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

export const fmtBytes = (n: number | null | undefined): string => {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
};

export const fmtNum = (n: number | null | undefined): string => (n ?? 0).toLocaleString("en-US");

export const fmtMs = (ms: number | null | undefined): string => {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 1000) return `${ms.toFixed(ms < 10 ? 2 : 0)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
};

export const shortHash = (h: string | null | undefined, n = 10): string => (h ? `${h.slice(0, n)}…` : "—");

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_STYLE: Record<Severity, { text: string; bg: string; ring: string; hex: string }> = {
  critical: { text: "text-rose-300", bg: "bg-rose-500/15", ring: "ring-rose-500/40", hex: "#fb7185" },
  high: { text: "text-orange-300", bg: "bg-orange-500/15", ring: "ring-orange-500/40", hex: "#fb923c" },
  medium: { text: "text-amber-200", bg: "bg-amber-400/10", ring: "ring-amber-400/30", hex: "#fbbf24" },
  low: { text: "text-slate-300", bg: "bg-slate-400/10", ring: "ring-slate-400/30", hex: "#94a3b8" },
};

export const VERDICTS: Verdict[] = [
  "verified_observation",
  "heuristic_correlation",
  "ai_hypothesis",
  "missing_evidence",
  "unsupported_claim",
  "contradictory_finding",
];

export const VERDICT_META: Record<Verdict, { label: string; short: string; text: string; bg: string; ring: string; hex: string; help: string }> = {
  verified_observation: {
    label: "Verified observation", short: "Verified", text: "text-emerald-300", bg: "bg-emerald-500/10",
    ring: "ring-emerald-500/35", hex: "#34d399", help: "Every checkable fact appears in the cited, in-scope events.",
  },
  heuristic_correlation: {
    label: "Heuristic correlation", short: "Correlation", text: "text-sky-300", bg: "bg-sky-500/10",
    ring: "ring-sky-500/35", hex: "#38bdf8", help: "Each fact is supported, but the link between them is inferred.",
  },
  ai_hypothesis: {
    label: "AI hypothesis", short: "Hypothesis", text: "text-violet-300", bg: "bg-violet-500/10",
    ring: "ring-violet-500/35", hex: "#a78bfa", help: "Speculative. Useful as a lead, not as evidence.",
  },
  missing_evidence: {
    label: "Missing evidence", short: "Missing", text: "text-amber-200", bg: "bg-amber-400/10",
    ring: "ring-amber-400/30", hex: "#fbbf24", help: "Depends on telemetry that does not exist in this investigation.",
  },
  unsupported_claim: {
    label: "Unsupported claim", short: "Unsupported", text: "text-orange-300", bg: "bg-orange-500/10",
    ring: "ring-orange-500/40", hex: "#fb923c", help: "Fabricated or out-of-scope citations, unknown entities, or facts the citations do not show.",
  },
  contradictory_finding: {
    label: "Contradictory finding", short: "Contradicted", text: "text-rose-300", bg: "bg-rose-500/10",
    ring: "ring-rose-500/40", hex: "#fb7185", help: "The evidence says otherwise (count, outcome, order, attribution).",
  },
};

export const UNSAFE: Verdict[] = ["unsupported_claim", "contradictory_finding"];

export const EVENT_TYPE_COLOR: Record<string, string> = {
  "auth.login": "#38bdf8",
  "process.start": "#a78bfa",
  "network.flow": "#34d399",
  "iam.change": "#f472b6",
  "dns.query": "#64748b",
  "file.access": "#94a3b8",
  "log.cleared": "#fb7185",
  other: "#475569",
};

export const TACTIC_LABEL = (t: string): string => t.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
