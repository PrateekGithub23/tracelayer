// Application shell: sidebar navigation, live system status (DB, LLM, ledger), and analyst identity.

import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, Bot, Database, FileSearch, Gauge, LayoutDashboard, Menu, ScanSearch, ShieldCheck, Siren, Upload, X,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { NavLink } from "react-router-dom";
import { api, loadSettings, saveSettings } from "../lib/api";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/investigations", label: "Investigations", icon: Siren },
  { to: "/events", label: "Event explorer", icon: FileSearch },
  { to: "/detections", label: "Detections", icon: ScanSearch },
  { to: "/integrity", label: "Evidence integrity", icon: ShieldCheck },
  { to: "/performance", label: "Performance", icon: Gauge },
  { to: "/ingest", label: "Ingest & system", icon: Upload },
];

function StatusDot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  return <span className={clsx("h-1.5 w-1.5 rounded-full", ok ? "bg-emerald-400" : warn ? "bg-amber-400" : "bg-rose-400")} />;
}

function SystemPanel() {
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 15_000, retry: false });
  const s = status.data;
  const llmOk = !!s?.llm.reachable && !!s?.llm.model_available;
  return (
    <div className="space-y-1.5 rounded-lg border border-ink-700 bg-ink-900/60 p-3 text-[11.5px]">
      <div className="flex items-center justify-between text-fg-muted">
        <span className="flex items-center gap-1.5"><Database className="h-3.5 w-3.5" /> API</span>
        <span className="flex items-center gap-1.5">{status.isError ? "offline" : s?.database ?? "…"}<StatusDot ok={!status.isError && !!s} /></span>
      </div>
      <div className="flex items-center justify-between text-fg-muted" title={s?.llm.error ?? undefined}>
        <span className="flex items-center gap-1.5"><Bot className="h-3.5 w-3.5" /> LLM</span>
        <span className="flex items-center gap-1.5">
          {!s ? "…" : s.llm.mode === "deterministic" ? "deterministic" : llmOk ? s.llm.configured_model : "fallback"}
          <StatusDot ok={llmOk || s?.llm.mode === "deterministic"} warn />
        </span>
      </div>
    </div>
  );
}

function AnalystBox() {
  const [settings, setSettings] = useState(loadSettings);
  const [editing, setEditing] = useState(false);
  if (editing) {
    return (
      <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); saveSettings(settings); setEditing(false); }}>
        <input aria-label="Analyst name" value={settings.analyst} onChange={(e) => setSettings({ ...settings, analyst: e.target.value })}
          className="h-8 w-full rounded-md border border-ink-600 bg-ink-800 px-2 text-xs" placeholder="analyst name" />
        <input aria-label="API token" type="password" value={settings.token} onChange={(e) => setSettings({ ...settings, token: e.target.value })}
          className="h-8 w-full rounded-md border border-ink-600 bg-ink-800 px-2 text-xs" placeholder="API token (if configured)" />
        <button type="submit" className="h-7 w-full rounded-md bg-ink-700 text-xs hover:bg-ink-600">Save</button>
      </form>
    );
  }
  return (
    <button onClick={() => setEditing(true)} className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left hover:bg-ink-800" title="Analyst identity is recorded in the audit log">
      <span className="flex h-7 w-7 items-center justify-center rounded-full bg-sky-500/20 text-xs font-semibold uppercase text-sky-200">{settings.analyst.slice(0, 2)}</span>
      <span className="min-w-0">
        <span className="block truncate text-[13px]">{settings.analyst}</span>
        <span className="block text-[11px] text-fg-faint">Signed actions · click to edit</span>
      </span>
    </button>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const nav = (
    <nav className="flex flex-col gap-0.5">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
          className={({ isActive }) => clsx("flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium transition-colors",
            isActive ? "bg-sky-500/10 text-sky-200 ring-1 ring-sky-500/25" : "text-fg-muted hover:bg-ink-800 hover:text-fg")}>
          <Icon className="h-4 w-4" /> {label}
        </NavLink>
      ))}
    </nav>
  );
  const brand = (
    <div className="flex items-center gap-2.5 px-1">
      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-sky-400/30 to-emerald-400/20 ring-1 ring-sky-400/30">
        <Activity className="h-4 w-4 text-sky-300" />
      </div>
      <div>
        <div className="text-sm font-semibold tracking-tight">TraceLayer</div>
        <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">Evidence-first SecOps</div>
      </div>
    </div>
  );
  return (
    <div className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col gap-6 border-r border-ink-700 bg-ink-950/60 p-4 lg:flex">
        {brand}
        {nav}
        <div className="mt-auto space-y-3"><SystemPanel /><AnalystBox /></div>
      </aside>
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-ink-700 bg-ink-900/90 px-4 py-3 backdrop-blur lg:hidden">
        {brand}
        <button onClick={() => setOpen(true)} aria-label="Open navigation" className="rounded-md p-1.5 hover:bg-ink-800"><Menu className="h-5 w-5" /></button>
      </header>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-ink-950/70" onClick={() => setOpen(false)} />
          <div className="relative flex h-full w-72 flex-col gap-6 bg-ink-900 p-4">
            <div className="flex items-center justify-between">{brand}<button onClick={() => setOpen(false)} aria-label="Close"><X className="h-5 w-5" /></button></div>
            {nav}
            <div className="mt-auto space-y-3"><SystemPanel /><AnalystBox /></div>
          </div>
        </div>
      )}
      <main className="px-4 py-6 lg:ml-60 lg:px-8 lg:py-8">
        <div className="mx-auto max-w-[1440px]">{children}</div>
      </main>
    </div>
  );
}
