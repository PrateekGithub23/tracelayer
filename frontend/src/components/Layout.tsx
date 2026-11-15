// Application shell: navigation (filtered by permission), queue badges, live system status and the
// signed-in user's menu. The demo banner appears whenever the browser-local demo transport is active.

import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, Bot, Compass, Database, FileSearch, Gauge, LayoutDashboard, LogOut, Menu, ScanSearch, Settings2,
  ShieldCheck, Siren, Upload, UserRound, Users, X,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import { api, isDemoTransport } from "../lib/api";
import { useAuth } from "../lib/auth";
import { SessionWarning } from "./SessionWarning";

interface NavItem { to: string; label: string; icon: typeof Activity; end?: boolean; perm?: string; badge?: "queue" }
const NAV: { section: string; items: NavItem[] }[] = [
  { section: "Investigate", items: [
    { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
    { to: "/walkthrough", label: "Guided scenario", icon: Compass },
    { to: "/investigations", label: "Investigations", icon: Siren, badge: "queue" },
    { to: "/events", label: "Event explorer", icon: FileSearch },
    { to: "/detections", label: "Detections", icon: ScanSearch },
  ] },
  { section: "Evidence & AI", items: [
    { to: "/integrity", label: "Evidence integrity", icon: ShieldCheck },
    { to: "/ai", label: "AI engine", icon: Bot },
    { to: "/datasets", label: "Datasets", icon: Database },
    { to: "/performance", label: "Performance", icon: Gauge },
  ] },
  { section: "Administer", items: [
    { to: "/ingest", label: "Ingest", icon: Upload, perm: "ingest:write" },
    { to: "/admin", label: "Users & settings", icon: Users, perm: "users:manage" },
  ] },
];

function StatusDot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  return <span className={clsx("h-1.5 w-1.5 rounded-full", ok ? "bg-emerald-400" : warn ? "bg-amber-400" : "bg-rose-400")} />;
}

function SystemPanel() {
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 30_000, retry: false });
  const s = status.data;
  const llmOk = !!s?.llm.reachable && !!s?.llm.model_available;
  return (
    <Link to="/ai" className="block space-y-1.5 rounded-lg border border-ink-700 bg-ink-900/60 p-3 text-[11.5px] hover:border-ink-600">
      <div className="flex items-center justify-between text-fg-muted">
        <span className="flex items-center gap-1.5"><Database className="h-3.5 w-3.5" /> {isDemoTransport() ? "Demo data" : "API"}</span>
        <span className="flex items-center gap-1.5">{status.isError ? "offline" : s?.database ?? "…"}<StatusDot ok={!status.isError && !!s} /></span>
      </div>
      <div className="flex items-center justify-between text-fg-muted" title={s?.llm.error ?? undefined}>
        <span className="flex items-center gap-1.5"><Bot className="h-3.5 w-3.5" /> LLM</span>
        <span className="flex items-center gap-1.5">
          {!s ? "…" : s.llm.mode === "deterministic" ? "deterministic" : llmOk ? s.llm.configured_model : "fallback"}
          <StatusDot ok={llmOk || s?.llm.mode === "deterministic"} warn />
        </span>
      </div>
    </Link>
  );
}

function UserMenu() {
  const { me, logout } = useAuth();
  const [open, setOpen] = useState(false);
  if (!me) return null;
  const u = me.user;
  return (
    <div className="relative">
      {open && (
        <div className="absolute bottom-full left-0 right-0 mb-2 overflow-hidden rounded-lg border border-ink-600 bg-ink-850 shadow-2xl" role="menu">
          <Link role="menuitem" to="/account" onClick={() => setOpen(false)} className="flex items-center gap-2 px-3 py-2.5 text-[13px] hover:bg-ink-700"><UserRound className="h-4 w-4" />Account</Link>
          <Link role="menuitem" to="/account?tab=sessions" onClick={() => setOpen(false)} className="flex items-center gap-2 px-3 py-2.5 text-[13px] hover:bg-ink-700"><Settings2 className="h-4 w-4" />Active sessions</Link>
          <button role="menuitem" onClick={() => void logout()} className="flex w-full items-center gap-2 border-t border-ink-700 px-3 py-2.5 text-left text-[13px] text-rose-200 hover:bg-ink-700"><LogOut className="h-4 w-4" />Sign out</button>
        </div>
      )}
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="menu"
        className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left hover:bg-ink-800">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-sky-500/20 text-xs font-semibold uppercase text-sky-200">{u.display_name.slice(0, 2)}</span>
        <span className="min-w-0">
          <span className="block truncate text-[13px]">{u.display_name}</span>
          <span className="block text-[11px] capitalize text-fg-faint">{u.role === "analyst" ? "security analyst" : u.role}{u.is_demo ? " · demo" : ""}</span>
        </span>
      </button>
    </div>
  );
}

function QueueBadge() {
  const q = useQuery({ queryKey: ["queues"], queryFn: api.queues, refetchInterval: 60_000 });
  const n = (q.data?.mine ?? 0) + (q.data?.needs_review ?? 0);
  return n ? <span className="ml-auto rounded-full bg-sky-500/20 px-1.5 text-[10.5px] font-semibold tabular-nums text-sky-200" title="Assigned to you + awaiting your review">{n}</span> : null;
}

function DemoBanner() {
  if (!isDemoTransport()) return null;
  return (
    <div className="border-b border-emerald-400/25 bg-emerald-400/10 px-4 py-2 text-center text-[12.5px] text-emerald-100 lg:ml-60">
      <b>Read-only public demo.</b> Data was processed by the real TraceLayer backend and packaged with this page; your changes stay in this browser tab and reset on reload.
      {import.meta.env.VITE_REPO_URL && <>{" "}<a className="underline" href={import.meta.env.VITE_REPO_URL} target="_blank" rel="noreferrer noopener">Run the full app locally</a>.</>}
    </div>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const { can } = useAuth();
  const nav = (
    <nav className="flex flex-col gap-4" aria-label="Main">
      {NAV.map(({ section, items }) => {
        const visible = items.filter((i) => !i.perm || can(i.perm));
        if (!visible.length) return null;
        return (
          <div key={section}>
            <div className="mb-1 px-2.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-fg-faint">{section}</div>
            <div className="flex flex-col gap-0.5">
              {visible.map(({ to, label, icon: Icon, end, badge }) => (
                <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
                  className={({ isActive }) => clsx("flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-[13px] font-medium transition-colors",
                    isActive ? "bg-sky-500/10 text-sky-200 ring-1 ring-sky-500/25" : "text-fg-muted hover:bg-ink-800 hover:text-fg")}>
                  <Icon className="h-4 w-4" /> {label}{badge === "queue" && <QueueBadge />}
                </NavLink>
              ))}
            </div>
          </div>
        );
      })}
    </nav>
  );
  const brand = (
    <Link to="/" className="flex items-center gap-2.5 px-1">
      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30">
        <Activity className="h-4 w-4 text-sky-300" />
      </div>
      <div>
        <div className="text-sm font-semibold tracking-tight">TraceLayer</div>
        <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">Evidence-first SecOps</div>
      </div>
    </Link>
  );
  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[70] focus:rounded focus:bg-ink-800 focus:px-3 focus:py-2">Skip to content</a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col gap-5 overflow-y-auto border-r border-ink-700 bg-ink-950/60 p-4 lg:flex">
        {brand}
        {nav}
        <div className="mt-auto space-y-3"><SystemPanel /><UserMenu /></div>
      </aside>
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-ink-700 bg-ink-900/90 px-4 py-3 backdrop-blur lg:hidden">
        {brand}
        <button onClick={() => setOpen(true)} aria-label="Open navigation" className="rounded-md p-1.5 hover:bg-ink-800"><Menu className="h-5 w-5" /></button>
      </header>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-ink-950/70" onClick={() => setOpen(false)} />
          <div className="relative flex h-full w-72 flex-col gap-5 overflow-y-auto bg-ink-900 p-4">
            <div className="flex items-center justify-between">{brand}<button onClick={() => setOpen(false)} aria-label="Close navigation"><X className="h-5 w-5" /></button></div>
            {nav}
            <div className="mt-auto space-y-3"><SystemPanel /><UserMenu /></div>
          </div>
        </div>
      )}
      <DemoBanner />
      <SessionWarning />
      <main id="main" className="px-4 py-6 lg:ml-60 lg:px-8 lg:py-8">
        <div className="mx-auto max-w-[1440px]">{children}</div>
      </main>
    </div>
  );
}
