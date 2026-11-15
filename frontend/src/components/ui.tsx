// UI primitives. Every page uses these so loading / error / empty states,
// severity and verdict colours look and behave identically everywhere.

import clsx from "clsx";
import { AlertTriangle, Inbox, Loader2, X } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { ApiError } from "../lib/api";
import { SEVERITY_STYLE, VERDICT_META } from "../lib/format";
import type { Severity, Verdict } from "../lib/types";

export function Card({ title, actions, children, className, pad = true, subtitle }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <section className={clsx("rounded-xl border border-ink-700 bg-ink-850/80 shadow-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-ink-700/70 px-4 py-3">
          <div className="min-w-0">
            <h2 className="text-[13px] font-semibold tracking-wide text-fg sm:truncate">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-fg-faint">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx(pad && "p-4")}>{children}</div>
    </section>
  );
}

export function Button({ children, onClick, variant = "default", size = "md", disabled, type = "button", title, className }: {
  children: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "danger" | "ghost" | "success";
  size?: "sm" | "md"; disabled?: boolean; type?: "button" | "submit"; title?: string; className?: string;
}) {
  return (
    <button
      type={type}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 disabled:cursor-not-allowed disabled:opacity-45",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-[13px]",
        variant === "primary" && "bg-sky-500 text-ink-950 hover:bg-sky-400",
        variant === "success" && "bg-emerald-500 text-ink-950 hover:bg-emerald-400",
        variant === "danger" && "bg-rose-500/15 text-rose-200 ring-1 ring-rose-500/40 hover:bg-rose-500/25",
        variant === "default" && "bg-ink-700 text-fg ring-1 ring-ink-600 hover:bg-ink-600",
        variant === "ghost" && "text-fg-muted hover:bg-ink-700 hover:text-fg",
        className,
      )}
    >
      {children}
    </button>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.low;
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ring-1", s.bg, s.text, s.ring, className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.hex }} />
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict, size = "md" }: { verdict: Verdict; size?: "sm" | "md" }) {
  const m = VERDICT_META[verdict];
  return (
    <span
      title={m.help}
      className={clsx("inline-flex shrink-0 items-center gap-1.5 rounded-md font-semibold ring-1", m.bg, m.text, m.ring,
        size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-[11px]")}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: m.hex }} />
      {size === "sm" ? m.short : m.label}
    </span>
  );
}

export function Pill({ children, className, mono }: { children: ReactNode; className?: string; mono?: boolean }) {
  return (
    <span className={clsx("inline-flex items-center rounded-md bg-ink-700/70 px-1.5 py-0.5 text-[11px] text-fg-muted ring-1 ring-ink-600/60", mono && "font-mono", className)}>
      {children}
    </span>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-850/80 p-4 shadow-panel">
      <div className="text-[11px] font-medium uppercase tracking-wider text-fg-faint">{label}</div>
      <div className="mt-1.5 text-2xl font-semibold tabular-nums" style={accent ? { color: accent } : undefined}>{value}</div>
      {hint && <div className="mt-1 text-xs text-fg-muted">{hint}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-fg-muted" role="status">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}…
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : "Something went wrong";
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-rose-500/25 bg-rose-500/5 px-4 py-8 text-center" role="alert">
      <AlertTriangle className="h-5 w-5 text-rose-300" />
      <p className="max-w-lg text-sm text-rose-100/90">{msg}</p>
      {onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-12 text-center">
      <div className="rounded-full bg-ink-700/60 p-3 text-fg-faint">{icon ?? <Inbox className="h-5 w-5" />}</div>
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-fg-muted">{children}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (t: T) => void;
}) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-ink-700" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={clsx("-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-[13px] font-medium transition-colors",
            value === t.id ? "border-sky-400 text-fg" : "border-transparent text-fg-muted hover:text-fg")}
        >
          {t.label}
          {t.count !== undefined && <span className="rounded bg-ink-700 px-1.5 text-[10px] tabular-nums text-fg-muted">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Drawer({ open, onClose, title, children, width = "max-w-2xl" }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-ink-950/70 backdrop-blur-[2px]" onClick={onClose} />
      <aside className={clsx("relative flex h-full w-full flex-col border-l border-ink-600 bg-ink-850 shadow-2xl", width)}>
        <header className="flex items-center justify-between gap-3 border-b border-ink-700 px-5 py-3.5">
          <div className="min-w-0 text-sm font-semibold">{title}</div>
          <button onClick={onClose} className="rounded-md p-1 text-fg-muted hover:bg-ink-700 hover:text-fg" aria-label="Close"><X className="h-4 w-4" /></button>
        </header>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  );
}

export function KV({ k, v, mono }: { k: string; v: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-3 py-1.5 text-[13px]">
      <dt className="text-fg-faint">{k}</dt>
      <dd className={clsx("min-w-0 break-words text-fg", mono && "font-mono text-[12px]")}>{v ?? "—"}</dd>
    </div>
  );
}

export function Select({ value, onChange, options, label, className }: {
  value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label: string; className?: string;
}) {
  return (
    <label className={clsx("flex flex-col gap-1", className)}>
      <span className="text-[11px] font-medium uppercase tracking-wider text-fg-faint">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="h-9 rounded-lg border border-ink-600 bg-ink-800 px-2.5 text-[13px] text-fg focus:border-sky-500 focus:outline-none">
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  );
}

export function TextInput({ value, onChange, label, placeholder, type = "text", className, mono }: {
  value: string; onChange: (v: string) => void; label?: string; placeholder?: string; type?: string; className?: string; mono?: boolean;
}) {
  return (
    <label className={clsx("flex flex-col gap-1", className)}>
      {label && <span className="text-[11px] font-medium uppercase tracking-wider text-fg-faint">{label}</span>}
      <input type={type} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
        className={clsx("h-9 rounded-lg border border-ink-600 bg-ink-800 px-3 text-[13px] text-fg placeholder:text-fg-faint focus:border-sky-500 focus:outline-none", mono && "font-mono")} />
    </label>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-fg-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined}>
      <div className="absolute inset-0 bg-ink-950/75 backdrop-blur-[2px]" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-xl border border-ink-600 bg-ink-850 shadow-2xl">
        <header className="flex items-center justify-between border-b border-ink-700 px-5 py-3.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button onClick={onClose} className="rounded-md p-1 text-fg-muted hover:bg-ink-700 hover:text-fg" aria-label="Close"><X className="h-4 w-4" /></button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-ink-700 px-5 py-3">{footer}</footer>}
      </div>
    </div>
  );
}

export function TextArea({ value, onChange, label, placeholder, rows = 3, className }: {
  value: string; onChange: (v: string) => void; label?: string; placeholder?: string; rows?: number; className?: string;
}) {
  return (
    <label className={clsx("flex flex-col gap-1", className)}>
      {label && <span className="text-[11px] font-medium uppercase tracking-wider text-fg-faint">{label}</span>}
      <textarea value={value} rows={rows} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-2 text-[13px] text-fg placeholder:text-fg-faint focus:border-sky-500 focus:outline-none" />
    </label>
  );
}

/** A value shown exactly once (invitation token, recovery code), with a copy button. */
export function SecretReveal({ label, value, note }: { label: string; value: string; note?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-lg border border-amber-400/30 bg-amber-400/5 p-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-amber-200">{label}</div>
      <div className="mt-1.5 flex items-center gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-ink-900 px-2 py-1.5 font-mono text-[12px]">{value}</code>
        <Button size="sm" onClick={() => { void navigator.clipboard?.writeText(value); setCopied(true); }}>{copied ? "Copied" : "Copy"}</Button>
      </div>
      <p className="mt-2 text-[11.5px] text-amber-100/80">{note ?? "Shown once. TraceLayer stores only a hash of it and cannot display it again."}</p>
    </div>
  );
}
