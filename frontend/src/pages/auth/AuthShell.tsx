// Shared layout for the signed-out screens: a short product statement and the form.
import { Activity, Fingerprint, ShieldCheck, Waypoints } from "lucide-react";
import type { ReactNode } from "react";

export function AuthShell({ title, subtitle, children, footer }: { title: string; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_minmax(420px,520px)]">
      <aside className="hidden flex-col justify-between border-r border-ink-700 bg-ink-950/70 p-10 lg:flex">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30"><Activity className="h-4.5 w-4.5 text-sky-300" /></div>
          <div>
            <div className="font-semibold tracking-tight">TraceLayer</div>
            <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">Evidence-first security investigations</div>
          </div>
        </div>
        <div className="max-w-lg space-y-6">
          <h2 className="text-2xl font-semibold leading-snug tracking-tight">AI can draft the investigation.<br />It cannot skip the evidence.</h2>
          <ul className="space-y-4 text-[13.5px] text-fg-muted">
            <li className="flex gap-3"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />Every claim in an AI draft is checked against the events it cites, and unsupported claims block approval.</li>
            <li className="flex gap-3"><Fingerprint className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />Each raw record is SHA-256 hashed and chained into a tamper-evident ledger, as are analyst decisions.</li>
            <li className="flex gap-3"><Waypoints className="mt-0.5 h-4 w-4 shrink-0 text-violet-300" />Detections are correlated into cases that analysts triage, assign, review and close, with full history.</li>
          </ul>
        </div>
        <p className="text-[11.5px] text-fg-faint">Runs locally. No paid services, no cloud APIs.</p>
      </aside>
      <main className="flex items-center justify-center px-4 py-10">
        <div className="w-full max-w-sm">
          <div className="mb-6 lg:hidden"><div className="font-semibold">TraceLayer</div></div>
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1.5 text-sm text-fg-muted">{subtitle}</p>}
          <div className="mt-6">{children}</div>
          {footer && <div className="mt-6 space-y-2 text-[13px] text-fg-muted">{footer}</div>}
        </div>
      </main>
    </div>
  );
}

export function Field({ label, type = "text", value, onChange, autoComplete, name, required = true, hint, autoFocus }: {
  label: string; type?: string; value: string; onChange: (v: string) => void; autoComplete?: string; name: string;
  required?: boolean; hint?: ReactNode; autoFocus?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-[12px] font-medium text-fg-muted">{label}</span>
      <input name={name} type={type} value={value} required={required} autoComplete={autoComplete} autoFocus={autoFocus}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 h-10 w-full rounded-lg border border-ink-600 bg-ink-800 px-3 text-[14px] text-fg focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/30" />
      {hint && <span className="mt-1 block text-[11.5px] text-fg-faint">{hint}</span>}
    </label>
  );
}

export function FormError({ error }: { error: string | null }) {
  return error ? <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[13px] text-rose-100">{error}</div> : null;
}

export const PASSWORD_HINT = "At least 12 characters. A passphrase of a few unrelated words works well.";
