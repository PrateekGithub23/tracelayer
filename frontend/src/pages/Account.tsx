// Account settings: profile, password, active sessions (with revocation) and sign-in history.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LogOut, MonitorSmartphone, ShieldAlert, UserRound } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useToast } from "../components/Toast";
import { Button, Card, EmptyState, ErrorState, KV, PageHeader, Pill, Spinner, Tabs } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtRelative, fmtTime } from "../lib/format";
import { Field, FormError, PASSWORD_HINT } from "./auth/AuthShell";

type Tab = "profile" | "security" | "sessions" | "history" | "activity";

function describeAgent(ua: string | null): string {
  if (!ua) return "Unknown client";
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : /python|httpx|curl/i.test(ua) ? "API client" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : "";
  return os ? `${browser} on ${os}` : browser;
}

export default function Account() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) || "profile";
  return (
    <>
      <PageHeader title="Account" subtitle="Your profile, password and where you are signed in." />
      <Tabs<Tab> value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} tabs={[
        { id: "profile", label: "Profile" }, { id: "security", label: "Password" },
        { id: "sessions", label: "Active sessions" }, { id: "history", label: "Sign-in history" }, { id: "activity", label: "My activity" }]} />
      <div className="mt-5 max-w-3xl">
        {tab === "profile" && <Profile />}
        {tab === "security" && <PasswordForm />}
        {tab === "sessions" && <Sessions />}
        {tab === "history" && <History />}
        {tab === "activity" && <ActivityList load={api.myActivity} queryKey="my-activity" />}
      </div>
    </>
  );
}

function Profile() {
  const { me, adopt } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(me?.user.display_name ?? "");
  if (!me) return null;
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const user = await api.updateProfile(name);
      adopt({ ...me, user });
      toast("success", "Profile saved");
    } catch (err) { toast("error", err instanceof ApiError ? err.message : "Could not save"); }
  };
  return (
    <Card title={<span className="flex items-center gap-2"><UserRound className="h-4 w-4" />Profile</span>}>
      <dl className="mb-4">
        <KV k="Email" v={me.user.email} />
        <KV k="Role" v={<span className="capitalize">{me.user.role}</span>} />
        <KV k="Member since" v={fmtTime(me.user.created_at)} />
        <KV k="Last sign-in" v={me.user.last_login_at ? `${fmtTime(me.user.last_login_at)} UTC` : "—"} />
        <KV k="Session ends" v={`${fmtTime(me.session.expires_at)} UTC (${fmtRelative(me.session.expires_at)}) unless you stay active`} />
      </dl>
      <form onSubmit={save} className="flex flex-wrap items-end gap-3">
        <div className="min-w-[240px] flex-1"><Field name="display_name" label="Display name" value={name} onChange={setName} autoComplete="name" /></div>
        <Button type="submit" variant="primary" disabled={me.user.is_demo}>Save</Button>
      </form>
      <p className="mt-3 text-[12px] text-fg-faint">Your email and role are managed by an administrator.</p>
    </Card>
  );
}

function PasswordForm() {
  const { adopt, me } = useAuth();
  const toast = useToast();
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (pw !== pw2) return setError("The new passwords do not match.");
    try {
      adopt(await api.changePassword(cur, pw));
      setCur(""); setPw(""); setPw2("");
      toast("success", "Password changed. Every other session was signed out.");
    } catch (err) { setError(err instanceof ApiError ? err.message : "Could not change password"); }
  };
  return (
    <Card title={<span className="flex items-center gap-2"><KeyRound className="h-4 w-4" />Change password</span>}
      subtitle="Changing your password signs out all of your sessions, including other browsers and devices.">
      {me?.user.is_demo ? <p className="text-sm text-fg-muted">Demo accounts cannot change their password.</p> : (
        <form onSubmit={submit} className="max-w-sm space-y-4">
          <Field name="current" label="Current password" type="password" autoComplete="current-password" value={cur} onChange={setCur} />
          <Field name="new" label="New password" type="password" autoComplete="new-password" value={pw} onChange={setPw} hint={PASSWORD_HINT} />
          <Field name="new2" label="Repeat new password" type="password" autoComplete="new-password" value={pw2} onChange={setPw2} />
          <FormError error={error} />
          <Button type="submit" variant="primary">Change password</Button>
        </form>
      )}
    </Card>
  );
}

function Sessions() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["my-sessions"], queryFn: api.sessions });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeSession(id),
    onSuccess: () => { toast("success", "Session signed out"); qc.invalidateQueries({ queryKey: ["my-sessions"] }); },
    onError: (e) => toast("error", (e as Error).message),
  });
  const others = useMutation({
    mutationFn: api.revokeOtherSessions,
    onSuccess: (r) => { toast("success", `Signed out ${r.revoked} other session${r.revoked === 1 ? "" : "s"}`); qc.invalidateQueries({ queryKey: ["my-sessions"] }); },
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const active = q.data!.filter((s) => s.active);
  const ended = q.data!.filter((s) => !s.active).slice(0, 10);
  return (
    <div className="space-y-4">
      <Card pad={false} title={<span className="flex items-center gap-2"><MonitorSmartphone className="h-4 w-4" />Active sessions</span>}
        subtitle="Sessions end after 8 hours of inactivity or 7 days after sign-in, whichever comes first."
        actions={active.length > 1 && <Button size="sm" variant="danger" onClick={() => others.mutate()}><LogOut className="h-3.5 w-3.5" />Sign out all others</Button>}>
        <ul className="divide-y divide-ink-700">
          {active.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-[13px]">
              <div className="min-w-0">
                <div className="flex items-center gap-2 font-medium">{describeAgent(s.user_agent)}{s.current && <Pill className="text-emerald-300">this browser</Pill>}</div>
                <div className="mt-0.5 text-[12px] text-fg-faint">{s.ip ?? "unknown IP"} · signed in {fmtRelative(s.created_at)} · last active {fmtRelative(s.last_seen_at)} · ends {fmtRelative(s.expires_at)}</div>
              </div>
              {!s.current && <Button size="sm" onClick={() => revoke.mutate(s.id)}>Sign out</Button>}
            </li>
          ))}
        </ul>
      </Card>
      {ended.length > 0 && (
        <Card pad={false} title="Recently ended">
          <ul className="divide-y divide-ink-700">
            {ended.map((s) => (
              <li key={s.id} className="flex justify-between gap-3 px-4 py-2.5 text-[12.5px] text-fg-muted">
                <span>{describeAgent(s.user_agent)} · {s.ip ?? "?"}</span>
                <span className="text-fg-faint">{(s.revoked_reason ?? "expired").replaceAll("_", " ")} · {fmtRelative(s.revoked_at ?? s.expires_at)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function History() {
  const q = useQuery({ queryKey: ["login-history"], queryFn: api.loginHistory });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} />;
  if (!q.data!.length) return <EmptyState title="No sign-ins recorded" />;
  const failures = q.data!.filter((r) => !r.success).length;
  return (
    <Card pad={false} title="Sign-in history" subtitle="The last 50 attempts on your account, including failed ones.">
      {failures > 0 && <div className="flex items-center gap-2 border-b border-ink-700 px-4 py-2.5 text-[12.5px] text-amber-200"><ShieldAlert className="h-4 w-4" />{failures} failed attempt{failures === 1 ? "" : "s"}. If these weren't you, change your password.</div>}
      <table className="w-full text-[12.5px]">
        <thead className="text-left text-[11px] uppercase tracking-wider text-fg-faint"><tr><th className="px-4 py-2">When (UTC)</th><th>Result</th><th>IP</th><th className="hidden md:table-cell">Client</th></tr></thead>
        <tbody className="divide-y divide-ink-700">
          {q.data!.map((r) => (
            <tr key={r.id}>
              <td className="px-4 py-2 font-mono text-[11.5px]">{fmtTime(r.created_at)}</td>
              <td className={r.success ? "text-emerald-300" : "text-rose-300"}>{r.success ? "success" : r.reason.replaceAll("_", " ")}</td>
              <td className="font-mono text-[11.5px]">{r.ip ?? "—"}</td>
              <td className="hidden text-fg-muted md:table-cell">{describeAgent(r.user_agent)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/** Audited actions by one user, newest first (also used by the admin user dialog). */
export function ActivityList({ load, queryKey }: { load: () => Promise<import("../lib/types-v2").UserActivity[]>; queryKey: string }) {
  const q = useQuery({ queryKey: [queryKey], queryFn: load });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} />;
  if (!q.data!.length) return <EmptyState title="No recorded actions yet" />;
  return (
    <Card pad={false} title="Activity" subtitle="Actions recorded in the hash-chained audit log under this account.">
      <ul className="divide-y divide-ink-700">
        {q.data!.map((a) => (
          <li key={a.id} className="grid gap-1 px-4 py-2.5 text-[12.5px] md:grid-cols-[170px_200px_1fr]">
            <span className="font-mono text-[11.5px] text-fg-faint">{fmtTime(a.timestamp)}</span>
            <span className="font-medium text-sky-200">{a.action}</span>
            <span className="truncate text-fg-muted">{a.target_type} <span className="font-mono">{a.target_id}</span></span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
