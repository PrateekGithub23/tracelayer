// Administration: users and roles, invitations, recovery codes, application settings and the audit log.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, CheckCircle2, KeyRound, LogOut, MailPlus, ShieldCheck, UserPlus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useToast } from "../components/Toast";
import {
  Button, Card, EmptyState, ErrorState, Modal, PageHeader, Pill, SecretReveal, Select, Spinner, Tabs, TextInput,
} from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtRelative, fmtTime, shortHash } from "../lib/format";
import type { AdminUser, Role } from "../lib/types-v2";

type Tab = "users" | "invitations" | "settings" | "audit";
const ROLE_OPTIONS = [{ value: "viewer", label: "Viewer: read only" }, { value: "analyst", label: "Security analyst" }, { value: "admin", label: "Administrator" }];

function useErr() {
  const toast = useToast();
  return (e: unknown) => toast("error", e instanceof ApiError ? e.message : "Request failed");
}

export default function Admin() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) || "users";
  return (
    <>
      <PageHeader title="Administration" subtitle="Accounts, access and system settings. Every change here is recorded in the hash-chained audit log." />
      <Tabs<Tab> value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} tabs={[
        { id: "users", label: "Users" }, { id: "invitations", label: "Invitations" },
        { id: "settings", label: "Settings" }, { id: "audit", label: "Audit log" }]} />
      <div className="mt-5">
        {tab === "users" && <Users />}
        {tab === "invitations" && <Invitations />}
        {tab === "settings" && <SettingsPanel />}
        {tab === "audit" && <AuditLog />}
      </div>
    </>
  );
}

function Users() {
  const qc = useQueryClient();
  const toast = useToast();
  const onErr = useErr();
  const { me } = useAuth();
  const q = useQuery({ queryKey: ["admin-users"], queryFn: api.users });
  const [creating, setCreating] = useState(false);
  const [code, setCode] = useState<{ email: string; code: string; expires_at: string } | null>(null);
  const done = (msg: string) => { toast("success", msg); qc.invalidateQueries({ queryKey: ["admin-users"] }); };
  const patch = useMutation({ mutationFn: ({ id, body }: { id: string; body: Record<string, string> }) => api.patchUser(id, body), onSuccess: () => done("User updated; their sessions were signed out"), onError: onErr });
  const revoke = useMutation({ mutationFn: api.revokeUserSessions, onSuccess: (r) => done(`Signed out ${r.revoked} session(s)`), onError: onErr });
  const recovery = useMutation({ mutationFn: api.recoveryCode, onSuccess: (r) => setCode(r), onError: onErr });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  return (
    <Card pad={false} title="Users" subtitle="Changing a role or disabling an account signs the user out everywhere immediately."
      actions={<Button size="sm" variant="primary" onClick={() => setCreating(true)}><UserPlus className="h-3.5 w-3.5" />New user</Button>}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-[13px]">
          <thead className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
            <tr><th className="px-4 py-2">User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th>Sessions</th><th className="px-4 text-right">Actions</th></tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {q.data!.map((u: AdminUser) => {
              const self = u.id === me?.user.id;
              return (
                <tr key={u.id} className={u.status === "disabled" ? "opacity-60" : undefined}>
                  <td className="px-4 py-2.5"><div className="font-medium">{u.display_name}{self && <span className="ml-2 text-[11px] text-fg-faint">(you)</span>}{u.is_demo && <Pill className="ml-2">demo</Pill>}</div><div className="text-[12px] text-fg-faint">{u.email}</div></td>
                  <td>
                    <select aria-label={`Role for ${u.email}`} value={u.role} disabled={self || u.is_demo}
                      onChange={(e) => patch.mutate({ id: u.id, body: { role: e.target.value } })}
                      className="h-8 rounded-md border border-ink-600 bg-ink-800 px-2 text-[12.5px] disabled:opacity-50">
                      {ROLE_OPTIONS.map((r) => <option key={r.value} value={r.value}>{r.value}</option>)}
                    </select>
                  </td>
                  <td>{u.status === "active" ? <span className="inline-flex items-center gap-1 text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" />active</span> : <span className="inline-flex items-center gap-1 text-rose-300"><Ban className="h-3.5 w-3.5" />disabled</span>}{u.must_change_password && <div className="text-[11px] text-amber-300">must change password</div>}</td>
                  <td className="text-fg-muted">{u.last_login_at ? fmtRelative(u.last_login_at) : "never"}</td>
                  <td className="tabular-nums">{u.active_sessions ?? 0}</td>
                  <td className="px-4">
                    <div className="flex justify-end gap-1.5">
                      <Button size="sm" variant="ghost" title="Sign out everywhere" disabled={!u.active_sessions} onClick={() => revoke.mutate(u.id)}><LogOut className="h-3.5 w-3.5" /></Button>
                      <Button size="sm" variant="ghost" title="Issue a one-time recovery code" disabled={u.is_demo} onClick={() => recovery.mutate(u.id)}><KeyRound className="h-3.5 w-3.5" /></Button>
                      <Button size="sm" variant={u.status === "active" ? "danger" : "default"} disabled={self || u.is_demo}
                        onClick={() => patch.mutate({ id: u.id, body: { status: u.status === "active" ? "disabled" : "active" } })}>
                        {u.status === "active" ? "Disable" : "Enable"}
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <CreateUser open={creating} onClose={() => setCreating(false)} onCreated={() => done("User created")} />
      <Modal open={!!code} onClose={() => setCode(null)} title="Recovery code" footer={<Button onClick={() => setCode(null)}>Done</Button>}>
        {code && <div className="space-y-3 text-[13px] text-fg-muted">
          <p>Give this code to <b className="text-fg">{code.email}</b> through a channel you trust (in person, chat, phone). They redeem it on the sign-in page under “reset it here”.</p>
          <SecretReveal label="One-time code" value={code.code} note={`Valid until ${fmtTime(code.expires_at)} UTC. Shown once; only its hash is stored.`} />
        </div>}
      </Modal>
    </Card>
  );
}

function CreateUser({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.createUser({ email, display_name: name || undefined, role, password: pw, must_change_password: true });
      setEmail(""); setName(""); setPw(""); setError(null);
      onCreated(); onClose();
    } catch (err) { setError(err instanceof ApiError ? err.message : "Could not create user"); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Create user">
      <form onSubmit={submit} className="space-y-3">
        <TextInput label="Email" value={email} onChange={setEmail} type="email" />
        <TextInput label="Display name" value={name} onChange={setName} placeholder="optional" />
        <Select label="Role" value={role} onChange={(v) => setRole(v as Role)} options={ROLE_OPTIONS} />
        <TextInput label="Temporary password" value={pw} onChange={setPw} type="password" />
        <p className="text-[12px] text-fg-faint">The user must replace this password at first sign-in. Minimum 12 characters.</p>
        {error && <p role="alert" className="text-[13px] text-rose-300">{error}</p>}
        <div className="flex justify-end gap-2 pt-2"><Button onClick={onClose}>Cancel</Button><Button type="submit" variant="primary">Create</Button></div>
      </form>
    </Modal>
  );
}

function Invitations() {
  const qc = useQueryClient();
  const onErr = useErr();
  const q = useQuery({ queryKey: ["invitations"], queryFn: api.invitations });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [created, setCreated] = useState<{ token: string; email: string | null } | null>(null);
  const create = useMutation({
    mutationFn: () => api.invite(email || null, role),
    onSuccess: (r) => { setCreated({ token: r.token, email: r.email }); setEmail(""); qc.invalidateQueries({ queryKey: ["invitations"] }); },
    onError: onErr,
  });
  const revoke = useMutation({ mutationFn: api.revokeInvitation, onSuccess: () => qc.invalidateQueries({ queryKey: ["invitations"] }), onError: onErr });
  const link = created ? `${window.location.origin}/register?token=${encodeURIComponent(created.token)}${created.email ? `&email=${encodeURIComponent(created.email)}` : ""}` : "";
  return (
    <div className="space-y-4">
      <Card title={<span className="flex items-center gap-2"><MailPlus className="h-4 w-4" />Invite someone</span>} subtitle="Invitations are single-use and expire after 7 days. Binding one to an email means only that address can use it.">
        <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="flex flex-wrap items-end gap-3">
          <TextInput label="Email (optional)" value={email} onChange={setEmail} type="email" className="min-w-[240px] flex-1" />
          <Select label="Role" value={role} onChange={setRole} options={ROLE_OPTIONS} className="w-52" />
          <Button type="submit" variant="primary">Create invitation</Button>
        </form>
        {created && <div className="mt-4"><SecretReveal label="Invitation link" value={link} /></div>}
      </Card>
      <Card pad={false} title="Invitations">
        {q.isLoading ? <Spinner /> : q.error ? <ErrorState error={q.error} /> : !q.data!.length ? <EmptyState title="No invitations yet" /> : (
          <ul className="divide-y divide-ink-700">
            {q.data!.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                <span>{i.email ?? <span className="text-fg-faint">any email</span>} · <span className="capitalize">{i.role}</span></span>
                <span className="flex items-center gap-3 text-[12px] text-fg-faint">
                  <Pill className={i.state === "pending" ? "text-sky-200" : undefined}>{i.state}</Pill>
                  created {fmtRelative(i.created_at)} · expires {fmtRelative(i.expires_at)}
                  {i.state === "pending" && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(i.id)}>Revoke</Button>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function SettingsPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const onErr = useErr();
  const q = useQuery({ queryKey: ["app-settings"], queryFn: api.settings });
  const save = useMutation({
    mutationFn: api.patchSettings,
    onSuccess: () => { toast("success", "Settings saved"); qc.invalidateQueries({ queryKey: ["app-settings"] }); qc.invalidateQueries({ queryKey: ["llm-status"] }); },
    onError: onErr,
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} />;
  const s = q.data!;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Registration">
        <Select label="Who can create accounts" value={s.registration_mode} onChange={(v) => save.mutate({ registration_mode: v as typeof s.registration_mode })} options={[
          { value: "disabled", label: "Only administrators" }, { value: "invite", label: "People with an invitation (default)" },
          { value: "open", label: "Anyone (viewer role; local labs only)" }]} />
        <p className="mt-3 text-[12px] text-fg-faint">Production deployments refuse to start with open registration.</p>
      </Card>
      <Card title="Sessions and cookies" subtitle="Set through environment variables; shown here for reference.">
        <dl className="space-y-1 text-[13px]">
          <div className="flex justify-between"><dt className="text-fg-faint">Inactivity timeout</dt><dd>{s.session_idle_minutes} min</dd></div>
          <div className="flex justify-between"><dt className="text-fg-faint">Maximum session lifetime</dt><dd>{s.session_absolute_hours} h</dd></div>
          <div className="flex justify-between"><dt className="text-fg-faint">Secure cookies (HTTPS only)</dt><dd>{s.cookie_secure ? "on" : "off (local HTTP development)"}</dd></div>
          <div className="flex justify-between"><dt className="text-fg-faint">Synthetic data generator</dt><dd>{s.allow_synthetic ? "allowed" : "disabled"}</dd></div>
          <div className="flex justify-between"><dt className="text-fg-faint">Environment</dt><dd>{s.env}</dd></div>
        </dl>
      </Card>
      <Card title="AI engine" subtitle="See the AI engine page for model status, a live test and latency." className="lg:col-span-2">
        <div className="flex flex-wrap items-end gap-3">
          <Select label="Mode" value={s.llm_mode} onChange={(v) => save.mutate({ llm_mode: v as typeof s.llm_mode })} className="w-72" options={[
            { value: "auto", label: "Auto: local LLM if available, else deterministic" }, { value: "ollama", label: "Local LLM only (fail if unavailable)" },
            { value: "deterministic", label: "Deterministic only (no model)" }]} />
          <ModelInput initial={s.ollama_model} onSave={(m) => save.mutate({ ollama_model: m })} />
        </div>
      </Card>
    </div>
  );
}

function ModelInput({ initial, onSave }: { initial: string; onSave: (m: string) => void }) {
  const [m, setM] = useState(initial);
  return (
    <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); onSave(m.trim()); }}>
      <TextInput label="Ollama model" value={m} onChange={setM} mono className="w-56" />
      <Button type="submit" disabled={!m.trim() || m === initial}>Save model</Button>
    </form>
  );
}

function AuditLog() {
  const toast = useToast();
  const [action, setAction] = useState("");
  const [cursor, setCursor] = useState<number | undefined>();
  const q = useQuery({ queryKey: ["admin-audit", action, cursor], queryFn: () => api.auditLog({ action: action || undefined, before_id: cursor }) });
  const verify = useMutation({
    mutationFn: api.verifyLedger,
    onSuccess: (r) => toast(r.ok ? "success" : "error", r.ok ? `Ledger and audit chain verified (${r.audit_chain.entries_checked} audit entries, ${r.ledger.events_checked} events)` : "Verification found problems: see Evidence integrity"),
  });
  return (
    <Card pad={false} title="Audit log" subtitle="Append-only and hash-chained. Tamper-evident, not tamper-proof: anchor the chain head externally for stronger guarantees."
      actions={<Button size="sm" onClick={() => verify.mutate()}><ShieldCheck className="h-3.5 w-3.5" />Verify chain</Button>}>
      <div className="flex flex-wrap items-end gap-3 border-b border-ink-700 p-4">
        <Select label="Action" value={action} onChange={(v) => { setAction(v); setCursor(undefined); }} className="w-52" options={[
          { value: "", label: "All actions" }, { value: "auth.", label: "Authentication" }, { value: "user.", label: "User management" },
          { value: "case.", label: "Case workflow" }, { value: "analysis.", label: "AI analyses" }, { value: "claim.", label: "Claim reviews" },
          { value: "investigation.exported", label: "Exports" }, { value: "dataset.", label: "Dataset imports" }, { value: "settings.", label: "Settings" }]} />
      </div>
      {q.isLoading ? <Spinner /> : q.error ? <ErrorState error={q.error} /> : !q.data!.items.length ? <EmptyState title="No entries" /> : (
        <>
          <ol className="divide-y divide-ink-700">
            {q.data!.items.map((a) => (
              <li key={a.id} className="grid gap-1 px-4 py-2.5 text-[12.5px] md:grid-cols-[60px_160px_190px_1fr_120px]">
                <span className="font-mono text-fg-faint">#{a.id}</span>
                <span className="font-mono text-[11.5px] text-fg-faint">{fmtTime(a.timestamp)}</span>
                <span className="font-medium text-sky-200">{a.action}</span>
                <span className="min-w-0 truncate text-fg-muted" title={JSON.stringify(a.details)}><span className="text-fg">{a.actor}</span> · {a.target_type} {a.target_id}</span>
                <span className="font-mono text-[11px] text-fg-faint" title={a.entry_hash}>{shortHash(a.entry_hash, 12)}</span>
              </li>
            ))}
          </ol>
          <div className="flex justify-end gap-2 border-t border-ink-700 p-3">
            {cursor && <Button size="sm" onClick={() => setCursor(undefined)}>Newest</Button>}
            {q.data!.next_before_id && <Button size="sm" onClick={() => setCursor(q.data!.next_before_id!)}>Older</Button>}
          </div>
        </>
      )}
    </Card>
  );
}
