// Screens shown instead of the app: loading, session expired, and the forced first-login password change.
import { Loader2, TimerOff } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { AuthShell, Field, FormError, PASSWORD_HINT } from "./AuthShell";

export function FullPageSpinner() {
  return <div className="flex min-h-screen items-center justify-center text-sm text-fg-muted"><Loader2 className="mr-2 h-4 w-4 animate-spin" />Checking your session…</div>;
}

export function SessionExpired() {
  const { expiredReason, refresh } = useAuth();
  const revoked = expiredReason === "revoked";
  return (
    <AuthShell title={revoked ? "You were signed out" : "Your session expired"}
      subtitle={revoked ? "This session was revoked: you signed out elsewhere, changed your password, or an administrator ended it." :
        "Sessions end after a period of inactivity, and after a fixed maximum lifetime. Nothing you had already saved was lost."}>
      <div className="flex items-center gap-3 rounded-lg border border-ink-600 bg-ink-800/60 p-4 text-[13px] text-fg-muted">
        <TimerOff className="h-5 w-5 text-amber-300" /> Sign in again to continue.
      </div>
      <Link to="/login" onClick={() => void refresh()}><Button variant="primary" className="mt-4 w-full">Sign in again</Button></Link>
    </AuthShell>
  );
}

export function MustChangePassword() {
  const { adopt, logout } = useAuth();
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try { adopt(await api.changePassword(cur, pw)); } catch (err) { setError(err instanceof ApiError ? err.message : "Could not change password"); }
  };
  return (
    <AuthShell title="Choose a new password" subtitle="Your administrator set a temporary password. Replace it before continuing."
      footer={<button className="text-sky-300 hover:underline" onClick={() => void logout()}>Sign out</button>}>
      <form onSubmit={submit} className="space-y-4">
        <Field name="current" label="Temporary password" type="password" autoComplete="current-password" value={cur} onChange={setCur} />
        <Field name="new" label="New password" type="password" autoComplete="new-password" value={pw} onChange={setPw} hint={PASSWORD_HINT} />
        <FormError error={error} />
        <Button type="submit" variant="primary" className="w-full">Save and continue</Button>
      </form>
    </AuthShell>
  );
}
