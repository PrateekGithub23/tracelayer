import { LogIn, PlayCircle } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui";
import { ApiError, isDemoTransport } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { AuthShell, Field, FormError } from "./AuthShell";

export default function Login() {
  const { login, config } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (isDemoTransport()) {
    return (
      <AuthShell title="Explore the TraceLayer demo" subtitle="A read-only copy of the real application, running entirely in your browser. You'll sign in as Dana, a security analyst working a live case.">
        <div className="space-y-4 text-[13px] text-fg-muted">
          <p>Every number, verdict and event here was produced by the real TraceLayer backend when this demo was built, from a seeded synthetic intrusion and public lab telemetry (OTRF Security-Datasets, MIT License).</p>
          <p>You can triage and comment on cases, pin evidence and review AI claims. Changes stay in this tab and reset on reload.</p>
          <Button variant="primary" className="w-full" onClick={async () => { await login("demo", "demo"); nav("/walkthrough", { replace: true }); }}>
            <PlayCircle className="h-4 w-4" />Start the guided scenario
          </Button>
          <Button className="w-full" onClick={async () => { await login("demo", "demo"); nav("/", { replace: true }); }}>Go straight to the dashboard</Button>
        </div>
      </AuthShell>
    );
  }
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      nav((loc.state as { from?: string } | null)?.from ?? "/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError && err.status === 429 ? "Too many attempts. Wait a few minutes and try again." :
        err instanceof ApiError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthShell title="Sign in" subtitle="Use the account your TraceLayer administrator created for you."
      footer={<>
        {config?.registration_mode !== "disabled" && <p>Have an invitation? <Link className="text-sky-300 hover:underline" to="/register">Create your account</Link></p>}
        <p>Forgot your password? Ask an administrator for a recovery code, then <Link className="text-sky-300 hover:underline" to="/recover">reset it here</Link>.</p>
        {config && !config.has_users && (
          <p className="rounded-lg border border-amber-400/25 bg-amber-400/5 p-3 text-amber-100">
            No accounts exist yet. Create the first administrator on the server:<br />
            <code className="mt-1 block font-mono text-[12px]">make create-admin</code>
          </p>
        )}
        <p className="pt-2"><a className="inline-flex items-center gap-1.5 text-emerald-300 hover:underline" href={import.meta.env.VITE_DEMO_URL || "/demo/"}><PlayCircle className="h-4 w-4" /> Explore the read-only demo instead</a></p>
      </>}>
      <form onSubmit={submit} className="space-y-4">
        <Field name="email" label="Email" type="email" autoComplete="username" value={email} onChange={setEmail} autoFocus />
        <Field name="password" label="Password" type="password" autoComplete="current-password" value={password} onChange={setPassword} />
        <FormError error={error} />
        <Button type="submit" variant="primary" className="w-full" disabled={busy}><LogIn className="h-4 w-4" />{busy ? "Signing in…" : "Sign in"}</Button>
      </form>
    </AuthShell>
  );
}
