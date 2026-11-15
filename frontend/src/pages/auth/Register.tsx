import { type FormEvent, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { AuthShell, Field, FormError, PASSWORD_HINT } from "./AuthShell";

export default function Register() {
  const [params] = useSearchParams();
  const { config } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const [token, setToken] = useState(params.get("token") ?? "");
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (pw !== pw2) return setError("The passwords do not match.");
    try {
      await api.register({ invite_token: token || undefined, email, display_name: name, password: pw });
      toast("success", "Account created. You can sign in now.");
      nav("/login");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed");
    }
  };
  if (config?.registration_mode === "disabled") {
    return <AuthShell title="Registration is closed" subtitle="Accounts on this TraceLayer are created by an administrator."
      footer={<Link className="text-sky-300 hover:underline" to="/login">Back to sign in</Link>}><span /></AuthShell>;
  }
  return (
    <AuthShell title="Create your account" subtitle={config?.registration_mode === "invite" ? "Paste the invitation token your administrator sent you. It works once and expires after 7 days." : "Open registration creates a read-only viewer account."}
      footer={<Link className="text-sky-300 hover:underline" to="/login">Already have an account? Sign in</Link>}>
      <form onSubmit={submit} className="space-y-4">
        {config?.registration_mode === "invite" && <Field name="token" label="Invitation token" value={token} onChange={setToken} autoComplete="off" />}
        <Field name="email" label="Email" type="email" autoComplete="username" value={email} onChange={setEmail} />
        <Field name="name" label="Display name" autoComplete="name" value={name} onChange={setName} />
        <Field name="password" label="Password" type="password" autoComplete="new-password" value={pw} onChange={setPw} hint={PASSWORD_HINT} />
        <Field name="password2" label="Repeat password" type="password" autoComplete="new-password" value={pw2} onChange={setPw2} />
        <FormError error={error} />
        <Button type="submit" variant="primary" className="w-full">Create account</Button>
      </form>
    </AuthShell>
  );
}
