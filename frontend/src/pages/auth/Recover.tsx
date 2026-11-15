import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { api, ApiError } from "../../lib/api";
import { AuthShell, Field, FormError, PASSWORD_HINT } from "./AuthShell";

export default function Recover() {
  const toast = useToast();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.recover(email, code.trim(), pw);
      toast("success", "Password reset. All your other sessions were signed out.");
      nav("/login");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Recovery failed");
    }
  };
  return (
    <AuthShell title="Reset your password" subtitle="TraceLayer does not send email. An administrator issues a one-time recovery code (valid for 60 minutes) and gives it to you directly."
      footer={<Link className="text-sky-300 hover:underline" to="/login">Back to sign in</Link>}>
      <form onSubmit={submit} className="space-y-4">
        <Field name="email" label="Email" type="email" autoComplete="username" value={email} onChange={setEmail} />
        <Field name="code" label="Recovery code" value={code} onChange={setCode} autoComplete="one-time-code" />
        <Field name="password" label="New password" type="password" autoComplete="new-password" value={pw} onChange={setPw} hint={PASSWORD_HINT} />
        <FormError error={error} />
        <Button type="submit" variant="primary" className="w-full">Reset password</Button>
      </form>
    </AuthShell>
  );
}
