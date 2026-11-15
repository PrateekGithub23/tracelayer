// Authentication state for the whole app.
//
// On load we ask the server who we are (/api/auth/me). The session cookie is HttpOnly, so this
// request is the *only* way the UI learns it is signed in. That is why a page refresh keeps you logged
// in until the server-side session expires or is revoked. `can()` only hides controls the user
// cannot use; every permission is enforced again by the API.

import { useQueryClient } from "@tanstack/react-query";
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, ApiError, setCsrfToken } from "./api";
import type { AuthConfig, Me } from "./types-v2";

type Status = "loading" | "anonymous" | "authenticated" | "expired" | "must_change_password";

interface AuthState {
  status: Status;
  me: Me | null;
  config: AuthConfig | null;
  expiredReason: string | null;
  can: (permission: string) => boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  adopt: (me: Me) => void;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<Status>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [expiredReason, setExpiredReason] = useState<string | null>(null);

  const adopt = useCallback((m: Me) => {
    setCsrfToken(m.csrf_token);
    setMe(m);
    setExpiredReason(null);
    setStatus(m.user.must_change_password ? "must_change_password" : "authenticated");
  }, []);

  const refresh = useCallback(async () => {
    try {
      adopt(await api.me());
    } catch (e) {
      setCsrfToken("");
      setMe(null);
      const reason = e instanceof ApiError ? (e.detail as any)?.reason : undefined;
      setStatus(reason === "expired" || reason === "revoked" ? "expired" : "anonymous");
      setExpiredReason(reason ?? null);
    }
  }, [adopt]);

  useEffect(() => {
    api.authConfig().then(setConfig).catch(() => setConfig(null));
    void refresh();
  }, [refresh]);

  // Any API call that discovers the session is gone moves the app to the "session expired" screen.
  useEffect(() => {
    const lost = (e: Event) => {
      setCsrfToken("");
      setMe(null);
      setExpiredReason(String((e as CustomEvent).detail ?? "expired"));
      setStatus("expired");
      qc.clear();
    };
    const mustChange = () => setStatus("must_change_password");
    window.addEventListener("tl:auth-lost", lost);
    window.addEventListener("tl:must-change-password", mustChange);
    return () => { window.removeEventListener("tl:auth-lost", lost); window.removeEventListener("tl:must-change-password", mustChange); };
  }, [qc]);

  const login = useCallback(async (email: string, password: string) => {
    adopt(await api.login(email, password));
    qc.clear();
  }, [adopt, qc]);

  const logout = useCallback(async () => {
    try { await api.logout(); } finally {
      setCsrfToken("");
      setMe(null);
      setStatus("anonymous");
      qc.clear();
    }
  }, [qc]);

  const value = useMemo<AuthState>(() => ({
    status, me, config, expiredReason, login, logout, refresh, adopt,
    can: (p: string) => !!me?.permissions.includes(p),
  }), [status, me, config, expiredReason, login, logout, refresh, adopt]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}

/** Renders children only when the current user holds `permission` (purely cosmetic; the API enforces it). */
export function Can({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  return useAuth().can(permission) ? <>{children}</> : <>{fallback}</>;
}
