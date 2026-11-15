// Route table and auth gating. Pages are code-split so the graph/chart libraries load only where used.
// Signed-out users only reach the auth screens; everything else requires a live server-side session.
import { lazy, type ReactNode, Suspense } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { EmptyState, Spinner } from "./components/ui";
import { useAuth } from "./lib/auth";
import { FullPageSpinner, MustChangePassword, SessionExpired } from "./pages/auth/Gates";

const Login = lazy(() => import("./pages/auth/Login"));
const Register = lazy(() => import("./pages/auth/Register"));
const Recover = lazy(() => import("./pages/auth/Recover"));
const Overview = lazy(() => import("./pages/Overview"));
const Investigations = lazy(() => import("./pages/Investigations"));
const InvestigationDetail = lazy(() => import("./pages/InvestigationDetail"));
const Events = lazy(() => import("./pages/Events"));
const Detections = lazy(() => import("./pages/Detections"));
const Integrity = lazy(() => import("./pages/Integrity"));
const Performance = lazy(() => import("./pages/Performance"));
const Ingest = lazy(() => import("./pages/Ingest"));
const Datasets = lazy(() => import("./pages/Datasets"));
const AiEngine = lazy(() => import("./pages/AiEngine"));
const Account = lazy(() => import("./pages/Account"));
const Admin = lazy(() => import("./pages/Admin"));
const Walkthrough = lazy(() => import("./pages/Walkthrough"));

function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth();
  return can(permission) ? <>{children}</> : (
    <EmptyState title="You don't have access to this page">
      Your role does not include <code className="font-mono">{permission}</code>. <Link className="text-sky-300" to="/">Back to overview</Link>
    </EmptyState>
  );
}

function SignedOut() {
  const loc = useLocation();
  return (
    <Suspense fallback={<FullPageSpinner />}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/recover" element={<Recover />} />
        <Route path="*" element={<Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />} />
      </Routes>
    </Suspense>
  );
}

export default function App() {
  const { status } = useAuth();
  const loc = useLocation();
  if (status === "loading") return <FullPageSpinner />;
  if (status === "expired" && !["/login", "/recover"].includes(loc.pathname)) return <SessionExpired />;
  if (status === "anonymous" || status === "expired") return <SignedOut />;
  if (status === "must_change_password") return <MustChangePassword />;
  return (
    <Layout>
      <Suspense fallback={<Spinner />}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/walkthrough" element={<Walkthrough />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/events" element={<Events />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/integrity" element={<Integrity />} />
          <Route path="/datasets" element={<Datasets />} />
          <Route path="/ai" element={<AiEngine />} />
          <Route path="/performance" element={<Performance />} />
          <Route path="/ingest" element={<RequirePermission permission="ingest:write"><Ingest /></RequirePermission>} />
          <Route path="/account" element={<Account />} />
          <Route path="/admin" element={<RequirePermission permission="users:manage"><Admin /></RequirePermission>} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<EmptyState title="Page not found"><Link className="text-sky-300" to="/">Back to overview</Link></EmptyState>} />
        </Routes>
      </Suspense>
    </Layout>
  );
}
