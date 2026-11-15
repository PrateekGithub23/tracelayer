// Route table. Pages are code-split so the graph/chart libraries load only where used.
import { lazy, Suspense } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { EmptyState, Spinner } from "./components/ui";

const Overview = lazy(() => import("./pages/Overview"));
const Investigations = lazy(() => import("./pages/Investigations"));
const InvestigationDetail = lazy(() => import("./pages/InvestigationDetail"));
const Events = lazy(() => import("./pages/Events"));
const Detections = lazy(() => import("./pages/Detections"));
const Integrity = lazy(() => import("./pages/Integrity"));
const Performance = lazy(() => import("./pages/Performance"));
const Ingest = lazy(() => import("./pages/Ingest"));

export default function App() {
  return (
    <Layout>
      <Suspense fallback={<Spinner />}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/events" element={<Events />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/integrity" element={<Integrity />} />
          <Route path="/performance" element={<Performance />} />
          <Route path="/ingest" element={<Ingest />} />
          <Route path="*" element={<EmptyState title="Page not found"><Link className="text-sky-300" to="/">Back to overview</Link></EmptyState>} />
        </Routes>
      </Suspense>
    </Layout>
  );
}
