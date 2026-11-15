// Application entry: fonts (bundled locally, no CDN), React Query, router, evidence inspector.
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "./index.css";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { InspectorProvider } from "./components/EvidenceInspector";
import { ToastProvider } from "./components/Toast";
import { demoTransport } from "./demo/transport";
import { ApiError, setTransport } from "./lib/api";
import { AuthProvider } from "./lib/auth";

// The public demo build (VITE_DEMO=1) serves recorded API responses from the browser: no backend at all.
if (import.meta.env.VITE_DEMO === "1") setTransport(demoTransport);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      // Don't hammer the API on 4xx (bad request / not found); retry transient failures once.
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 1,
    },
    mutations: {
      retry: false,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* Base keeps its trailing slash, so the root route is "/<repo>/" (what static hosts serve), never "/<repo>". */}
      <BrowserRouter basename={import.meta.env.BASE_URL}>
        <ToastProvider>
          <AuthProvider>
            <InspectorProvider>
              <App />
            </InspectorProvider>
          </AuthProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
