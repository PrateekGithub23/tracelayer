// End-to-end tests against the real backend (isolated SQLite) and the real UI (Vite dev server).
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  workers: 1, // one shared backend database; tests run in order
  use: { baseURL: "http://localhost:5174", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: [
    { command: "./e2e/backend.sh", url: "http://localhost:8010/api/health", reuseExistingServer: false, timeout: 60_000 },
    { command: "VITE_API_TARGET=http://localhost:8010 npx vite --port 5174 --strictPort", url: "http://localhost:5174", reuseExistingServer: false },
  ],
});
