// End-to-end tests for the static public demo build (dist-demo): no backend runs at all.
import { defineConfig } from "@playwright/test";

// VITE_BASE=/tracelayer/ reproduces GitHub Pages' repository sub-path (https://<user>.github.io/<repo>/).
const base = process.env.VITE_BASE ?? "/";

export default defineConfig({
  testDir: "e2e-demo",
  timeout: 60_000,
  workers: 1,
  use: { baseURL: `http://localhost:5180${base}`, screenshot: "only-on-failure" },
  webServer: { command: `VITE_DEMO=1 VITE_BASE=${base} npx vite preview --port 5180 --strictPort`, url: `http://localhost:5180${base}`, reuseExistingServer: false },
});
