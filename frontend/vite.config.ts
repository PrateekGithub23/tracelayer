/// <reference types="vitest" />
// Vite config. In development, /api is proxied to the FastAPI backend so the
// browser sees a single origin (no CORS, same paths as the nginx production setup).
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// VITE_DEMO=1 builds the static public demo: browser-local data from demo-public/, no backend.
// The demo snapshot lives outside public/ so it is never shipped inside the real application build.
const demo = process.env.VITE_DEMO === "1";

export default defineConfig({
  plugins: [react()],
  publicDir: demo ? "demo-public" : "public",
  base: process.env.VITE_BASE ?? "/",
  server: {
    port: 5173,
    proxy: { "/api": { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true } },
  },
  build: { chunkSizeWarningLimit: 1200, outDir: demo ? "dist-demo" : "dist" },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"], include: ["src/**/*.test.{ts,tsx}"] },
});
