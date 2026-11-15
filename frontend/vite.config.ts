/// <reference types="vitest" />
// Vite config. In development, /api is proxied to the FastAPI backend so the
// browser sees a single origin (no CORS, same paths as the nginx production setup).
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true } },
  },
  build: { chunkSizeWarningLimit: 1200 },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"] },
});
