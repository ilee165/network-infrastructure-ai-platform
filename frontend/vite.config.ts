import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Vite + Vitest configuration (ADR-0012).
 *
 * - Dev server proxies `/api` to the FastAPI backend on localhost:8000 so the
 *   SPA is same-origin in development (production uses nginx for the same).
 * - Vitest runs in jsdom with the shared setup file (jest-dom matchers +
 *   testing-library cleanup).
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
