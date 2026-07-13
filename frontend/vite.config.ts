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
    rollupOptions: {
      output: {
        // Wave 5 / perf #5: isolate cytoscape from the entry chunk so /login
        // does not download the topology visualizer (~440 KB).
        manualChunks(id) {
          if (id.includes("node_modules/cytoscape")) {
            return "cytoscape";
          }
          if (id.includes("node_modules")) {
            return "vendor";
          }
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      // Ratchet floor (F2): raise over time; never lower to silence gaps.
      thresholds: {
        lines: 40,
        functions: 40,
        branches: 30,
        statements: 40,
      },
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/test/**",
        "src/main.tsx",
        "src/vite-env.d.ts",
      ],
    },
  },
});
