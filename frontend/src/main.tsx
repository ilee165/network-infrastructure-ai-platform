/**
 * SPA entrypoint (composition root): React 18 root + TanStack Query client +
 * browser router around the route table in App.tsx.
 *
 * Server state lives exclusively in the Query cache; UI-local state lives in
 * Zustand (ADR-0012 decisions 3–4).
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { initAuth } from "./api/auth";
import { App } from "./App";
import "./index.css";

// Boot the auth session once at startup: POST /auth/refresh → GET /auth/me →
// status "authed", or status "anon" on failure. The store starts in "loading"
// and ProtectedRoute renders a loader until this resolves. Fire-and-forget — the
// store transition re-renders the gate; a failed boot is the expected anon path.
void initAuth();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
});

const container = document.getElementById("root");
if (container === null) {
  throw new Error("Root element #root not found — index.html is malformed.");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
