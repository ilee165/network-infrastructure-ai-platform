/**
 * Incidents route RBAC guard tests (T17 review fix — Finding 1).
 *
 * The /incidents route must be wrapped in RoleRoute(minimum="viewer") as
 * defense-in-depth over the backend viewer+ RBAC on GET /docs (ADR-0019).
 * Every other sensitive operational page uses a frontend RoleRoute guard;
 * /incidents must be consistent.
 *
 * A user at "viewer" rank or above sees the IncidentReportsPage outlet; a user
 * with an unknown/absent role gets the forbidden view. Mirrors the
 * SettingsRoute.test.tsx isolated-subtree pattern.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
import { IncidentReportsPage } from "../pages/IncidentReportsPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

// Stub fetch so IncidentReportsPage does not make real network calls.
vi.stubGlobal(
  "fetch",
  vi.fn().mockResolvedValue(
    new Response(
      JSON.stringify({ items: [], total: 0, limit: 50, offset: 0 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  ),
);

function userWithRole(role: string): UserMe {
  return {
    id: "22222222-2222-2222-2222-222222222222",
    username: "u",
    email: null,
    display_name: null,
    role,
    is_active: true,
    must_change_password: false,
  };
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(resetStore);
afterEach(resetStore);

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

/** Mount the /incidents subtree exactly as App wires it. */
function renderIncidentsRoute(role: string) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user: userWithRole(role) });
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/incidents"]}>
        <Routes>
          <Route element={<RoleRoute minimum="viewer" />}>
            <Route path="/incidents" element={<IncidentReportsPage />} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("/incidents route — viewer+ RoleRoute guard", () => {
  it("renders the IncidentReportsPage for a viewer", async () => {
    renderIncidentsRoute("viewer");
    expect(await screen.findByText("Incident Reports")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("renders the IncidentReportsPage for an engineer", async () => {
    renderIncidentsRoute("engineer");
    expect(await screen.findByText("Incident Reports")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("renders the IncidentReportsPage for an admin", async () => {
    renderIncidentsRoute("admin");
    expect(await screen.findByText("Incident Reports")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("blocks a user with an unknown role with a forbidden view", () => {
    renderIncidentsRoute("unprivileged");
    expect(screen.queryByText("Incident Reports")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });
});
