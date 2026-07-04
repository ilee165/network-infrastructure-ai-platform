/**
 * axe-core accessibility audit across the five Wave-4 core pages (audit
 * UI_UX #5c): render each page in a realistic loaded state and assert zero
 * serious/critical axe violations.
 *
 * `color-contrast` is disabled in the run options: jsdom has no real layout
 * engine, so axe cannot reliably compute rendered contrast there (a known
 * jsdom/axe limitation) — contrast is exercised by manual/visual QA instead,
 * per the Wave 4 test plan. All other axe-core rules run at their default
 * severity.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import type { AxeResults } from "axe-core";
import type { DeviceListResponse } from "../api/devices";
import type { RunListResponse } from "../api/discovery";
import { ChangePasswordPage } from "../pages/ChangePasswordPage";
import { ChangesPage } from "../pages/ChangesPage";
import { DashboardPage } from "../pages/DashboardPage";
import { DevicesPage } from "../pages/DevicesPage";
import { LoginPage } from "../pages/LoginPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";
import { useUiStore } from "../stores/ui";

vi.mock("../api/changes", () => ({
  listChangeRequests: vi.fn(),
  getChangeRequest: vi.fn(),
  approveChangeRequest: vi.fn(),
  rejectChangeRequest: vi.fn(),
}));

import { listChangeRequests } from "../api/changes";
import type { ChangeRequestListResponse } from "../api/changes";

/** axe-core run options shared by every page in this audit (see file header). */
const AXE_OPTIONS = { rules: { "color-contrast": { enabled: false } } };

/** The wave's bar is zero serious/critical findings — lower-impact findings don't fail the gate. */
function expectNoSeriousViolations(results: AxeResults): void {
  const serious = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(serious).toEqual([]);
}

function makeQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

const ENGINEER: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "engineer",
  is_active: true,
  must_change_password: false,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  useAuthStore.setState({ accessToken: null, user: null, status: "anon" });
  useUiStore.setState({ toasts: [] });
});

describe("axe — core pages (audit UI_UX #5)", () => {
  it("LoginPage has no serious/critical violations", async () => {
    const { container } = render(
      <MemoryRouter initialEntries={["/login"]}>
        <LoginPage />
      </MemoryRouter>,
    );
    await screen.findByTestId("login-page");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("ChangePasswordPage has no serious/critical violations", async () => {
    useAuthStore.setState({
      accessToken: "tok",
      status: "authed",
      user: { ...ENGINEER, must_change_password: true },
    });

    const { container } = render(
      <MemoryRouter initialEntries={["/change-password"]}>
        <ChangePasswordPage />
      </MemoryRouter>,
    );
    await screen.findByTestId("change-password-page");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("DashboardPage has no serious/critical violations", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (): Promise<Response> =>
          Promise.resolve(
            new Response(
              JSON.stringify({
                status: "ok",
                dependencies: {
                  postgres: { status: "ok", latency_ms: 3.2, error: null },
                  neo4j: { status: "ok", latency_ms: 5.1, error: null },
                  redis: { status: "ok", latency_ms: 1.4, error: null },
                },
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            ),
          ),
      ),
    );

    const { container } = render(
      <QueryClientProvider client={makeQueryClient()}>
        <DashboardPage />
      </QueryClientProvider>,
    );
    await screen.findByTestId("dependency-card-postgres");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("DevicesPage has no serious/critical violations", async () => {
    const emptyDevices: DeviceListResponse = { items: [], total: 0, limit: 50, offset: 0 };
    const emptyRuns: RunListResponse = { items: [], total: 0, limit: 50, offset: 0 };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string): Promise<Response> => {
        const body = String(url).includes("/discovery/runs") ? emptyRuns : emptyDevices;
        return Promise.resolve(
          new Response(JSON.stringify(body), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );

    const { container } = render(
      <QueryClientProvider client={makeQueryClient()}>
        <DevicesPage />
      </QueryClientProvider>,
    );
    await screen.findByTestId("devices-empty-state");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("ChangesPage has no serious/critical violations", async () => {
    useAuthStore.setState({ accessToken: "tok", user: ENGINEER, status: "authed" });
    const emptyList: ChangeRequestListResponse = { items: [], total: 0, limit: 50, offset: 0 };
    vi.mocked(listChangeRequests).mockResolvedValue(emptyList);

    const { container } = render(
      <QueryClientProvider client={makeQueryClient()}>
        <ChangesPage />
      </QueryClientProvider>,
    );
    await screen.findByTestId("cr-empty-state");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });
});
