/**
 * DashboardPage tests: readiness states rendered from a mocked global fetch —
 * no backend, Postgres, Neo4j, or Redis required.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReadinessReport } from "../api/health";
import { DashboardPage } from "../pages/DashboardPage";

const HEALTHY: ReadinessReport = {
  status: "ok",
  dependencies: {
    postgres: { status: "ok", latency_ms: 3.2, error: null },
    neo4j: { status: "ok", latency_ms: 5.1, error: null },
    redis: { status: "ok", latency_ms: 1.4, error: null },
  },
};

const DEGRADED: ReadinessReport = {
  status: "degraded",
  dependencies: {
    postgres: { status: "ok", latency_ms: 3.2, error: null },
    neo4j: { status: "error", latency_ms: 2001.0, error: "TimeoutError: probe timed out" },
    redis: { status: "ok", latency_ms: 1.4, error: null },
  },
};

/**
 * Build a fetch mock returning a FRESH Response per call — a Response body is
 * single-use, so sharing one across refetches would throw "body already read".
 */
function fetchReturning(body: unknown, status = 200) {
  return vi.fn(
    (): Promise<Response> =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      ),
  );
}

function renderDashboard(): void {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <DashboardPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DashboardPage", () => {
  it("renders one ok card per dependency when all probes pass", async () => {
    vi.stubGlobal("fetch", fetchReturning(HEALTHY));
    renderDashboard();

    expect(await screen.findByTestId("dependency-card-postgres")).toHaveTextContent("ok");
    expect(screen.getByTestId("dependency-card-neo4j")).toHaveTextContent("ok");
    expect(screen.getByTestId("dependency-card-redis")).toHaveTextContent("ok");
    expect(screen.getByTestId("overall-status")).toHaveTextContent("ok");
  });

  it("surfaces the failing dependency and its error when degraded", async () => {
    vi.stubGlobal("fetch", fetchReturning(DEGRADED));
    renderDashboard();

    expect(await screen.findByTestId("dependency-card-neo4j")).toHaveTextContent("error");
    expect(screen.getByText("TimeoutError: probe timed out")).toBeInTheDocument();
    expect(screen.getByTestId("overall-status")).toHaveTextContent("degraded");
    // Healthy siblings still render as ok.
    expect(screen.getByTestId("dependency-card-postgres")).toHaveTextContent("ok");
  });

  it("shows an error alert when the API is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderDashboard();

    expect(await screen.findByRole("alert")).toHaveTextContent(/Failed to fetch/);
  });

  it("shows an error alert with problem details on a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      fetchReturning(
        {
          type: "urn:netops:error:internal",
          title: "Internal Server Error",
          status: 500,
          detail: "unexpected failure",
        },
        500,
      ),
    );
    renderDashboard();

    // ErrorBanner (audit UI_UX #3) renders the RFC 7807 `detail`, not `title`.
    expect(await screen.findByRole("alert")).toHaveTextContent(/unexpected failure/);
  });

  it("requests the canonical readiness path", async () => {
    const fetchMock = fetchReturning(HEALTHY);
    vi.stubGlobal("fetch", fetchMock);
    renderDashboard();

    await screen.findByTestId("dependency-card-postgres");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/health/ready", expect.anything());
  });

  it("shows skeleton placeholder cards (not text) while probing", () => {
    // A promise that never resolves keeps the query in its pending state.
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );
    renderDashboard();

    expect(screen.getByTestId("dependency-card-skeleton-0")).toBeInTheDocument();
    expect(screen.queryByText(/probing dependencies/i)).not.toBeInTheDocument();
  });
});
