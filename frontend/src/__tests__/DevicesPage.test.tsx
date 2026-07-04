/**
 * DevicesPage tests: inventory table, empty state, discovery launcher,
 * and run status — mocked global fetch, no backend required.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DeviceListResponse } from "../api/devices";
import type { RunListResponse, RunStatus } from "../api/discovery";
import { DevicesPage } from "../pages/DevicesPage";
import { useUiStore } from "../stores/ui";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DEVICE_LIST: DeviceListResponse = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      hostname: "core-sw-01",
      mgmt_ip: "192.168.1.1",
      vendor_id: "cisco",
      model: "Catalyst 9300",
      os_version: "17.3.4",
      serial: "FCW2142P0KS",
      status: "active",
      credential_id: null,
      last_discovered_at: "2024-01-15T10:30:00Z",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-15T10:30:00Z",
    },
    {
      id: "22222222-2222-2222-2222-222222222222",
      hostname: "dist-sw-02",
      mgmt_ip: "192.168.1.2",
      vendor_id: "arista",
      model: "DCS-7050TX",
      os_version: "4.28.1F",
      serial: "JPE19460123",
      status: "active",
      credential_id: null,
      last_discovered_at: "2024-01-15T10:31:00Z",
      created_at: "2024-01-02T00:00:00Z",
      updated_at: "2024-01-15T10:31:00Z",
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
};

const EMPTY_LIST: DeviceListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

const EMPTY_RUNS: RunListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

const PENDING_RUN: RunStatus = {
  id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  status: "pending",
  seeds: ["10.0.0.1"],
  hop_limit: 2,
  allowlist: ["10.0.0.0/24"],
  credential_names: ["prod-ssh"],
  stats: {},
  error: null,
  created_at: "2024-01-15T11:00:00Z",
  started_at: null,
  finished_at: null,
};

const RUNS_WITH_PENDING: RunListResponse = {
  items: [PENDING_RUN],
  total: 1,
  limit: 50,
  offset: 0,
};

const RUNNING_RUN: RunStatus = {
  ...PENDING_RUN,
  id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  status: "running",
  started_at: "2024-01-15T11:01:00Z",
};

const RUNS_WITH_RUNNING: RunListResponse = {
  items: [RUNNING_RUN],
  total: 1,
  limit: 50,
  offset: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Fetch mock that routes by URL: /discovery/runs → runsBody, else → deviceBody.
 * Each call returns a fresh Response (body is single-use).
 */
function fetchRouted(deviceBody: unknown, runsBody: unknown) {
  return vi.fn((url: string): Promise<Response> => {
    const body = String(url).includes("/discovery/runs") ? runsBody : deviceBody;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <DevicesPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  useUiStore.setState({ toasts: [] });
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("DevicesPage — loading state", () => {
  it("shows skeleton placeholder rows (not visible text) while the inventory loads", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );
    renderPage();

    // Skeleton rows render as empty <td>s inside the inventory table shell.
    const skeletonCells = document.querySelectorAll("td .animate-pulse");
    expect(skeletonCells.length).toBeGreaterThan(0);
  });

  it("announces the inventory loading state to screen readers via a visually-hidden status", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );
    renderPage();

    const status = screen.getByRole("status", { name: /loading inventory/i });
    expect(status.closest("tr")).toHaveClass("sr-only");
  });
});

describe("DevicesPage — inventory table", () => {
  it("renders one row per device with hostname, mgmt IP, vendor, model, OS and status", async () => {
    vi.stubGlobal("fetch", fetchRouted(DEVICE_LIST, EMPTY_RUNS));
    renderPage();

    expect(await screen.findByText("core-sw-01")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    expect(screen.getByText("cisco")).toBeInTheDocument();
    expect(screen.getByText("Catalyst 9300")).toBeInTheDocument();
    expect(screen.getByText("17.3.4")).toBeInTheDocument();

    expect(screen.getByText("dist-sw-02")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.2")).toBeInTheDocument();
    expect(screen.getByText("arista")).toBeInTheDocument();
  });

  it("shows the empty state when no devices exist", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, EMPTY_RUNS));
    renderPage();

    expect(await screen.findByTestId("devices-empty-state")).toBeInTheDocument();
  });

  it("shows an error alert when the devices API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(/Failed to fetch/);
  });

  it("requests the canonical devices path", async () => {
    const mock = fetchRouted(DEVICE_LIST, EMPTY_RUNS);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await screen.findByText("core-sw-01");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/devices"),
      expect.anything(),
    );
  });
});

describe("DevicesPage — discovery launcher", () => {
  it("renders the launcher form fields", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, EMPTY_RUNS));
    renderPage();

    await screen.findByTestId("devices-empty-state");
    expect(screen.getByTestId("launcher-seeds-input")).toBeInTheDocument();
    expect(screen.getByTestId("launcher-hop-limit-input")).toBeInTheDocument();
    expect(screen.getByTestId("launcher-allowlist-input")).toBeInTheDocument();
    expect(screen.getByTestId("launcher-credentials-input")).toBeInTheDocument();
    expect(screen.getByTestId("launcher-submit-btn")).toBeInTheDocument();
  });

  it("submits the correct StartRunRequest payload", async () => {
    const postResponse = new Response(JSON.stringify(PENDING_RUN), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    });

    const mock = vi.fn((url: string, init?: RequestInit): Promise<Response> => {
      if ((init as RequestInit | undefined)?.method === "POST") {
        return Promise.resolve(postResponse);
      }
      const body = String(url).includes("/discovery/runs") ? EMPTY_RUNS : EMPTY_LIST;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    // Wait for the form to be present (empty state rendered)
    await screen.findByTestId("launcher-seeds-input");

    fireEvent.change(screen.getByTestId("launcher-seeds-input"), {
      target: { value: "10.0.0.1" },
    });
    fireEvent.change(screen.getByTestId("launcher-hop-limit-input"), {
      target: { value: "2" },
    });
    fireEvent.change(screen.getByTestId("launcher-allowlist-input"), {
      target: { value: "10.0.0.0/24" },
    });
    fireEvent.change(screen.getByTestId("launcher-credentials-input"), {
      target: { value: "prod-ssh" },
    });

    fireEvent.click(screen.getByTestId("launcher-submit-btn"));

    await waitFor(() => {
      const postCall = mock.mock.calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === "POST",
      );
      expect(postCall).toBeDefined();
      const body = JSON.parse((postCall![1] as RequestInit).body as string) as unknown;
      expect(body).toEqual({
        seeds: ["10.0.0.1"],
        hop_limit: 2,
        allowlist: ["10.0.0.0/24"],
        credential_names: ["prod-ssh"],
      });
    });
  });
});

describe("DevicesPage — run status list", () => {
  it("renders a run status badge for a pending run", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, RUNS_WITH_PENDING));
    renderPage();

    expect(await screen.findByTestId("run-status-pending")).toBeInTheDocument();
  });

  it("shows the run seed IPs", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, RUNS_WITH_PENDING));
    renderPage();

    expect(await screen.findByTestId("run-status-pending")).toBeInTheDocument();
    expect(screen.getByText(/10\.0\.0\.1/)).toBeInTheDocument();
  });

  it("renders a running run with the accent (info) tone, restoring its pre-shared-primitive tone", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, RUNS_WITH_RUNNING));
    renderPage();

    const badge = await screen.findByTestId("run-status-running");
    expect(badge).toHaveClass("border-accent/40", "bg-accent/10", "text-accent");
  });

  it("never fires a per-run GET /discovery/runs/{id} request — status comes from the list poll only", async () => {
    const mock = fetchRouted(EMPTY_LIST, RUNS_WITH_PENDING);
    vi.stubGlobal("fetch", mock);
    renderPage();

    // Wait for the run badge to appear (list poll has resolved).
    await screen.findByTestId("run-status-pending");

    // No call should have targeted the individual run URL.
    const perRunCalls = mock.mock.calls.filter(([url]: [string]) =>
      new RegExp(`/discovery/runs/${PENDING_RUN.id}`).test(String(url)),
    );
    expect(perRunCalls).toHaveLength(0);
  });
});

describe("DevicesPage — expandable row a11y", () => {
  const DEVICE_ID = "11111111-1111-1111-1111-111111111111";

  it("toggles aria-expanded and reveals the detail panel on click", async () => {
    vi.stubGlobal("fetch", fetchRouted(DEVICE_LIST, EMPTY_RUNS));
    renderPage();

    const row = await screen.findByTestId(`device-row-${DEVICE_ID}`);
    expect(row).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(await screen.findByTestId(`device-detail-${DEVICE_ID}`)).toBeInTheDocument();

    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "false");
  });

  it("toggles expansion with the Enter and Space keys (keyboard operability)", async () => {
    vi.stubGlobal("fetch", fetchRouted(DEVICE_LIST, EMPTY_RUNS));
    renderPage();

    const row = await screen.findByTestId(`device-row-${DEVICE_ID}`);
    expect(row).toHaveAttribute("tabIndex", "0");

    fireEvent.keyDown(row, { key: "Enter" });
    expect(row).toHaveAttribute("aria-expanded", "true");

    fireEvent.keyDown(row, { key: " " });
    expect(row).toHaveAttribute("aria-expanded", "false");
  });

  it("applies a reduced-motion-safe transition to the expanded panel", async () => {
    vi.stubGlobal("fetch", fetchRouted(DEVICE_LIST, EMPTY_RUNS));
    renderPage();

    const row = await screen.findByTestId(`device-row-${DEVICE_ID}`);
    fireEvent.click(row);
    const detail = await screen.findByTestId(`device-detail-${DEVICE_ID}`);
    expect(detail).toHaveClass("transition-opacity", "motion-reduce:transition-none");
  });

  it("announces the interfaces panel loading state to screen readers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string): Promise<Response> => {
        if (String(url).includes("/interfaces")) {
          return new Promise<Response>(() => {});
        }
        return fetchRouted(DEVICE_LIST, EMPTY_RUNS)(url);
      }),
    );
    renderPage();

    const row = await screen.findByTestId(`device-row-${DEVICE_ID}`);
    fireEvent.click(row);

    const status = await screen.findByRole("status", { name: /loading interfaces/i });
    expect(status.closest("tr")).toHaveClass("sr-only");
  });

  it("announces the neighbors panel loading state to screen readers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string): Promise<Response> => {
        if (String(url).includes("/neighbors")) {
          return new Promise<Response>(() => {});
        }
        return fetchRouted(DEVICE_LIST, EMPTY_RUNS)(url);
      }),
    );
    renderPage();

    const row = await screen.findByTestId(`device-row-${DEVICE_ID}`);
    fireEvent.click(row);
    fireEvent.click(await screen.findByText("Neighbors"));

    const status = await screen.findByRole("status", { name: /loading neighbors/i });
    expect(status.closest("tr")).toHaveClass("sr-only");
  });
});

describe("DevicesPage — discovery-run mutation outcomes routed through toast", () => {
  it("pushes a success toast when a discovery run starts", async () => {
    const postResponse = new Response(JSON.stringify(PENDING_RUN), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    });
    const mock = vi.fn((url: string, init?: RequestInit): Promise<Response> => {
      if ((init as RequestInit | undefined)?.method === "POST") {
        return Promise.resolve(postResponse);
      }
      const body = String(url).includes("/discovery/runs") ? EMPTY_RUNS : EMPTY_LIST;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    await screen.findByTestId("launcher-seeds-input");
    fireEvent.change(screen.getByTestId("launcher-seeds-input"), {
      target: { value: "10.0.0.1" },
    });
    fireEvent.change(screen.getByTestId("launcher-allowlist-input"), {
      target: { value: "10.0.0.0/24" },
    });
    fireEvent.click(screen.getByTestId("launcher-submit-btn"));

    await waitFor(() => {
      expect(useUiStore.getState().toasts).toHaveLength(1);
    });
    expect(useUiStore.getState().toasts[0]).toMatchObject({
      kind: "success",
      message: "Discovery run started.",
    });
  });

  it("shows a spinner on the submit button while the run is starting", async () => {
    let resolvePost!: (value: Response) => void;
    const mock = vi.fn((url: string, init?: RequestInit): Promise<Response> => {
      if ((init as RequestInit | undefined)?.method === "POST") {
        return new Promise<Response>((resolve) => {
          resolvePost = resolve;
        });
      }
      const body = String(url).includes("/discovery/runs") ? EMPTY_RUNS : EMPTY_LIST;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    await screen.findByTestId("launcher-seeds-input");
    fireEvent.change(screen.getByTestId("launcher-seeds-input"), {
      target: { value: "10.0.0.1" },
    });
    fireEvent.change(screen.getByTestId("launcher-allowlist-input"), {
      target: { value: "10.0.0.0/24" },
    });
    const submit = screen.getByTestId("launcher-submit-btn");
    fireEvent.click(submit);

    await waitFor(() => expect(submit).toBeDisabled());
    expect(within(submit).getByRole("status")).toBeInTheDocument();

    resolvePost(
      new Response(JSON.stringify(PENDING_RUN), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
});
