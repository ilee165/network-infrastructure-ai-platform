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

import { fireEvent, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import { axe } from "vitest-axe";
import type { AxeResults } from "axe-core";
import type {
  DeviceInterfaceRead,
  DeviceListResponse,
  DeviceNeighborRead,
  DeviceRead,
} from "../api/devices";
import type { RunListResponse, RunStatus } from "../api/discovery";
import { ChangePasswordPage } from "../pages/ChangePasswordPage";
import { ChangesPage } from "../pages/ChangesPage";
import { DashboardPage } from "../pages/DashboardPage";
import { DevicesPage } from "../pages/DevicesPage";
import { LoginPage } from "../pages/LoginPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";
import { useUiStore } from "../stores/ui";

vi.mock("../api/changes", async () => (await import("../test/test-utils")).mockChangesApi(() => ({
  listChangeRequests: vi.fn(),
  getChangeRequest: vi.fn(),
  approveChangeRequest: vi.fn(),
  rejectChangeRequest: vi.fn(),
}))());

import { approveChangeRequest, listChangeRequests } from "../api/changes";
import type { ChangeRequestListResponse, ChangeRequestRead } from "../api/changes";

/** axe-core run options shared by every page in this audit (see file header). */
const AXE_OPTIONS = { rules: { "color-contrast": { enabled: false } } };

/** The wave's bar is zero serious/critical findings — lower-impact findings don't fail the gate. */
function expectNoSeriousViolations(results: AxeResults): void {
  const serious = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(serious).toEqual([]);
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

// ── Loaded-state fixtures (audit UI_UX #5c) ─────────────────────────────────
// Zero-row renders never exercise StatusPill rows, the keyboard-operable
// expandable <tr role="button">, or Spinner-in-button markup, so the
// zero-row-only axe suite could pass even if any of those had an
// accessibility defect. These fixtures populate that state.

const DEVICE_ROW: DeviceRead = {
  id: "33333333-3333-3333-3333-333333333333",
  hostname: "core-sw-01",
  mgmt_ip: "192.168.1.1",
  vendor_id: "cisco",
  model: "Catalyst 9300",
  os_version: "17.3.4",
  serial: "FCW2142P0KS",
  status: "reachable",
  site: null,
  credential_id: null,
  last_discovered_at: "2024-01-15T10:30:00Z",
  created_at: "2024-01-01T00:00:00Z",
  updated_at: "2024-01-15T10:30:00Z",
};

const LOADED_DEVICES: DeviceListResponse = { items: [DEVICE_ROW], total: 1, limit: 50, offset: 0 };

const RUNNING_RUN: RunStatus = {
  id: "44444444-4444-4444-4444-444444444444",
  status: "running",
  seeds: ["10.0.0.1"],
  hop_limit: 2,
  allowlist: ["10.0.0.0/24"],
  credential_names: ["prod-ssh"],
  stats: {},
  error: null,
  created_at: "2024-01-15T11:00:00Z",
  started_at: "2024-01-15T11:00:01Z",
  finished_at: null,
};

const LOADED_RUNS: RunListResponse = { items: [RUNNING_RUN], total: 1, limit: 50, offset: 0 };

const DEVICE_INTERFACES: DeviceInterfaceRead[] = [
  {
    id: "55555555-5555-5555-5555-555555555555",
    name: "Gi1/0/1",
    description: "uplink",
    admin_status: "up",
    oper_status: "up",
    mac_address: "aa:bb:cc:dd:ee:ff",
    ip_address: "192.168.1.1",
    mtu: 1500,
    speed_mbps: 1000,
    duplex: "full",
    vlan_id: 10,
    input_errors: 0,
    output_errors: 0,
    collected_at: "2024-01-15T10:30:00Z",
    source_vendor: "cisco",
  },
];

const DEVICE_NEIGHBORS: DeviceNeighborRead[] = [
  {
    id: "66666666-6666-6666-6666-666666666666",
    protocol: "lldp",
    local_interface: "Gi1/0/1",
    neighbor_name: "dist-sw-02",
    neighbor_interface: "Gi1/0/24",
    neighbor_platform: "Catalyst 9500",
    neighbor_address: "192.168.1.2",
    neighbor_capabilities: ["switch"],
    collected_at: "2024-01-15T10:30:00Z",
    source_vendor: "cisco",
  },
];

const LOADED_CR_LIST: ChangeRequestListResponse = {
  items: [
    {
      id: "77777777-7777-7777-7777-777777777777",
      state: "pending_approval",
      kind: "config",
      requester_id: "88888888-8888-8888-8888-888888888888",
      four_eyes_required: true,
      target_refs: { device_ids: ["core-sw-01"] },
      reasoning_trace_id: null,
      created_at: "2026-06-18T10:00:00Z",
      updated_at: "2026-06-18T10:00:00Z",
    },
    {
      id: "99999999-9999-9999-9999-999999999999",
      state: "executing",
      kind: "ddi",
      requester_id: ENGINEER.id,
      four_eyes_required: false,
      target_refs: { dns_records: ["www.example.com"] },
      reasoning_trace_id: null,
      created_at: "2026-06-18T11:00:00Z",
      updated_at: "2026-06-18T11:00:00Z",
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  useAuthStore.setState({ accessToken: null, user: null, status: "anon" });
  useUiStore.setState({ toasts: [] });
});

describe("axe — core pages (audit UI_UX #5)", () => {
  it("LoginPage has no serious/critical violations", async () => {
    const { container } = renderWithQueryClient(
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

    const { container } = renderWithQueryClient(<MemoryRouter initialEntries={["/change-password"]}>
        <ChangePasswordPage />
      </MemoryRouter>);
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

    const { container } = renderWithQueryClient(
        <DashboardPage />
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

    const { container } = renderWithQueryClient(
        <DevicesPage />
      );
    await screen.findByTestId("devices-empty-state");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("ChangesPage has no serious/critical violations", async () => {
    useAuthStore.setState({ accessToken: "tok", user: ENGINEER, status: "authed" });
    const emptyList: ChangeRequestListResponse = { items: [], total: 0, limit: 50, offset: 0 };
    vi.mocked(listChangeRequests).mockResolvedValue(emptyList);

    const { container } = renderWithQueryClient(
        <ChangesPage />
      );
    await screen.findByTestId("cr-empty-state");

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  // The zero-row cases above never render a StatusPill, the keyboard-operable
  // expandable <tr role="button">, or Spinner-in-button markup — a defect in
  // any of those could still pass an axe suite that only ever sees empty
  // states. These loaded-state cases populate the tables so axe actually
  // traverses that markup.

  it("DevicesPage (loaded, with an expanded row) has no serious/critical violations", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string): Promise<Response> => {
        const target = String(url);
        let body: unknown;
        if (target.includes("/interfaces")) {
          body = DEVICE_INTERFACES;
        } else if (target.includes("/neighbors")) {
          body = DEVICE_NEIGHBORS;
        } else if (target.includes("/discovery/runs")) {
          body = LOADED_RUNS;
        } else {
          body = LOADED_DEVICES;
        }
        return Promise.resolve(
          new Response(JSON.stringify(body), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );

    const { container } = renderWithQueryClient(
        <DevicesPage />
      );

    // Populated inventory row (exercises the device-status StatusPill) and
    // populated discovery-runs row (exercises the run-status StatusPill).
    const row = await screen.findByTestId(`device-row-${DEVICE_ROW.id}`);
    await screen.findByTestId(`run-status-${RUNNING_RUN.status}`);

    // Expand the row (keyboard-operable <tr role="button">) so its detail
    // panel — with its own populated interfaces table — is in the DOM too.
    fireEvent.click(row);
    await screen.findByTestId(`device-detail-${DEVICE_ROW.id}`);
    await screen.findByText(DEVICE_INTERFACES[0]!.name);

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });

  it("ChangesPage (loaded, decision in flight) has no serious/critical violations", async () => {
    useAuthStore.setState({ accessToken: "tok", user: ENGINEER, status: "authed" });
    vi.mocked(listChangeRequests).mockResolvedValue(LOADED_CR_LIST);
    // Held pending so the approve button renders its Spinner-in-button markup
    // during the axe check.
    vi.mocked(approveChangeRequest).mockReturnValue(new Promise(() => {}));

    const { container } = renderWithQueryClient(
        <ChangesPage />
      );

    const [pendingCr, executingCr] = LOADED_CR_LIST.items as [
      ChangeRequestRead,
      ChangeRequestRead,
    ];
    await screen.findByTestId(`cr-row-${pendingCr.id}`);
    // Populated kind/state StatusPills, including the "executing" state.
    await screen.findByTestId(`cr-state-${executingCr.id}`);

    fireEvent.click(screen.getByTestId(`cr-view-${pendingCr.id}`));
    fireEvent.click(await screen.findByTestId("cr-approve-btn"));
    await screen.findByRole("status", { name: "Approving" });

    const results = await axe(container, AXE_OPTIONS);
    expectNoSeriousViolations(results);
  });
});
