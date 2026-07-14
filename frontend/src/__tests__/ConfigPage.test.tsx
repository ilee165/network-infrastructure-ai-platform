/**
 * ConfigPage tests: snapshots list, drift diff view, compliance posture —
 * mocked global fetch, no backend required.
 *
 * Mirrors the DevicesPage test pattern: fetchRouted() by URL substring,
 * QueryClientProvider wrapping, afterEach unstubAll.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  ComplianceRunResponse,
  ConfigSnapshotListResponse,
  DriftResponse,
} from "../api/config";
import type { DeviceListResponse } from "../api/devices";
import { ConfigPage } from "../pages/ConfigPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DEVICE_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

const DEVICE_LIST: DeviceListResponse = {
  items: [
    {
      id: DEVICE_ID,
      hostname: "core-sw-01",
      mgmt_ip: "192.168.1.1",
      vendor_id: "cisco",
      model: "Catalyst 9300",
      os_version: "17.3.4",
      serial: null,
      status: "reachable",
      site: null,
      credential_id: null,
      last_discovered_at: null,
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
    },
  ],
  total: 1,
  limit: 500,
  offset: 0,
};

const EMPTY_SNAPSHOTS: ConfigSnapshotListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

const SNAP_ID_A = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const SNAP_ID_B = "cccccccc-cccc-cccc-cccc-cccccccccccc";

const SNAPSHOTS_LIST: ConfigSnapshotListResponse = {
  items: [
    {
      id: SNAP_ID_A,
      device_id: DEVICE_ID,
      captured_at: "2024-01-15T10:00:00Z",
      content_hash: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      source: "scheduled",
      capture_run_id: null,
      baseline: true,
      created_at: "2024-01-15T10:00:00Z",
      updated_at: "2024-01-15T10:00:00Z",
    },
    {
      id: SNAP_ID_B,
      device_id: DEVICE_ID,
      captured_at: "2024-01-16T10:00:00Z",
      content_hash: "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      source: "on_demand",
      capture_run_id: null,
      baseline: false,
      created_at: "2024-01-16T10:00:00Z",
      updated_at: "2024-01-16T10:00:00Z",
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
};

const DRIFT_NO_CHANGE: DriftResponse = {
  device_id: DEVICE_ID,
  has_drift: false,
  diff: "",
  hunks: [],
  baseline_hash: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  current_hash: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
};

const DRIFT_WITH_CHANGE: DriftResponse = {
  device_id: DEVICE_ID,
  has_drift: true,
  diff: [
    "--- baseline",
    "+++ current",
    "@@ -1,3 +1,4 @@",
    " hostname core-sw-01",
    "-ntp server 10.0.0.1",
    "+ntp server 10.0.0.2",
    "+logging host 10.0.0.100",
  ].join("\n"),
  hunks: ["@@ -1,3 +1,4 @@"],
  baseline_hash: "sha256:aaaa",
  current_hash: "sha256:bbbb",
};

const COMPLIANCE_CLEAN: ComplianceRunResponse = {
  device_id: DEVICE_ID,
  policy_id: "baseline-hardening",
  policy_version: 1,
  findings: [
    {
      device_id: DEVICE_ID,
      policy_id: "baseline-hardening",
      policy_version: 1,
      rule_id: "no-telnet",
      severity: "violation",
      status: "pass",
      evidence: "",
    },
    {
      device_id: DEVICE_ID,
      policy_id: "baseline-hardening",
      policy_version: 1,
      rule_id: "ntp-configured",
      severity: "warn",
      status: "pass",
      evidence: "",
    },
  ],
  violation_count: 0,
  warn_count: 0,
  pass_count: 2,
  skipped_count: 0,
};

const COMPLIANCE_WITH_VIOLATIONS: ComplianceRunResponse = {
  device_id: DEVICE_ID,
  policy_id: "baseline-hardening",
  policy_version: 1,
  findings: [
    {
      device_id: DEVICE_ID,
      policy_id: "baseline-hardening",
      policy_version: 1,
      rule_id: "no-telnet",
      severity: "violation",
      status: "violation",
      evidence: "telnet found in line vty 0 4",
    },
    {
      device_id: DEVICE_ID,
      policy_id: "baseline-hardening",
      policy_version: 1,
      rule_id: "ntp-configured",
      severity: "warn",
      status: "violation",
      evidence: "no ntp server configured",
    },
    {
      device_id: DEVICE_ID,
      policy_id: "baseline-hardening",
      policy_version: 1,
      rule_id: "logging-host",
      severity: "info",
      status: "pass",
      evidence: "",
    },
  ],
  violation_count: 2,
  warn_count: 1,
  pass_count: 1,
  skipped_count: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Route fetch by URL path substring. Priority: drift > compliance > snapshots
 * > devices (fallback). Each call returns a fresh Response.
 */
function fetchRouted(opts: {
  devices?: unknown;
  snapshots?: unknown;
  drift?: unknown;
  compliance?: unknown;
}) {
  return vi.fn((url: string): Promise<Response> => {
    const u = String(url);
    let body: unknown;
    if (u.includes("/drift")) {
      body = opts.drift ?? DRIFT_NO_CHANGE;
    } else if (u.includes("/compliance")) {
      body = opts.compliance ?? COMPLIANCE_CLEAN;
    } else if (u.includes("/config-snapshots")) {
      body = opts.snapshots ?? EMPTY_SNAPSHOTS;
    } else {
      body = opts.devices ?? DEVICE_LIST;
    }
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
      <ConfigPage />
    </QueryClientProvider>,
  );
}

/** Select a device in the dropdown and return after device is chosen. */
async function selectDevice(): Promise<void> {
  const select = await screen.findByTestId("config-device-select");
  fireEvent.change(select, { target: { value: DEVICE_ID } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Page-level tests ──────────────────────────────────────────────────────────

describe("ConfigPage — initial state", () => {
  it("renders the page header", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByText("Config Management")).toBeInTheDocument();
  });

  it("shows a device selector after devices load", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByTestId("config-device-select")).toBeInTheDocument();
  });

  it("shows the no-device prompt before a device is selected", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByTestId("config-no-device")).toBeInTheDocument();
  });

  it("populates the device selector with the device hostname", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    const option = await screen.findByText(/core-sw-01/);
    expect(option).toBeInTheDocument();
  });

  it("hides the no-device prompt after selecting a device", async () => {
    vi.stubGlobal("fetch", fetchRouted({ snapshots: SNAPSHOTS_LIST }));
    renderPage();
    await selectDevice();
    await waitFor(() => {
      expect(screen.queryByTestId("config-no-device")).not.toBeInTheDocument();
    });
  });
});

// ── Snapshots tab ─────────────────────────────────────────────────────────────

describe("ConfigPage — Snapshots tab", () => {
  it("shows the snapshots empty state when no snapshots exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({ snapshots: EMPTY_SNAPSHOTS }));
    renderPage();
    await selectDevice();
    expect(await screen.findByTestId("snapshots-empty-state")).toBeInTheDocument();
  });

  it("renders a row per snapshot with captured_at and source", async () => {
    vi.stubGlobal("fetch", fetchRouted({ snapshots: SNAPSHOTS_LIST }));
    renderPage();
    await selectDevice();
    expect(await screen.findByTestId(`snapshot-row-${SNAP_ID_A}`)).toBeInTheDocument();
    expect(screen.getByTestId(`snapshot-row-${SNAP_ID_B}`)).toBeInTheDocument();
  });

  it("shows the baseline badge for the baseline snapshot", async () => {
    vi.stubGlobal("fetch", fetchRouted({ snapshots: SNAPSHOTS_LIST }));
    renderPage();
    await selectDevice();
    await screen.findByTestId(`snapshot-row-${SNAP_ID_A}`);
    expect(screen.getByText("baseline")).toBeInTheDocument();
  });

  it("shows the truncated content hash", async () => {
    vi.stubGlobal("fetch", fetchRouted({ snapshots: SNAPSHOTS_LIST }));
    renderPage();
    await selectDevice();
    await screen.findByTestId(`snapshot-row-${SNAP_ID_A}`);
    // The hash is sliced to 16 chars; "sha256:abcdef12" → first 16 chars of the hash string
    expect(screen.getByText(/sha256:abcdef12/)).toBeInTheDocument();
  });

  it("requests the canonical config-snapshots path", async () => {
    const mock = fetchRouted({ snapshots: SNAPSHOTS_LIST });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await selectDevice();
    await screen.findByTestId(`snapshot-row-${SNAP_ID_A}`);
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining(`/devices/${DEVICE_ID}/config-snapshots`),
      expect.anything(),
    );
  });

  it("shows an error alert when the snapshots API fails", async () => {
    const mock = vi.fn((url: string): Promise<Response> => {
      if (String(url).includes("/config-snapshots")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              type: "urn:netops:error:not-found",
              title: "Not Found",
              status: 404,
              detail: "device has no snapshots",
            }),
            { status: 404, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify(DEVICE_LIST), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await selectDevice();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Snapshots load failed: device has no snapshots",
    );
  });
});

// ── Drift tab ─────────────────────────────────────────────────────────────────

describe("ConfigPage — Drift tab", () => {
  async function goToDrift(): Promise<void> {
    await selectDevice();
    const driftTab = await screen.findByTestId("config-tab-drift");
    fireEvent.click(driftTab);
  }

  it("shows no-drift indicator when config matches baseline", async () => {
    vi.stubGlobal("fetch", fetchRouted({ drift: DRIFT_NO_CHANGE }));
    renderPage();
    await goToDrift();
    expect(await screen.findByTestId("drift-no-change")).toBeInTheDocument();
    expect(screen.getByTestId("drift-has-drift")).toHaveTextContent("No");
  });

  it("renders the unified diff when drift is detected", async () => {
    vi.stubGlobal("fetch", fetchRouted({ drift: DRIFT_WITH_CHANGE }));
    renderPage();
    await goToDrift();
    expect(await screen.findByTestId("unified-diff")).toBeInTheDocument();
    expect(screen.getByTestId("drift-has-drift")).toHaveTextContent("Yes");
  });

  it("shows diff lines with + prefix in the diff block", async () => {
    vi.stubGlobal("fetch", fetchRouted({ drift: DRIFT_WITH_CHANGE }));
    renderPage();
    await goToDrift();
    await screen.findByTestId("unified-diff");
    // The +logging host line should be visible
    expect(screen.getByText(/\+logging host/)).toBeInTheDocument();
  });

  it("shows the hunk summary when hunks are present", async () => {
    vi.stubGlobal("fetch", fetchRouted({ drift: DRIFT_WITH_CHANGE }));
    renderPage();
    await goToDrift();
    expect(await screen.findByTestId("drift-hunk-0")).toBeInTheDocument();
    expect(screen.getByTestId("drift-hunk-0")).toHaveTextContent("@@ -1,3 +1,4 @@");
  });

  it("requests the canonical drift path", async () => {
    const mock = fetchRouted({ drift: DRIFT_NO_CHANGE });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await goToDrift();
    await screen.findByTestId("drift-no-change");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining(`/devices/${DEVICE_ID}/drift`),
      expect.anything(),
    );
  });

  it("shows an error alert when the drift API fails", async () => {
    const mock = vi.fn((url: string): Promise<Response> => {
      if (String(url).includes("/drift")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              type: "urn:netops:error:not-found",
              title: "Not Found",
              status: 404,
              detail: "no approved baseline",
            }),
            { status: 404, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify(DEVICE_LIST), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await goToDrift();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Drift check failed: no approved baseline",
    );
  });
});

// ── Compliance tab ────────────────────────────────────────────────────────────

describe("ConfigPage — Compliance tab", () => {
  async function goToCompliance(): Promise<void> {
    await selectDevice();
    const complianceTab = await screen.findByTestId("config-tab-compliance");
    fireEvent.click(complianceTab);
  }

  it("shows zero violation count when device is compliant", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_CLEAN }));
    renderPage();
    await goToCompliance();
    expect(await screen.findByTestId("compliance-violation-count")).toHaveTextContent("0");
    expect(screen.getByTestId("compliance-pass-count")).toHaveTextContent("2");
  });

  it("shows the violation count when violations exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_WITH_VIOLATIONS }));
    renderPage();
    await goToCompliance();
    expect(await screen.findByTestId("compliance-violation-count")).toHaveTextContent("2");
    expect(screen.getByTestId("compliance-warn-count")).toHaveTextContent("1");
  });

  it("renders a row for each finding", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_WITH_VIOLATIONS }));
    renderPage();
    await goToCompliance();
    expect(await screen.findByTestId("finding-row-no-telnet")).toBeInTheDocument();
    expect(screen.getByTestId("finding-row-ntp-configured")).toBeInTheDocument();
    expect(screen.getByTestId("finding-row-logging-host")).toBeInTheDocument();
  });

  it("shows severity badges on findings", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_WITH_VIOLATIONS }));
    renderPage();
    await goToCompliance();
    await screen.findByTestId("finding-row-no-telnet");
    // At least one violation-severity badge
    expect(screen.getAllByTestId("severity-violation").length).toBeGreaterThan(0);
  });

  it("shows finding-status badges (violation and pass)", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_WITH_VIOLATIONS }));
    renderPage();
    await goToCompliance();
    await screen.findByTestId("finding-row-no-telnet");
    expect(screen.getAllByTestId("finding-status-violation").length).toBeGreaterThan(0);
    expect(screen.getAllByTestId("finding-status-pass").length).toBeGreaterThan(0);
  });

  it("shows the policy id and version in the summary bar", async () => {
    vi.stubGlobal("fetch", fetchRouted({ compliance: COMPLIANCE_CLEAN }));
    renderPage();
    await goToCompliance();
    await screen.findByTestId("compliance-violation-count");
    expect(screen.getByText(/baseline-hardening v1/)).toBeInTheDocument();
  });

  it("requests the canonical compliance path", async () => {
    const mock = fetchRouted({ compliance: COMPLIANCE_CLEAN });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await goToCompliance();
    await screen.findByTestId("compliance-violation-count");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining(`/devices/${DEVICE_ID}/compliance`),
      expect.anything(),
    );
  });

  it("shows an error alert when the compliance API fails", async () => {
    const mock = vi.fn((url: string): Promise<Response> => {
      if (String(url).includes("/compliance")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              type: "urn:netops:error:not-found",
              title: "Not Found",
              status: 404,
              detail: "no config snapshots to evaluate",
            }),
            { status: 404, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify(DEVICE_LIST), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();
    await goToCompliance();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Compliance check failed: no config snapshots to evaluate",
    );
  });
});
