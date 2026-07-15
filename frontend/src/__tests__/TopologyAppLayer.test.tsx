/**
 * TopologyPage application-dependency layer tests (P4 W2-T4, rider P9).
 *
 * Verifies the ``app`` layer toggle and the app-dependency panel it reveals:
 *  - the App layer button renders alongside L2 / L3 / DNS / All and sends
 *    layer=app to the topology/graph endpoint;
 *  - DEPENDS_ON edges render with a per-source badge (manual / f5 / vmware / dns);
 *  - the panel shows the projection watermark and an honest empty state.
 *
 * Mirrors TopologyDnsLayer.test.tsx: mocked cytoscape (jsdom has no canvas) +
 * mocked global fetch.
 */

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { TopologyGraph } from "../api/topology";
import { TopologyPage } from "../pages/TopologyPage";

vi.mock("cytoscape", () => {
  // Must cover everything the Wave-5 persistent TopologyCanvas calls
  // (pan/zoom/batch/elements/add/nodes/getElementById) — a partial mock
  // makes the canvas effect throw and the whole page render empty.
  const factory = vi.fn(() => ({
    on: vi.fn(),
    destroy: vi.fn(),
    resize: vi.fn(),
    fit: vi.fn(),
    pan: () => ({ x: 0, y: 0 }),
    zoom: () => 1,
    viewport: vi.fn(),
    batch: (fn: () => void) => fn(),
    elements: () => ({ remove: vi.fn() }),
    add: vi.fn(),
    nodes: () => ({ forEach: vi.fn() }),
    getElementById: () => ({ nonempty: () => false, position: vi.fn() }),
    layout: () => ({ run: vi.fn() }),
  }));
  return { default: factory };
});

// ── Fixtures ──────────────────────────────────────────────────────────────────

const GRAPH_WITH_DEPENDS_ON: TopologyGraph = {
  nodes: [
    {
      label: "Application",
      key: "app-1",
      properties: { name: "billing-web", origin: "manual" },
    },
    {
      label: "Device",
      key: "dev-1",
      properties: { hostname: "core-sw-01" },
    },
  ],
  edges: [
    {
      type: "DEPENDS_ON",
      source: "app-1",
      target: "dev-1",
      properties: {
        sources: ["f5", "manual"],
        provenance: ["f5:adc_vs:/Common/vs_billing", "manual:user:u1"],
        derived_at: "2026-07-04T10:00:00Z",
      },
    },
  ],
  projected_at: "2026-07-04T10:00:00Z",
};

// An app-layer graph with Application nodes but no DEPENDS_ON edges (projected,
// but nothing depends on anything yet).
const GRAPH_APP_NO_EDGES: TopologyGraph = {
  nodes: [{ label: "Application", key: "app-1", properties: { name: "billing-web" } }],
  edges: [],
  projected_at: "2026-07-04T10:00:00Z",
};

const EMPTY_GRAPH: TopologyGraph = { nodes: [], edges: [], projected_at: null };

const DEVICES = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      hostname: "core-sw-01",
      mgmt_ip: "192.168.1.1",
      vendor_id: "cisco",
      model: null,
      os_version: null,
      serial: null,
      status: "active",
      site: "hq-dc",
      credential_id: null,
      last_discovered_at: null,
      created_at: "2026-06-01T00:00:00Z",
      updated_at: "2026-06-01T00:00:00Z",
    },
  ],
  total: 1,
  limit: 500,
  offset: 0,
};

function makeFetch(body: unknown = GRAPH_WITH_DEPENDS_ON) {
  return vi.fn((input: RequestInfo | URL): Promise<Response> => {
    const payload = String(input).includes("/devices") ? DEVICES : body;
    return Promise.resolve(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
renderWithQueryClient(
      <TopologyPage />
    );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── topology_page_offers_app_layer_selection ───────────────────────────────────

describe("topology_page_offers_app_layer_selection", () => {
  it("renders the App layer button alongside L2 / L3 / DNS / All", async () => {
    vi.stubGlobal("fetch", makeFetch(EMPTY_GRAPH));
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("topology-layer-app")).toBeInTheDocument();
    });
    expect(screen.getByTestId("topology-layer-dns")).toBeInTheDocument();
    expect(screen.getByTestId("topology-layer-all")).toBeInTheDocument();
  });

  it("clicking App sends layer=app to the topology/graph endpoint", async () => {
    const fetchMock = makeFetch(GRAPH_WITH_DEPENDS_ON);
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());

    fireEvent.click(screen.getByTestId("topology-layer-app"));
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((args) => String((args as unknown[])[0]));
      expect(urls.some((u) => u.includes("layer=app"))).toBe(true);
    });
    expect(screen.getByTestId("topology-layer-app")).toHaveAttribute("aria-pressed", "true");
  });
});

// ── app_layer_edges_render_per_source_badges ───────────────────────────────────

describe("app_layer_edges_render_per_source_badges", () => {
  it("renders a per-source badge for each DEPENDS_ON edge", async () => {
    vi.stubGlobal("fetch", makeFetch(GRAPH_WITH_DEPENDS_ON));
    renderPage();
    await waitFor(() => expect(screen.getByTestId("topology-layer-app")).toBeInTheDocument());

    fireEvent.click(screen.getByTestId("topology-layer-app"));

    const panel = await screen.findByTestId("app-dependency-panel");
    const edge = await within(panel).findByTestId("app-dependency-edge-0");
    // Both asserting sources render as badges on the edge.
    expect(within(edge).getByTestId("app-edge-0-source-f5")).toHaveTextContent("f5");
    expect(within(edge).getByTestId("app-edge-0-source-manual")).toHaveTextContent("manual");
    // The edge names its endpoints so the dependency is legible.
    expect(edge).toHaveTextContent("app-1");
    expect(edge).toHaveTextContent("dev-1");
  });
});

// ── impact_view_shows_watermark_and_empty_state ────────────────────────────────

describe("impact_view_shows_watermark_and_empty_state", () => {
  it("shows the projection watermark and an empty state when nothing depends on anything", async () => {
    vi.stubGlobal("fetch", makeFetch(GRAPH_APP_NO_EDGES));
    renderPage();
    await waitFor(() => expect(screen.getByTestId("topology-layer-app")).toBeInTheDocument());

    fireEvent.click(screen.getByTestId("topology-layer-app"));

    const panel = await screen.findByTestId("app-dependency-panel");
    // The watermark cites the projection these answers are "as of".
    expect(within(panel).getByTestId("app-impact-watermark")).toBeInTheDocument();
    // No DEPENDS_ON edges => an honest empty state, not a blank panel.
    expect(within(panel).getByTestId("app-impact-empty")).toBeInTheDocument();
  });
});
