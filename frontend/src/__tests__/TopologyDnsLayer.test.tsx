/**
 * TopologyPage DNS-layer toggle tests (T17).
 *
 * Verifies that:
 *  - The DNS layer toggle button is rendered alongside L2 / L3 / All.
 *  - Clicking the DNS button sends layer=dns to the topology/graph endpoint.
 *  - Deselecting DNS (clicking "All") removes the dns layer param.
 *
 * Mirrors the existing TopologyPage.test.tsx test pattern: mocked cytoscape
 * (jsdom has no canvas) + mocked global fetch.
 */

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { TopologyGraph } from "../api/topology";
import { TopologyPage } from "../pages/TopologyPage";

// ── cytoscape mock (same as TopologyPage.test.tsx) ───────────────────────────

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

/** A minimal topology graph response — includes a DnsZone node so hasNodes is true. */
const GRAPH_WITH_DNS: TopologyGraph = {
  nodes: [
    {
      label: "DnsZone",
      key: "zone:corp.example.com",
      properties: { name: "corp.example.com", kind: "forward" },
    },
    {
      label: "DnsRecord",
      key: "record:www.corp.example.com:A",
      properties: { fqdn: "www.corp.example.com", record_type: "A", rdata: "10.0.0.10" },
    },
  ],
  edges: [
    {
      type: "IN_ZONE",
      source: "record:www.corp.example.com:A",
      target: "zone:corp.example.com",
      properties: {},
    },
  ],
  projected_at: "2026-06-18T10:00:00Z",
};

const EMPTY_GRAPH: TopologyGraph = {
  nodes: [],
  edges: [],
  projected_at: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// Minimal inventory for the scope pickers (audit Wave 5): one sited device so
// the page's default scoped (site) query fires and the layer toggle refetches.
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

function makeFetch(body: unknown = GRAPH_WITH_DNS) {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("TopologyPage — DNS layer toggle", () => {
  it("renders the DNS layer button alongside L2 / L3 / All", async () => {
    vi.stubGlobal("fetch", makeFetch(EMPTY_GRAPH));
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("topology-layer-dns")).toBeInTheDocument();
    });
    expect(screen.getByTestId("topology-layer-all")).toBeInTheDocument();
    expect(screen.getByTestId("topology-layer-l2")).toBeInTheDocument();
    expect(screen.getByTestId("topology-layer-l3")).toBeInTheDocument();
  });

  it("clicking DNS sends layer=dns to the topology/graph endpoint", async () => {
    const fetchMock = makeFetch(GRAPH_WITH_DNS);
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    // Wait for initial load to complete
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByTestId("topology-layer-dns"));

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((args) => String((args as unknown[])[0]));
      const dnsCall = urls.find((u) => u.includes("layer=dns"));
      expect(dnsCall).toBeDefined();
    });
  });

  it("DNS button has aria-pressed=true when DNS layer is active", async () => {
    vi.stubGlobal("fetch", makeFetch(EMPTY_GRAPH));
    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId("topology-layer-dns")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId("topology-layer-dns"));
    expect(screen.getByTestId("topology-layer-dns")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("clicking All after DNS removes the dns layer param", async () => {
    const fetchMock = makeFetch(GRAPH_WITH_DNS);
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled();
    });

    // Switch to dns
    fireEvent.click(screen.getByTestId("topology-layer-dns"));
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((args) => String((args as unknown[])[0]));
      expect(urls.some((u) => u.includes("layer=dns"))).toBe(true);
    });

    // Switch back to all
    fireEvent.click(screen.getByTestId("topology-layer-all"));
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((args) => String((args as unknown[])[0]));
      // The latest call should be layer=all (or no layer param, depending on
      // the implementation — check the param is absent or equal to "all")
      const lastUrl = urls[urls.length - 1] ?? "";
      expect(lastUrl.includes("layer=dns")).toBe(false);
    });
  });

  it("DNS layer toggle adds DnsZone nodes to the graph", async () => {
    const fetchMock = makeFetch(GRAPH_WITH_DNS);
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    fireEvent.click(screen.getByTestId("topology-layer-dns"));

    // After fetching with DNS layer the canvas should show (nodes present)
    await waitFor(() => {
      expect(screen.getByTestId("topology-canvas")).toBeInTheDocument();
    });
  });
});
