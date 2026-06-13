/**
 * TopologyPage tests: Cytoscape element mapping, L2/L3 layer toggle,
 * node detail side panel, loading/error/empty states — mocked global fetch
 * and a mocked cytoscape module (jsdom cannot render a canvas).
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TopologyGraph } from "../api/topology";
import { TopologyPage } from "../pages/TopologyPage";
import { toCytoscapeElements } from "../pages/topology-graph";

// ── cytoscape mock ──────────────────────────────────────────────────────────
//
// jsdom has no canvas, so cytoscape cannot actually render. We replace the
// default export with a factory that records the options it was called with
// and exposes the registered `tap` handlers so a test can drive node clicks.

interface TapHandler {
  selector: string;
  handler: (evt: { target: { id: () => string } }) => void;
}

interface MockCyInstance {
  options: unknown;
  handlers: TapHandler[];
  on: (event: string, selector: string, handler: TapHandler["handler"]) => void;
  destroy: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  fit: ReturnType<typeof vi.fn>;
  layout: () => { run: ReturnType<typeof vi.fn> };
}

const cyInstances: MockCyInstance[] = [];

vi.mock("cytoscape", () => {
  const factory = vi.fn((options: unknown): MockCyInstance => {
    const instance: MockCyInstance = {
      options,
      handlers: [],
      on(event, selector, handler) {
        if (event === "tap") {
          this.handlers.push({ selector, handler });
        }
      },
      destroy: vi.fn(),
      resize: vi.fn(),
      fit: vi.fn(),
      layout: () => ({ run: vi.fn() }),
    };
    cyInstances.push(instance);
    return instance;
  });
  return { default: factory };
});

/** The most recently created (mock) cytoscape instance. */
function lastCy(): MockCyInstance {
  const cy = cyInstances[cyInstances.length - 1];
  if (cy === undefined) {
    throw new Error("no cytoscape instance has been created yet");
  }
  return cy;
}

/** Fire a node tap on the most recently created cytoscape instance. */
function tapNode(id: string): void {
  for (const { selector, handler } of lastCy().handlers) {
    if (selector === "node") {
      handler({ target: { id: () => id } });
    }
  }
}

/** The `elements` option handed to the most recent cytoscape() call. */
function lastElements(): ReturnType<typeof toCytoscapeElements> {
  return (lastCy().options as { elements: ReturnType<typeof toCytoscapeElements> }).elements;
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const DEVICE_KEY = "11111111-1111-1111-1111-111111111111";
const IFACE_KEY = "22222222-2222-2222-2222-222222222222";

const GRAPH: TopologyGraph = {
  nodes: [
    {
      label: "Device",
      key: DEVICE_KEY,
      properties: {
        pg_id: DEVICE_KEY,
        hostname: "core-sw-01",
        mgmt_ip: "192.168.1.1",
        vendor_id: "cisco",
        model: "Catalyst 9300",
        site: "hq-dc",
        last_projected_at: "2024-01-15T10:30:00Z",
      },
    },
    {
      label: "Interface",
      key: IFACE_KEY,
      properties: {
        pg_id: IFACE_KEY,
        name: "GigabitEthernet0/1",
        admin_status: "up",
        oper_status: "down",
        mac_address: "00:11:22:33:44:55",
      },
    },
    {
      label: "Subnet",
      key: "10.0.0.0/24",
      properties: { cidr: "10.0.0.0/24" },
    },
  ],
  edges: [
    {
      type: "HAS_INTERFACE",
      source: DEVICE_KEY,
      target: IFACE_KEY,
      properties: {},
    },
  ],
  projected_at: "2024-01-15T10:30:00Z",
};

const EMPTY_GRAPH: TopologyGraph = { nodes: [], edges: [], projected_at: null };

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Fetch mock returning `body` for any topology request; records call URLs. */
function fetchGraph(body: unknown) {
  return vi.fn((): Promise<Response> => {
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
      <TopologyPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  cyInstances.length = 0;
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ── Pure mapping ────────────────────────────────────────────────────────────

describe("toCytoscapeElements", () => {
  it("maps each node to an element keyed by node.key with its label", () => {
    const elements = toCytoscapeElements(GRAPH);
    const deviceEl = elements.find((e) => e.data.id === DEVICE_KEY);
    expect(deviceEl).toBeDefined();
    expect(deviceEl!.data.label).toBe("Device");
    expect(deviceEl!.classes).toContain("Device");
  });

  it("labels Device nodes by hostname and Subnet nodes by cidr", () => {
    const elements = toCytoscapeElements(GRAPH);
    const deviceEl = elements.find((e) => e.data.id === DEVICE_KEY);
    const subnetEl = elements.find((e) => e.data.id === "10.0.0.0/24");
    expect(deviceEl!.data.display).toBe("core-sw-01");
    expect(subnetEl!.data.display).toBe("10.0.0.0/24");
  });

  it("maps each edge to an element with source, target and type", () => {
    const elements = toCytoscapeElements(GRAPH);
    const edgeEl = elements.find((e) => e.data.source !== undefined);
    expect(edgeEl).toBeDefined();
    expect(edgeEl!.data.source).toBe(DEVICE_KEY);
    expect(edgeEl!.data.target).toBe(IFACE_KEY);
    expect(edgeEl!.data.label).toBe("HAS_INTERFACE");
  });

  it("produces one element per node plus one per edge", () => {
    const elements = toCytoscapeElements(GRAPH);
    expect(elements).toHaveLength(GRAPH.nodes.length + GRAPH.edges.length);
  });
});

// ── Rendering + states ──────────────────────────────────────────────────────

describe("TopologyPage — render and elements", () => {
  it("hands the mapped elements to cytoscape", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    const els = lastElements();
    expect(els.find((e) => e.data.id === DEVICE_KEY)).toBeDefined();
    expect(els.find((e) => e.data.id === IFACE_KEY)).toBeDefined();
  });

  it("shows the projected_at 'as of' timestamp", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    expect(await screen.findByTestId("topology-as-of")).toBeInTheDocument();
  });

  it("shows the empty state when the projection has no nodes", async () => {
    vi.stubGlobal("fetch", fetchGraph(EMPTY_GRAPH));
    renderPage();

    expect(await screen.findByTestId("topology-empty-state")).toBeInTheDocument();
  });

  it("shows an error alert when the graph API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(/Failed to fetch/);
  });

  it("requests the canonical topology graph path", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/topology/graph"),
      expect.anything(),
    );
  });
});

// ── Layer toggle ────────────────────────────────────────────────────────────

describe("TopologyPage — L2/L3 layer toggle", () => {
  it("requests layer=all by default", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("layer=all"),
      expect.anything(),
    );
  });

  it("refetches with layer=l2 when the L2 toggle is selected", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    fireEvent.click(screen.getByTestId("topology-layer-l2"));

    await waitFor(() =>
      expect(mock).toHaveBeenCalledWith(
        expect.stringContaining("layer=l2"),
        expect.anything(),
      ),
    );
  });

  it("refetches with layer=l3 when the L3 toggle is selected", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    fireEvent.click(screen.getByTestId("topology-layer-l3"));

    await waitFor(() =>
      expect(mock).toHaveBeenCalledWith(
        expect.stringContaining("layer=l3"),
        expect.anything(),
      ),
    );
  });
});

// ── Detail side panel ───────────────────────────────────────────────────────

describe("TopologyPage — node detail panel", () => {
  it("shows a hint to select a node before any node is clicked", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    expect(await screen.findByTestId("topology-detail-empty")).toBeInTheDocument();
  });

  it("renders device fields when a Device node is clicked", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    tapNode(DEVICE_KEY);

    const panel = await screen.findByTestId("topology-detail-panel");
    expect(panel).toHaveTextContent("core-sw-01");
    expect(panel).toHaveTextContent("192.168.1.1");
    expect(panel).toHaveTextContent("cisco");
    expect(panel).toHaveTextContent("Catalyst 9300");
    expect(panel).toHaveTextContent("hq-dc");
  });

  it("renders interface fields when an Interface node is clicked", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    tapNode(IFACE_KEY);

    const panel = await screen.findByTestId("topology-detail-panel");
    expect(panel).toHaveTextContent("GigabitEthernet0/1");
    expect(panel).toHaveTextContent("down");
  });
});
