/**
 * TopologyPage tests: Cytoscape element mapping, L2/L3 layer toggle,
 * node detail side panel, loading/error/empty states — mocked global fetch
 * and a mocked cytoscape module (jsdom cannot render a canvas).
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunListResponse } from "../api/discovery";
import type { TopologyDiffResponse, TopologyGraph } from "../api/topology";
import { TopologyPage } from "../pages/TopologyPage";
import { DIFF_REMOVED_CLASS, toCytoscapeElements } from "../pages/topology-graph";

// ── cytoscape mock ──────────────────────────────────────────────────────────
//
// jsdom has no canvas, so cytoscape cannot actually render. We replace the
// default export with a factory that records the options it was called with
// and exposes the registered `tap` handlers so a test can drive node clicks.

interface TapHandler {
  selector: string;
  handler: (evt: { target: { id: () => string } | MockCyInstance }) => void;
}

interface MockCyInstance {
  options: unknown;
  handlers: TapHandler[];
  on: (
    event: string,
    selectorOrHandler: string | TapHandler["handler"],
    handler?: TapHandler["handler"],
  ) => void;
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
      on(event, selectorOrHandler, handler?) {
        if (event === "tap") {
          if (typeof selectorOrHandler === "function") {
            // Two-argument form: cy.on('tap', handler) — background tap
            this.handlers.push({ selector: "", handler: selectorOrHandler });
          } else if (handler !== undefined) {
            // Three-argument form: cy.on('tap', 'node', handler)
            this.handlers.push({ selector: selectorOrHandler, handler });
          }
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

/**
 * Fire a background tap (no node selected) on the most recently created
 * cytoscape instance. The handler receives ``evt.target === cy`` which is
 * exactly what TopologyCanvas checks to clear the selection.
 */
function tapBackground(): void {
  const cy = lastCy();
  for (const { selector, handler } of cy.handlers) {
    if (selector === "") {
      handler({ target: cy });
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
        ip_address: "10.0.0.1/24",
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

  it("renders interface fields including IP when an Interface node is clicked", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    tapNode(IFACE_KEY);

    const panel = await screen.findByTestId("topology-detail-panel");
    expect(panel).toHaveTextContent("GigabitEthernet0/1");
    expect(panel).toHaveTextContent("down");
    expect(panel).toHaveTextContent("10.0.0.1/24");
  });

  it("clears the detail panel when the background is tapped", async () => {
    vi.stubGlobal("fetch", fetchGraph(GRAPH));
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));

    // Select a node first so the detail panel is visible.
    tapNode(DEVICE_KEY);
    expect(await screen.findByTestId("topology-detail-panel")).toBeInTheDocument();

    // Tap background — detail panel must revert to the empty hint.
    tapBackground();
    expect(await screen.findByTestId("topology-detail-empty")).toBeInTheDocument();
  });
});

// ── Run-to-run diff view (M2-14) ─────────────────────────────────────────────

const RUN_FROM = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const RUN_TO = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const RUNS: RunListResponse = {
  items: [
    {
      id: RUN_FROM,
      status: "succeeded",
      seeds: ["10.0.0.1"],
      hop_limit: 1,
      allowlist: ["10.0.0.0/24"],
      credential_names: [],
      stats: {},
      error: null,
      created_at: "2026-06-12T10:00:00Z",
      started_at: "2026-06-12T10:00:01Z",
      finished_at: "2026-06-12T10:01:00Z",
    },
    {
      id: RUN_TO,
      status: "succeeded",
      seeds: ["10.0.0.1"],
      hop_limit: 1,
      allowlist: ["10.0.0.0/24"],
      credential_names: [],
      stats: {},
      error: null,
      created_at: "2026-06-13T10:00:00Z",
      started_at: "2026-06-13T10:00:01Z",
      finished_at: "2026-06-13T10:01:00Z",
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
};

// The diff removes the HAS_INTERFACE edge that GRAPH still contains, so the
// canvas overlay can highlight it and the panel can list it.
const DIFF: TopologyDiffResponse = {
  from_run: RUN_FROM,
  to_run: RUN_TO,
  diff: {
    nodes_added: [],
    nodes_removed: [],
    edges_added: [],
    edges_removed: [["HAS_INTERFACE", DEVICE_KEY, IFACE_KEY]],
  },
};

/**
 * Fetch mock that routes by URL: the runs list, the topology graph, and the
 * diff endpoint each return their own body. Records the requested diff URL so a
 * test can assert the run ids were passed through.
 */
function routingFetch(diff: TopologyDiffResponse = DIFF) {
  return vi.fn((input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    let body: unknown = GRAPH;
    if (url.includes("/discovery/runs")) body = RUNS;
    else if (url.includes("/topology/diff")) body = diff;
    else if (url.includes("/topology/graph")) body = GRAPH;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

async function selectRunsAndCompare(): Promise<void> {
  // The runs list populates the two selects; wait for the options to arrive.
  await waitFor(() =>
    expect(screen.getByTestId("diff-from-run").querySelectorAll("option").length).toBeGreaterThan(
      1,
    ),
  );
  fireEvent.change(screen.getByTestId("diff-from-run"), { target: { value: RUN_FROM } });
  fireEvent.change(screen.getByTestId("diff-to-run"), { target: { value: RUN_TO } });
  fireEvent.click(screen.getByTestId("diff-compare-btn"));
}

describe("TopologyPage — run-to-run diff view", () => {
  it("renders the run-pair selector from the discovery runs list", async () => {
    vi.stubGlobal("fetch", routingFetch());
    renderPage();

    await waitFor(() =>
      expect(
        screen.getByTestId("diff-from-run").querySelectorAll("option").length,
      ).toBeGreaterThan(1),
    );
    // Both runs offered in each select (plus the placeholder option).
    expect(screen.getByTestId("diff-from-run")).toBeInTheDocument();
    expect(screen.getByTestId("diff-to-run")).toBeInTheDocument();
  });

  it("requests the diff endpoint with the two selected run ids on Compare", async () => {
    const mock = routingFetch();
    vi.stubGlobal("fetch", mock);
    renderPage();

    await selectRunsAndCompare();

    await waitFor(() => {
      const diffCall = mock.mock.calls.find((c) => String(c[0]).includes("/topology/diff"));
      expect(diffCall).toBeDefined();
      expect(String(diffCall![0])).toContain(`from_run=${RUN_FROM}`);
      expect(String(diffCall![0])).toContain(`to_run=${RUN_TO}`);
    });
  });

  it("shows the changed elements in the diff list panel", async () => {
    vi.stubGlobal("fetch", routingFetch());
    renderPage();

    await selectRunsAndCompare();

    const panel = await screen.findByTestId("topology-diff-panel");
    expect(panel).toHaveTextContent("Changes (1)");
    const removed = await screen.findByTestId("diff-item-removed");
    expect(removed).toHaveTextContent("HAS_INTERFACE");
    expect(removed).toHaveTextContent(`${DEVICE_KEY} → ${IFACE_KEY}`);
  });

  it("highlights the removed edge on the canvas with the diff-removed class", async () => {
    vi.stubGlobal("fetch", routingFetch());
    renderPage();

    await selectRunsAndCompare();

    // The canvas is rebuilt with the overlay classes applied to the elements.
    await waitFor(() => {
      const edge = lastElements().find(
        (e) => e.data.id === `${DEVICE_KEY}:${IFACE_KEY}:HAS_INTERFACE`,
      );
      expect(edge).toBeDefined();
      expect(edge!.classes).toContain(DIFF_REMOVED_CLASS);
    });
  });

  it("clears the diff and restores the selection panel on Clear diff", async () => {
    vi.stubGlobal("fetch", routingFetch());
    renderPage();

    await selectRunsAndCompare();
    expect(await screen.findByTestId("topology-diff-panel")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("diff-clear-btn"));

    // Diff panel gone; the node-selection hint is back.
    await waitFor(() =>
      expect(screen.queryByTestId("topology-diff-panel")).not.toBeInTheDocument(),
    );
    expect(screen.getByTestId("topology-detail-empty")).toBeInTheDocument();
  });

  it("shows a no-changes message when the diff is empty", async () => {
    const emptyDiff: TopologyDiffResponse = {
      from_run: RUN_FROM,
      to_run: RUN_TO,
      diff: { nodes_added: [], nodes_removed: [], edges_added: [], edges_removed: [] },
    };
    vi.stubGlobal("fetch", routingFetch(emptyDiff));
    renderPage();

    await selectRunsAndCompare();

    expect(await screen.findByTestId("diff-no-changes")).toBeInTheDocument();
  });
});
