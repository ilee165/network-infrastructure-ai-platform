/**
 * TopologyPage tests: Cytoscape element mapping, L2/L3 layer toggle,
 * node detail side panel, loading/error/empty states — mocked global fetch
 * and a mocked cytoscape module (jsdom cannot render a canvas).
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DeviceListResponse, DeviceRead } from "../api/devices";
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
  currentElements: ReturnType<typeof toCytoscapeElements>;
  layoutRuns: number;
  nodePositions: Record<string, { x: number; y: number }>;
  on: (
    event: string,
    selectorOrHandler: string | TapHandler["handler"],
    handler?: TapHandler["handler"],
  ) => void;
  destroy: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  fit: ReturnType<typeof vi.fn>;
  pan: () => { x: number; y: number };
  zoom: () => number;
  viewport: ReturnType<typeof vi.fn>;
  batch: (fn: () => void) => void;
  elements: () => { remove: ReturnType<typeof vi.fn> };
  nodes: () => {
    forEach: (
      cb: (n: { id: () => string; position: () => { x: number; y: number } }) => void,
    ) => void;
  };
  getElementById: (id: string) => {
    nonempty: () => boolean;
    position: (pos?: { x: number; y: number }) => { x: number; y: number };
  };
  add: (els: ReturnType<typeof toCytoscapeElements>) => void;
  layout: (opts?: unknown) => { run: () => void };
}

const cyInstances: MockCyInstance[] = [];

vi.mock("cytoscape", () => {
  const factory = vi.fn((options: unknown): MockCyInstance => {
    // Cytoscape destroys removed elements INCLUDING their layout positions;
    // re-added nodes start at default coordinates unless the app restores
    // them. The mock mirrors that so position-loss regressions are testable.
    const remove = vi.fn(() => {
      instance.currentElements = [];
      instance.nodePositions = {};
    });
    const instance: MockCyInstance = {
      options,
      handlers: [],
      currentElements: [],
      layoutRuns: 0,
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
      pan: () => ({ x: 0, y: 0 }),
      zoom: () => 1,
      viewport: vi.fn(),
      nodePositions: {} as Record<string, { x: number; y: number }>,
      batch(fn) {
        fn();
      },
      elements() {
        return { remove };
      },
      nodes() {
        return {
          forEach(cb: (n: { id: () => string; position: () => { x: number; y: number } }) => void) {
            for (const el of instance.currentElements) {
              if (el.data.source === undefined) {
                const id = el.data.id;
                cb({
                  id: () => id,
                  position: () => instance.nodePositions[id] ?? { x: 10, y: 20 },
                });
              }
            }
          },
        };
      },
      getElementById(id: string) {
        return {
          nonempty: () => instance.currentElements.some((e) => e.data.id === id),
          position(pos?: { x: number; y: number }) {
            if (pos) {
              instance.nodePositions[id] = pos;
            }
            return instance.nodePositions[id] ?? { x: 0, y: 0 };
          },
        };
      },
      add(els) {
        this.currentElements = els;
        for (const el of els) {
          if (el.data.source === undefined && this.nodePositions[el.data.id] === undefined) {
            this.nodePositions[el.data.id] = { x: 10, y: 20 };
          }
        }
      },
      layout() {
        return {
          run: () => {
            this.layoutRuns += 1;
          },
        };
      },
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

/** Elements applied to the persistent cy instance (via ``cy.add``). */
function lastElements(): ReturnType<typeof toCytoscapeElements> {
  return lastCy().currentElements;
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

// The inventory drives the scope pickers: the first (sorted) site is the
// page's default scoped view, and the device list feeds the neighborhood mode.
const DEVICE_2_ID = "33333333-3333-3333-3333-333333333333";

function makeDevice(overrides: Partial<DeviceRead>): DeviceRead {
  return {
    id: DEVICE_KEY,
    hostname: "core-sw-01",
    mgmt_ip: "192.168.1.1",
    vendor_id: "cisco",
    model: "Catalyst 9300",
    os_version: null,
    serial: null,
    status: "reachable",
    site: "hq-dc",
    credential_id: null,
    last_discovered_at: null,
    created_at: "2026-06-01T00:00:00Z",
    updated_at: "2026-06-01T00:00:00Z",
    ...overrides,
  };
}

const DEVICES: DeviceListResponse = {
  items: [
    makeDevice({}),
    makeDevice({ id: DEVICE_2_ID, hostname: "edge-rt-01", site: null }),
  ],
  total: 2,
  limit: 500,
  offset: 0,
};

const DEVICES_NO_SITES: DeviceListResponse = {
  items: [
    makeDevice({ site: null }),
    makeDevice({ id: DEVICE_2_ID, hostname: "edge-rt-01", site: null }),
  ],
  total: 2,
  limit: 500,
  offset: 0,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Fetch mock returning `body` for any topology request (and the device
 * inventory for the scope pickers); records call URLs.
 */
function fetchGraph(body: unknown, devices: DeviceListResponse = DEVICES) {
  return vi.fn((input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    const payload = url.includes("/devices") ? devices : body;
    return Promise.resolve(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

/** All topology-graph request URLs a fetch mock received (excluding devices/runs). */
function topologyCalls(mock: ReturnType<typeof vi.fn>): string[] {
  return mock.mock.calls
    .map((c) => String((c as unknown as [RequestInfo | URL])[0]))
    .filter((url) => url.includes("/topology/graph"));
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
    // The inventory (scope pickers) loads fine; the scoped graph read fails.
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL): Promise<Response> => {
        if (String(input).includes("/devices")) {
          return Promise.resolve(
            new Response(JSON.stringify(DEVICES), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return Promise.reject(new TypeError("Failed to fetch"));
      }),
    );
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

// ── Scoped-by-default loading (audit Wave 5) ────────────────────────────────

describe("TopologyPage — scoped-by-default loading", () => {
  it("default-loads the first site's subgraph, never the full graph", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    const calls = topologyCalls(mock);
    expect(calls.length).toBeGreaterThan(0);
    for (const url of calls) {
      expect(url).toContain("site=hq-dc");
    }
  });

  it("refetches when a different site is picked", async () => {
    const mock = fetchGraph(GRAPH, {
      ...DEVICES,
      items: [
        makeDevice({}),
        makeDevice({ id: DEVICE_2_ID, hostname: "edge-rt-01", site: "branch-1" }),
      ],
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    fireEvent.change(await screen.findByTestId("topology-site-select"), {
      target: { value: "hq-dc" },
    });
    // Sites are sorted, so branch-1 is the auto-selected default; switching to
    // hq-dc must issue a new scoped fetch.
    await waitFor(() =>
      expect(topologyCalls(mock).some((url) => url.includes("site=hq-dc"))).toBe(true),
    );
  });

  it("device mode fetches the neighborhood endpoint with device and depth", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    fireEvent.click(await screen.findByTestId("topology-scope-device"));
    // No fetch until a device is picked — the hint is shown instead.
    expect(await screen.findByTestId("topology-scope-hint")).toBeInTheDocument();

    const select = await screen.findByTestId("topology-device-select");
    await waitFor(() => expect(select.querySelectorAll("option").length).toBeGreaterThan(1));
    fireEvent.change(select, { target: { value: DEVICE_KEY } });

    await waitFor(() => {
      const url = topologyCalls(mock).find((u) => u.includes("/graph/neighborhood"));
      expect(url).toBeDefined();
      expect(url).toContain(`device=${DEVICE_KEY}`);
      expect(url).toContain("depth=2");
    });
  });

  it("changing the depth refetches the neighborhood", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    fireEvent.click(await screen.findByTestId("topology-scope-device"));
    const select = await screen.findByTestId("topology-device-select");
    await waitFor(() => expect(select.querySelectorAll("option").length).toBeGreaterThan(1));
    fireEvent.change(select, { target: { value: DEVICE_KEY } });
    fireEvent.change(screen.getByTestId("topology-depth-select"), { target: { value: "3" } });

    await waitFor(() =>
      expect(topologyCalls(mock).some((url) => url.includes("depth=3"))).toBe(true),
    );
  });

  it("full-graph fetch is explicit and unscoped", async () => {
    const mock = fetchGraph(GRAPH);
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    fireEvent.click(screen.getByTestId("topology-scope-full"));

    await waitFor(() => {
      const unscoped = topologyCalls(mock).filter(
        (url) => !url.includes("site=") && !url.includes("/graph/neighborhood"),
      );
      expect(unscoped.length).toBeGreaterThan(0);
    });
  });

  it("surfaces the server 413 cap and recovers by switching back to a scoped mode", async () => {
    const problem = {
      type: "urn:netops:error:graph-too-large",
      title: "Graph Too Large",
      status: 413,
      detail:
        "this subgraph has 123456 nodes, over the 5000-node limit; narrow the read " +
        "with ?site=<name> or GET /topology/graph/neighborhood, or raise " +
        "NETOPS_TOPOLOGY_MAX_NODES",
      instance: "/api/v1/topology/graph",
    };
    // Only the explicit UNSCOPED fetch is over the cap; scoped reads succeed.
    const mock = vi.fn((input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      if (url.includes("/devices")) {
        return Promise.resolve(
          new Response(JSON.stringify(DEVICES), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      if (url.includes("/topology/graph") && !url.includes("site=")) {
        return Promise.resolve(
          new Response(JSON.stringify(problem), {
            status: 413,
            headers: { "Content-Type": "application/problem+json" },
          }),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify(GRAPH), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    // Scoped default loads fine; the explicit full fetch hits the cap.
    await waitFor(() => expect(cyInstances.length).toBeGreaterThan(0));
    fireEvent.click(screen.getByTestId("topology-scope-full"));

    const alert = await screen.findByTestId("topology-cap-alert");
    expect(alert).toHaveTextContent("Graph too large to load");
    expect(alert).toHaveTextContent("123456 nodes");
    expect(alert).toHaveTextContent(/site or device-neighborhood scope/);
    // The scope controls survive the error — switching back to Site recovers.
    fireEvent.click(screen.getByTestId("topology-scope-site"));
    await waitFor(() =>
      expect(screen.queryByTestId("topology-cap-alert")).not.toBeInTheDocument(),
    );
    const scoped = topologyCalls(mock).filter((url) => url.includes("site=hq-dc"));
    expect(scoped.length).toBeGreaterThan(0);
  });

  it("shows an error alert when the neighborhood device is unknown (404)", async () => {
    const problem = {
      type: "urn:netops:error:not-found",
      title: "Not Found",
      status: 404,
      detail: `no projected device with key '${DEVICE_KEY}'`,
      instance: "/api/v1/topology/graph/neighborhood",
    };
    const mock = vi.fn((input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      if (url.includes("/devices")) {
        return Promise.resolve(
          new Response(JSON.stringify(DEVICES), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      if (url.includes("/graph/neighborhood")) {
        return Promise.resolve(
          new Response(JSON.stringify(problem), {
            status: 404,
            headers: { "Content-Type": "application/problem+json" },
          }),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify(GRAPH), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    fireEvent.click(await screen.findByTestId("topology-scope-device"));
    const select = await screen.findByTestId("topology-device-select");
    await waitFor(() => expect(select.querySelectorAll("option").length).toBeGreaterThan(1));
    fireEvent.change(select, { target: { value: DEVICE_KEY } });

    // The stale-projection 404 surfaces as the generic load error, not a
    // blank page and not the cap alert.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/no projected device/);
    expect(screen.queryByTestId("topology-cap-alert")).not.toBeInTheDocument();
  });

  it("with no sites in inventory, nothing is fetched until full graph is explicit", async () => {
    const mock = fetchGraph(GRAPH, DEVICES_NO_SITES);
    vi.stubGlobal("fetch", mock);
    renderPage();

    const empty = await screen.findByTestId("topology-scope-empty");
    expect(empty).toHaveTextContent(/No sites in the inventory/);
    expect(topologyCalls(mock)).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Load full graph" }));
    await waitFor(() => {
      const unscoped = topologyCalls(mock).filter(
        (url) => !url.includes("site=") && !url.includes("/graph/neighborhood"),
      );
      expect(unscoped.length).toBeGreaterThan(0);
    });
  });

  it("accumulates inventory pages so later-page sites feed the picker", async () => {
    // Two pages of one device each; the second page carries the sorted-first
    // site, so the default scoped fetch proves page 2 reached the picker.
    const page1: DeviceListResponse = { items: [makeDevice({})], total: 2, limit: 500, offset: 0 };
    const page2: DeviceListResponse = {
      items: [makeDevice({ id: DEVICE_2_ID, hostname: "edge-rt-01", site: "aaa-branch" })],
      total: 2,
      limit: 500,
      offset: 1,
    };
    const mock = vi.fn((input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      let body: unknown = GRAPH;
      if (url.includes("/devices")) body = url.includes("offset=1") ? page2 : page1;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    await waitFor(() =>
      expect(topologyCalls(mock).some((url) => url.includes("site=aaa-branch"))).toBe(true),
    );
    expect(mock.mock.calls.some((c) => String(c[0]).includes("offset=1"))).toBe(true);
  });

  it("surfaces an inventory load failure and still allows the explicit full graph", async () => {
    const mock = vi.fn((input: RequestInfo | URL): Promise<Response> => {
      if (String(input).includes("/devices")) {
        return Promise.reject(new TypeError("Failed to fetch"));
      }
      return Promise.resolve(
        new Response(JSON.stringify(GRAPH), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    renderPage();

    const alert = await screen.findByTestId("topology-inventory-error");
    expect(alert).toHaveTextContent(/Device inventory failed to load/);
    expect(topologyCalls(mock)).toHaveLength(0);

    fireEvent.click(screen.getByTestId("topology-scope-full"));
    await waitFor(() => expect(topologyCalls(mock).length).toBeGreaterThan(0));
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
    else if (url.includes("/devices")) body = DEVICES;
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

  it("preserves node positions across a class-only diff overlay (no re-layout)", async () => {
    vi.stubGlobal("fetch", routingFetch());
    renderPage();

    // Initial load: canvas populated and laid out once.
    await waitFor(() => expect(lastElements().length).toBeGreaterThan(0));
    const cy = lastCy();
    const layoutRunsBefore = cy.layoutRuns;
    // Simulate the cose layout having placed the device node somewhere real.
    cy.nodePositions[DEVICE_KEY] = { x: 111, y: 222 };

    // The DIFF only adds the diff-removed class to an edge that is already in
    // the graph — same node/edge ids, so this is a non-structural update.
    await selectRunsAndCompare();
    await waitFor(() => {
      const edge = lastElements().find(
        (e) => e.data.id === `${DEVICE_KEY}:${IFACE_KEY}:HAS_INTERFACE`,
      );
      expect(edge?.classes).toContain(DIFF_REMOVED_CLASS);
    });

    // No re-layout ran, and the node position survived the remove/re-add
    // (the mock's remove() wipes positions, mirroring cytoscape).
    expect(cy.layoutRuns).toBe(layoutRunsBefore);
    expect(cy.nodePositions[DEVICE_KEY]).toEqual({ x: 111, y: 222 });
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
