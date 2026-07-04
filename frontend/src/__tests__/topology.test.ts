/**
 * Unit tests for the topology API client (M2-12).
 *
 * Mirrors the test style used for devices/discovery: global fetch is stubbed
 * with ``vi.stubGlobal``; RFC 7807 error path exercises ``ApiError``; no
 * backend or Neo4j required.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type {
  TopologyDiffResponse,
  TopologyGraph,
} from "../api/topology";
import {
  getTopologyDiff,
  getTopologyGraph,
  getTopologyNeighborhood,
  MAX_NEIGHBORHOOD_DEPTH,
} from "../api/topology";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const GRAPH_RESPONSE: TopologyGraph = {
  nodes: [
    {
      label: "Device",
      key: "11111111-1111-1111-1111-111111111111",
      properties: { hostname: "core-sw-01", vendor: "cisco" },
    },
    {
      label: "Interface",
      key: "22222222-2222-2222-2222-222222222222",
      properties: { name: "GigabitEthernet0/0" },
    },
  ],
  edges: [
    {
      type: "HAS_INTERFACE",
      source: "11111111-1111-1111-1111-111111111111",
      target: "22222222-2222-2222-2222-222222222222",
      properties: {},
    },
  ],
  projected_at: "2024-01-15T10:30:00Z",
};

const GRAPH_EMPTY: TopologyGraph = {
  nodes: [],
  edges: [],
  projected_at: null,
};

const FROM_RUN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TO_RUN = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const DIFF_RESPONSE: TopologyDiffResponse = {
  from_run: FROM_RUN,
  to_run: TO_RUN,
  diff: {
    nodes_added: [["Device", "cccccccc-cccc-cccc-cccc-cccccccccccc"]],
    nodes_removed: [],
    edges_added: [],
    edges_removed: [["CONNECTED_TO", "aaa", "bbb"]],
  },
};

const DIFF_EMPTY: TopologyDiffResponse = {
  from_run: FROM_RUN,
  to_run: TO_RUN,
  diff: {
    nodes_added: [],
    nodes_removed: [],
    edges_added: [],
    edges_removed: [],
  },
};

const PROBLEM_404 = {
  type: "urn:netops:error:not-found",
  title: "Not Found",
  status: 404,
  detail: "no topology snapshot exists for run aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  instance: "/api/v1/topology/diff",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function okFetch(body: unknown, status = 200) {
  return vi.fn((): Promise<Response> =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

function errorFetch(problem: unknown, status: number) {
  return vi.fn((): Promise<Response> =>
    Promise.resolve(
      new Response(JSON.stringify(problem), {
        status,
        headers: { "Content-Type": "application/problem+json" },
      }),
    ),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── getTopologyGraph ──────────────────────────────────────────────────────────

describe("getTopologyGraph — success", () => {
  it("returns a typed TopologyGraph on 200", async () => {
    vi.stubGlobal("fetch", okFetch(GRAPH_RESPONSE));
    const result = await getTopologyGraph({});
    expect(result).toEqual(GRAPH_RESPONSE);
  });

  it("returns empty graph when nodes/edges are empty and projected_at is null", async () => {
    vi.stubGlobal("fetch", okFetch(GRAPH_EMPTY));
    const result = await getTopologyGraph({});
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
    expect(result.projected_at).toBeNull();
  });

  it("hits the canonical /api/v1/topology/graph path", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({});
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/topology/graph"),
      expect.anything(),
    );
  });
});

describe("getTopologyGraph — param serialization", () => {
  it("omits query string when no filters supplied", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({});
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).not.toContain("?");
  });

  it("appends site param when provided", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({ site: "dc-east" });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("site=dc-east");
  });

  it("appends vrf param when provided", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({ vrf: "MGMT" });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("vrf=MGMT");
  });

  it("appends layer param when provided", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({ layer: "l2" });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("layer=l2");
  });

  it("serializes all filters together", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyGraph({ site: "dc-west", vrf: "PROD", layer: "l3" });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("site=dc-west");
    expect(url).toContain("vrf=PROD");
    expect(url).toContain("layer=l3");
  });
});

describe("getTopologyGraph — RFC 7807 error path", () => {
  it("throws ApiError with the problem document on 4xx", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    await expect(getTopologyGraph({})).rejects.toBeInstanceOf(ApiError);
  });

  it("ApiError.status matches the HTTP status code", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    try {
      await getTopologyGraph({});
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
    }
  });

  it("ApiError.problem carries the full RFC 7807 document", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    try {
      await getTopologyGraph({});
      expect.fail("should have thrown");
    } catch (err) {
      expect((err as ApiError).problem).toMatchObject({
        type: "urn:netops:error:not-found",
        title: "Not Found",
        status: 404,
      });
    }
  });

  it("synthesizes an ApiError when response body is not valid problem+json", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((): Promise<Response> =>
        Promise.resolve(new Response("<html>Bad Gateway</html>", { status: 502 })),
      ),
    );
    try {
      await getTopologyGraph({});
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(502);
    }
  });
});

// ── getTopologyNeighborhood ───────────────────────────────────────────────────

describe("getTopologyNeighborhood", () => {
  const DEVICE = "11111111-1111-1111-1111-111111111111";

  it("returns a typed TopologyGraph on 200", async () => {
    vi.stubGlobal("fetch", okFetch(GRAPH_RESPONSE));
    const result = await getTopologyNeighborhood({ device: DEVICE });
    expect(result).toEqual(GRAPH_RESPONSE);
  });

  it("hits the canonical /api/v1/topology/graph/neighborhood path with device", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyNeighborhood({ device: DEVICE });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("/api/v1/topology/graph/neighborhood");
    expect(url).toContain(`device=${DEVICE}`);
  });

  it("omits depth and layer unless provided (server defaults apply)", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyNeighborhood({ device: DEVICE });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).not.toContain("depth=");
    expect(url).not.toContain("layer=");
  });

  it("serializes depth and layer when provided", async () => {
    const mock = okFetch(GRAPH_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyNeighborhood({ device: DEVICE, depth: 3, layer: "l2" });
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain("depth=3");
    expect(url).toContain("layer=l2");
  });

  it("exports the depth bound the backend enforces", () => {
    expect(MAX_NEIGHBORHOOD_DEPTH).toBe(5);
  });

  it("throws ApiError with the problem document on 404 (unknown device)", async () => {
    vi.stubGlobal(
      "fetch",
      errorFetch(
        {
          type: "urn:netops:error:not-found",
          title: "Not Found",
          status: 404,
          detail: `no projected device with key '${DEVICE}'`,
          instance: "/api/v1/topology/graph/neighborhood",
        },
        404,
      ),
    );
    try {
      await getTopologyNeighborhood({ device: DEVICE });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
    }
  });
});

// ── getTopologyDiff ───────────────────────────────────────────────────────────

describe("getTopologyDiff — success", () => {
  it("returns a typed TopologyDiffResponse on 200", async () => {
    vi.stubGlobal("fetch", okFetch(DIFF_RESPONSE));
    const result = await getTopologyDiff(FROM_RUN, TO_RUN);
    expect(result).toEqual(DIFF_RESPONSE);
  });

  it("returns an empty diff when nothing changed", async () => {
    vi.stubGlobal("fetch", okFetch(DIFF_EMPTY));
    const result = await getTopologyDiff(FROM_RUN, TO_RUN);
    expect(result.diff.nodes_added).toHaveLength(0);
    expect(result.diff.nodes_removed).toHaveLength(0);
    expect(result.diff.edges_added).toHaveLength(0);
    expect(result.diff.edges_removed).toHaveLength(0);
  });

  it("hits the canonical /api/v1/topology/diff path", async () => {
    const mock = okFetch(DIFF_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyDiff(FROM_RUN, TO_RUN);
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/topology/diff"),
      expect.anything(),
    );
  });
});

describe("getTopologyDiff — param serialization", () => {
  it("includes from_run in the query string", async () => {
    const mock = okFetch(DIFF_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyDiff(FROM_RUN, TO_RUN);
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain(`from_run=${FROM_RUN}`);
  });

  it("includes to_run in the query string", async () => {
    const mock = okFetch(DIFF_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyDiff(FROM_RUN, TO_RUN);
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain(`to_run=${TO_RUN}`);
  });

  it("includes both run ids together in the query string", async () => {
    const mock = okFetch(DIFF_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await getTopologyDiff(FROM_RUN, TO_RUN);
    const url = String((mock.mock.calls[0] as unknown as [string])[0]);
    expect(url).toContain(`from_run=${FROM_RUN}`);
    expect(url).toContain(`to_run=${TO_RUN}`);
  });
});

describe("getTopologyDiff — RFC 7807 error path", () => {
  it("throws ApiError when a snapshot is missing (404)", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    await expect(getTopologyDiff(FROM_RUN, TO_RUN)).rejects.toBeInstanceOf(ApiError);
  });

  it("ApiError.status matches the HTTP status on diff endpoint", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    try {
      await getTopologyDiff(FROM_RUN, TO_RUN);
      expect.fail("should have thrown");
    } catch (err) {
      expect((err as ApiError).status).toBe(404);
    }
  });

  it("ApiError.problem carries the full RFC 7807 document on diff endpoint", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_404, 404));
    try {
      await getTopologyDiff(FROM_RUN, TO_RUN);
      expect.fail("should have thrown");
    } catch (err) {
      expect((err as ApiError).problem).toMatchObject({
        type: "urn:netops:error:not-found",
        status: 404,
      });
    }
  });

  it("synthesizes ApiError for non-problem+json error body on diff endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((): Promise<Response> =>
        Promise.resolve(new Response("Service Unavailable", { status: 503 })),
      ),
    );
    try {
      await getTopologyDiff(FROM_RUN, TO_RUN);
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(503);
    }
  });
});
