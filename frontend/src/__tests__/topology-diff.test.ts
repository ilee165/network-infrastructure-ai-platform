/**
 * Unit tests for the pure topology-diff overlay helpers (M2-14).
 *
 * Cover the framework-free functions in ``pages/topology-graph.ts`` that turn a
 * {@link TopologyDiff} into highlight classes on Cytoscape elements and into
 * the diff list-panel rows. No DOM, no cytoscape, no backend.
 */

import { describe, expect, it } from "vitest";
import type { TopologyDiff, TopologyGraph } from "../api/topology";
import {
  DIFF_ADDED_CLASS,
  DIFF_REMOVED_CLASS,
  applyDiffClasses,
  diffChangeCount,
  diffListItems,
  indexDiff,
  toCytoscapeElements,
} from "../pages/topology-graph";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DEV1 = "11111111-1111-1111-1111-111111111111";
const IF1 = "22222222-2222-2222-2222-222222222222";
const IF2 = "33333333-3333-3333-3333-333333333333";

/** A small graph: one device, two interfaces, one CONNECTED_TO link IF1↔IF2. */
const GRAPH: TopologyGraph = {
  nodes: [
    { label: "Device", key: DEV1, properties: { hostname: "core-1" } },
    { label: "Interface", key: IF1, properties: { name: "Ethernet1" } },
    { label: "Interface", key: IF2, properties: { name: "Ethernet2" } },
  ],
  edges: [
    { type: "HAS_INTERFACE", source: DEV1, target: IF1, properties: {} },
    { type: "CONNECTED_TO", source: IF1, target: IF2, properties: {} },
  ],
  projected_at: "2026-06-13T01:00:00Z",
};

/** The headline §4 diff: exactly one CONNECTED_TO edge removed. */
const LINK_REMOVED_DIFF: TopologyDiff = {
  nodes_added: [],
  nodes_removed: [],
  edges_added: [],
  edges_removed: [["CONNECTED_TO", IF1, IF2]],
};

const EMPTY_DIFF: TopologyDiff = {
  nodes_added: [],
  nodes_removed: [],
  edges_added: [],
  edges_removed: [],
};

// ── indexDiff ───────────────────────────────────────────────────────────────

describe("indexDiff", () => {
  it("indexes added/removed node keys by the key column of [label, key]", () => {
    const diff: TopologyDiff = {
      nodes_added: [["Device", "new-dev"]],
      nodes_removed: [["Subnet", "10.0.0.0/24"]],
      edges_added: [],
      edges_removed: [],
    };
    const idx = indexDiff(diff);
    expect(idx.addedNodeKeys.has("new-dev")).toBe(true);
    expect(idx.removedNodeKeys.has("10.0.0.0/24")).toBe(true);
  });

  it("indexes edges by the rel_type/src/dst triple", () => {
    const idx = indexDiff(LINK_REMOVED_DIFF);
    expect(idx.removedEdgeKeys.has(`CONNECTED_TO ${IF1} ${IF2}`)).toBe(true);
    expect(idx.addedEdgeKeys.size).toBe(0);
  });
});

// ── applyDiffClasses ──────────────────────────────────────────────────────────

describe("applyDiffClasses", () => {
  it("marks a removed CONNECTED_TO edge present in the graph with diff-removed", () => {
    const elements = toCytoscapeElements(GRAPH);
    const annotated = applyDiffClasses(elements, LINK_REMOVED_DIFF);
    const edge = annotated.find((e) => e.data.id === `${IF1}:${IF2}:CONNECTED_TO`);
    expect(edge).toBeDefined();
    expect(edge!.classes).toContain(DIFF_REMOVED_CLASS);
  });

  it("leaves untouched edges without any diff class", () => {
    const elements = toCytoscapeElements(GRAPH);
    const annotated = applyDiffClasses(elements, LINK_REMOVED_DIFF);
    const hasIface = annotated.find((e) => e.data.id === `${DEV1}:${IF1}:HAS_INTERFACE`);
    expect(hasIface!.classes).not.toContain(DIFF_REMOVED_CLASS);
    expect(hasIface!.classes).not.toContain(DIFF_ADDED_CLASS);
  });

  it("marks an added node present in the graph with diff-added", () => {
    const diff: TopologyDiff = {
      nodes_added: [["Device", DEV1]],
      nodes_removed: [],
      edges_added: [],
      edges_removed: [],
    };
    const annotated = applyDiffClasses(toCytoscapeElements(GRAPH), diff);
    const dev = annotated.find((e) => e.data.id === DEV1);
    expect(dev!.classes).toContain(DIFF_ADDED_CLASS);
    // The base label class is preserved alongside the marker.
    expect(dev!.classes).toContain("Device");
  });

  it("does not mutate the input elements (returns new descriptors)", () => {
    const elements = toCytoscapeElements(GRAPH);
    const before = elements.map((e) => e.classes);
    applyDiffClasses(elements, LINK_REMOVED_DIFF);
    expect(elements.map((e) => e.classes)).toEqual(before);
  });

  it("is a no-op for an empty diff", () => {
    const elements = toCytoscapeElements(GRAPH);
    const annotated = applyDiffClasses(elements, EMPTY_DIFF);
    for (const el of annotated) {
      expect(el.classes).not.toContain(DIFF_ADDED_CLASS);
      expect(el.classes).not.toContain(DIFF_REMOVED_CLASS);
    }
  });

  it("ignores a removed element that is absent from the current graph", () => {
    // A removed edge whose endpoints no longer exist cannot be highlighted —
    // it must not throw and must not invent an element.
    const diff: TopologyDiff = {
      nodes_added: [],
      nodes_removed: [],
      edges_added: [],
      edges_removed: [["CONNECTED_TO", "ghost-a", "ghost-b"]],
    };
    const annotated = applyDiffClasses(toCytoscapeElements(GRAPH), diff);
    expect(annotated.some((e) => e.classes.includes(DIFF_REMOVED_CLASS))).toBe(false);
  });
});

// ── diffListItems ─────────────────────────────────────────────────────────────

describe("diffListItems", () => {
  it("surfaces a removed link as a removed/edge row with src → dst", () => {
    const items = diffListItems(LINK_REMOVED_DIFF);
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual({
      change: "removed",
      kind: "edge",
      category: "CONNECTED_TO",
      label: `${IF1} → ${IF2}`,
    });
  });

  it("orders removed edges before removed nodes before added elements", () => {
    const diff: TopologyDiff = {
      nodes_added: [["Device", "added-dev"]],
      nodes_removed: [["Subnet", "10.0.0.0/24"]],
      edges_added: [["HAS_INTERFACE", "d", "i"]],
      edges_removed: [["CONNECTED_TO", IF1, IF2]],
    };
    const items = diffListItems(diff);
    expect(items.map((i) => `${i.change}:${i.kind}`)).toEqual([
      "removed:edge",
      "removed:node",
      "added:edge",
      "added:node",
    ]);
  });

  it("returns an empty list for an empty diff", () => {
    expect(diffListItems(EMPTY_DIFF)).toEqual([]);
  });
});

// ── diffChangeCount ───────────────────────────────────────────────────────────

describe("diffChangeCount", () => {
  it("counts every changed element across all four buckets", () => {
    const diff: TopologyDiff = {
      nodes_added: [["Device", "a"]],
      nodes_removed: [["Device", "b"]],
      edges_added: [["CONNECTED_TO", "a", "b"]],
      edges_removed: [["CONNECTED_TO", "c", "d"]],
    };
    expect(diffChangeCount(diff)).toBe(4);
  });

  it("is zero for an identical-snapshot diff", () => {
    expect(diffChangeCount(EMPTY_DIFF)).toBe(0);
  });
});
