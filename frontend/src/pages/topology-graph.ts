/**
 * Pure mapping helpers for the Cytoscape topology view (M2-12).
 *
 * Kept separate from ``TopologyPage.tsx`` so that page module exports only the
 * React component (react-refresh / fast-refresh convention) while these
 * framework-free functions stay independently unit-testable.
 */

import type { TopologyDiff, TopologyGraph, TopologyNode } from "../api/topology";

// ── Styling tokens ─────────────────────────────────────────────────────────────

/** Accent color per projected node label (falls back to a neutral grey). */
export const LABEL_COLOR: Record<string, string> = {
  Device: "#38bdf8", // sky
  Interface: "#a78bfa", // violet
  IPAddress: "#34d399", // emerald
  Subnet: "#fbbf24", // amber
  Vlan: "#f472b6", // pink
  VRF: "#fb923c", // orange
  Site: "#9ca3af", // grey
  // DNS layer (T13 DnsZone / DnsRecord nodes)
  DnsZone: "#c084fc", // purple
  DnsRecord: "#86efac", // light-green
};

export const DEFAULT_NODE_COLOR = "#71717a";

// ── Element mapping ────────────────────────────────────────────────────────────

/** One Cytoscape element descriptor (node or edge). */
export interface CytoscapeElement {
  data: {
    id: string;
    /** The node/edge label (node: projected label; edge: relationship type). */
    label: string;
    /** Human-friendly caption rendered on the node, or the edge type. */
    display: string;
    /** Present on edges only. */
    source?: string;
    /** Present on edges only. */
    target?: string;
  };
  /** Space-free class used by the stylesheet (the label / relationship type). */
  classes: string;
}

/** Human caption for a node, chosen by its projected label. */
export function nodeDisplay(node: TopologyNode): string {
  const props = node.properties;
  const pick = (k: string): string | undefined => {
    const v = props[k];
    return v === undefined || v === null ? undefined : String(v);
  };
  switch (node.label) {
    case "Device":
      return pick("hostname") ?? node.key;
    case "Interface":
      return pick("name") ?? node.key;
    case "IPAddress":
      return pick("address") ?? node.key;
    case "Subnet":
      return pick("cidr") ?? node.key;
    case "Vlan":
      return pick("vlan_id") !== undefined ? `VLAN ${pick("vlan_id")}` : node.key;
    case "VRF":
    case "Site":
      return pick("name") ?? node.key;
    default:
      return node.key;
  }
}

/**
 * Map a topology graph into a flat list of Cytoscape element descriptors:
 * one node element per node (keyed by ``node.key``) and one edge element per
 * edge (keyed ``src→dst:type``). Pure — no DOM, no cytoscape import needed.
 */
export function toCytoscapeElements(graph: TopologyGraph): CytoscapeElement[] {
  const nodes: CytoscapeElement[] = graph.nodes.map((node) => ({
    data: {
      id: node.key,
      label: node.label,
      display: nodeDisplay(node),
    },
    classes: node.label,
  }));
  const edges: CytoscapeElement[] = graph.edges.map((edge) => ({
    data: {
      id: `${edge.source}:${edge.target}:${edge.type}`,
      label: edge.type,
      display: edge.type,
      source: edge.source,
      target: edge.target,
    },
    classes: edge.type,
  }));
  return [...nodes, ...edges];
}

/** Read a property as a display string (``undefined``/``null`` → ``undefined``). */
export function nodeProp(node: TopologyNode, key: string): string | undefined {
  const v = node.properties[key];
  return v === undefined || v === null ? undefined : String(v);
}

/** Label-specific field list for a node's detail panel. */
export function detailFields(node: TopologyNode): { label: string; value: string | undefined }[] {
  switch (node.label) {
    case "Device":
      return [
        { label: "Hostname", value: nodeProp(node, "hostname") },
        { label: "Mgmt IP", value: nodeProp(node, "mgmt_ip") },
        { label: "Vendor", value: nodeProp(node, "vendor_id") },
        { label: "Model", value: nodeProp(node, "model") },
        { label: "Site", value: nodeProp(node, "site") },
      ];
    case "Interface":
      return [
        { label: "Name", value: nodeProp(node, "name") },
        { label: "Admin Status", value: nodeProp(node, "admin_status") },
        { label: "Oper Status", value: nodeProp(node, "oper_status") },
        { label: "IP", value: nodeProp(node, "ip_address") },
        { label: "MAC", value: nodeProp(node, "mac_address") },
      ];
    case "IPAddress":
      return [{ label: "Address", value: nodeProp(node, "address") }];
    case "Subnet":
      return [{ label: "CIDR", value: nodeProp(node, "cidr") }];
    case "Vlan":
      return [{ label: "VLAN ID", value: nodeProp(node, "vlan_id") }];
    case "VRF":
    case "Site":
      return [{ label: "Name", value: nodeProp(node, "name") }];
    default:
      return [{ label: "Key", value: node.key }];
  }
}

// ── Diff overlay (M2-14) ────────────────────────────────────────────────────

/**
 * Marker classes the stylesheet keys diff highlighting on. ``diff-added`` is
 * green, ``diff-removed`` is red; both apply to nodes and edges. They are
 * appended to an element's existing label/type class so the base label color
 * still drives un-highlighted elements.
 */
export const DIFF_ADDED_CLASS = "diff-added";
export const DIFF_REMOVED_CLASS = "diff-removed";

/** Stable lookup key for a diff edge triple ``[rel_type, src, dst]``. */
function edgeKey(type: string, source: string, target: string): string {
  return `${type} ${source} ${target}`;
}

/**
 * Pre-indexed added/removed sets derived from a {@link TopologyDiff}.
 *
 * Node membership is keyed by node ``key`` (the diff carries ``[label, key]``);
 * edge membership by the ``rel_type``/``source``/``target`` triple. Removed
 * elements may be absent from the current graph (they no longer exist), so the
 * sets are also surfaced directly for the list panel.
 */
export interface DiffIndex {
  addedNodeKeys: Set<string>;
  removedNodeKeys: Set<string>;
  addedEdgeKeys: Set<string>;
  removedEdgeKeys: Set<string>;
}

/** Key of a diff node element ``[label, key]`` (the ``key`` column). */
function nodeElementKey(element: string[]): string {
  return element[1] ?? "";
}

/** Key of a diff edge element ``[rel_type, src_key, dst_key]``. */
function edgeElementKey(element: string[]): string {
  return edgeKey(element[0] ?? "", element[1] ?? "", element[2] ?? "");
}

/** Build a {@link DiffIndex} from a diff result (pure, no DOM). */
export function indexDiff(diff: TopologyDiff): DiffIndex {
  return {
    // Diff node elements are ``[label, key]``; index by the key (column 1).
    addedNodeKeys: new Set(diff.nodes_added.map(nodeElementKey)),
    removedNodeKeys: new Set(diff.nodes_removed.map(nodeElementKey)),
    // Diff edge elements are ``[rel_type, src_key, dst_key]``.
    addedEdgeKeys: new Set(diff.edges_added.map(edgeElementKey)),
    removedEdgeKeys: new Set(diff.edges_removed.map(edgeElementKey)),
  };
}

/**
 * Return a copy of ``elements`` with ``diff-added`` / ``diff-removed`` appended
 * to the ``classes`` of any element the diff touches.
 *
 * Only elements *present in the current graph* can be highlighted; a removed
 * node/edge that is no longer projected simply has no element to style (it is
 * still listed in the diff panel). Pure: returns new descriptors, never mutates.
 */
export function applyDiffClasses(
  elements: CytoscapeElement[],
  diff: TopologyDiff,
): CytoscapeElement[] {
  const index = indexDiff(diff);
  return elements.map((el) => {
    const isEdge = el.data.source !== undefined && el.data.target !== undefined;
    let marker: string | null = null;
    if (isEdge) {
      const key = edgeKey(el.data.label, el.data.source!, el.data.target!);
      if (index.addedEdgeKeys.has(key)) marker = DIFF_ADDED_CLASS;
      else if (index.removedEdgeKeys.has(key)) marker = DIFF_REMOVED_CLASS;
    } else {
      if (index.addedNodeKeys.has(el.data.id)) marker = DIFF_ADDED_CLASS;
      else if (index.removedNodeKeys.has(el.data.id)) marker = DIFF_REMOVED_CLASS;
    }
    return marker ? { ...el, classes: `${el.classes} ${marker}` } : el;
  });
}

/** One human-readable row in the diff list panel. */
export interface DiffListItem {
  /** ``added`` | ``removed`` — drives the row color. */
  change: "added" | "removed";
  /** ``node`` | ``edge`` — the element kind. */
  kind: "node" | "edge";
  /** ``Device``/``Subnet``… for nodes; ``CONNECTED_TO``… for edges. */
  category: string;
  /** Display string: node key for nodes, ``src → dst`` for edges. */
  label: string;
}

/**
 * Flatten a diff into a stable, display-ordered list of rows for the panel.
 * Order: removed before added, edges before nodes within each (so a link
 * removal — the headline §4 criterion — surfaces first), then lexicographic.
 */
export function diffListItems(diff: TopologyDiff): DiffListItem[] {
  const items: DiffListItem[] = [];
  const edgeRow = (change: "added" | "removed", element: string[]): DiffListItem => ({
    change,
    kind: "edge",
    category: element[0] ?? "",
    label: `${element[1] ?? ""} → ${element[2] ?? ""}`,
  });
  const nodeRow = (change: "added" | "removed", element: string[]): DiffListItem => ({
    change,
    kind: "node",
    category: element[0] ?? "",
    label: element[1] ?? "",
  });
  for (const element of diff.edges_removed) items.push(edgeRow("removed", element));
  for (const element of diff.nodes_removed) items.push(nodeRow("removed", element));
  for (const element of diff.edges_added) items.push(edgeRow("added", element));
  for (const element of diff.nodes_added) items.push(nodeRow("added", element));
  return items;
}

/** Total number of changed elements across a diff (0 ⇒ identical snapshots). */
export function diffChangeCount(diff: TopologyDiff): number {
  return (
    diff.nodes_added.length +
    diff.nodes_removed.length +
    diff.edges_added.length +
    diff.edges_removed.length
  );
}
