/**
 * Pure mapping helpers for the Cytoscape topology view (M2-12).
 *
 * Kept separate from ``TopologyPage.tsx`` so that page module exports only the
 * React component (react-refresh / fast-refresh convention) while these
 * framework-free functions stay independently unit-testable.
 */

import type { TopologyGraph, TopologyNode } from "../api/topology";

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
