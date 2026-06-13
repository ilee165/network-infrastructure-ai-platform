/**
 * Typed client functions for the topology endpoints (M2-12).
 *
 * Mirrors the backend schemas in ``app/schemas/topology.py`` and
 * ``app/engines/topology/diff.py``, and the routes in
 * ``app/api/v1/topology.py`` (M2-10).
 */

import { apiFetch } from "./client";

// ── Node / Edge types ─────────────────────────────────────────────────────────

/**
 * One projected node: its label, key value, and flat property map.
 *
 * Mirrors ``GraphNode`` in ``app/schemas/topology.py``.
 */
export interface TopologyNode {
  /** Projected node label, e.g. ``Device``, ``Subnet``. */
  label: string;
  /** Value of the label's key property (pg_id UUID or natural key string). */
  key: string;
  /** Flat, JSON-safe property map for display. */
  properties: Record<string, unknown>;
}

/**
 * One projected relationship between two node keys.
 *
 * Mirrors ``GraphEdge`` in ``app/schemas/topology.py``.
 */
export interface TopologyEdge {
  /** Relationship type, e.g. ``CONNECTED_TO``, ``ROUTES_TO``. */
  type: string;
  /** Key of the start node. */
  source: string;
  /** Key of the end node. */
  target: string;
  /** Flat, JSON-safe relationship property map. */
  properties: Record<string, unknown>;
}

// ── Response shapes ───────────────────────────────────────────────────────────

/**
 * The projected topology subgraph returned by ``GET /topology/graph``.
 *
 * Mirrors ``GraphResponse`` in ``app/schemas/topology.py``.
 * ``projected_at`` is ``null`` when the filtered subgraph contains no nodes.
 */
export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  /** ISO-8601 UTC timestamp of the most recent projection pass, or ``null``. */
  projected_at: string | null;
}

/**
 * The diff result from M2-08 between two topology snapshots.
 *
 * Each field is a lexicographically sorted list in the canonical element form:
 * - ``nodes_added`` / ``nodes_removed``: ``[[label, key], ...]``
 * - ``edges_added`` / ``edges_removed``: ``[[rel_type, src_key, dst_key], ...]``
 *
 * Mirrors ``TopologyDiff`` in ``app/engines/topology/diff.py``.
 */
export interface TopologyDiff {
  /** Nodes present in ``to_run`` but absent in ``from_run``. */
  nodes_added: string[][];
  /** Nodes present in ``from_run`` but absent in ``to_run``. */
  nodes_removed: string[][];
  /** Edges present in ``to_run`` but absent in ``from_run``. */
  edges_added: string[][];
  /** Edges present in ``from_run`` but absent in ``to_run``. */
  edges_removed: string[][];
}

/**
 * The diff between two topology snapshots returned by ``GET /topology/diff``.
 *
 * Wraps {@link TopologyDiff} with the two run ids the diff was computed from.
 * Mirrors ``TopologyDiffResponse`` in ``app/schemas/topology.py``.
 */
export interface TopologyDiffResponse {
  /** The earlier (baseline) run id. */
  from_run: string;
  /** The later (compared) run id. */
  to_run: string;
  diff: TopologyDiff;
}

// ── Query-string params ───────────────────────────────────────────────────────

/** Optional filters for ``GET /topology/graph``. */
export interface TopologyGraphParams {
  /** Scope to devices assigned to this site name. */
  site?: string;
  /** Scope to nodes belonging to this VRF. */
  vrf?: string;
  /**
   * Relationship families to include in the response.
   * ``l2`` — LLDP/CDP neighbor links only.
   * ``l3`` — subnet adjacency and routing links only.
   * ``all`` — all relationship types (default server-side).
   */
  layer?: "l2" | "l3" | "all";
}

// ── API functions ─────────────────────────────────────────────────────────────

/**
 * ``GET /api/v1/topology/graph`` — return the projected Neo4j subgraph.
 *
 * @param params - Optional filters: ``site``, ``vrf``, ``layer``.
 * @returns The projected topology graph as of the latest projection pass.
 * @throws {ApiError} For any non-2xx response (RFC 7807 problem document).
 */
export function getTopologyGraph(params: TopologyGraphParams = {}): Promise<TopologyGraph> {
  const qs = new URLSearchParams();
  if (params.site !== undefined) qs.set("site", params.site);
  if (params.vrf !== undefined) qs.set("vrf", params.vrf);
  if (params.layer !== undefined) qs.set("layer", params.layer);
  const query = qs.toString();
  return apiFetch<TopologyGraph>(`/topology/graph${query ? `?${query}` : ""}`);
}

/**
 * ``GET /api/v1/topology/diff`` — diff the snapshots of two discovery runs.
 *
 * @param fromRun - The earlier (baseline) run id (UUID string).
 * @param toRun - The later (compared) run id (UUID string).
 * @returns Added and removed nodes and edges between the two run snapshots.
 * @throws {ApiError} 404 when either run has no snapshot; 422 for invalid UUIDs.
 */
export function getTopologyDiff(fromRun: string, toRun: string): Promise<TopologyDiffResponse> {
  const qs = new URLSearchParams({ from_run: fromRun, to_run: toRun });
  return apiFetch<TopologyDiffResponse>(`/topology/diff?${qs.toString()}`);
}
