/**
 * Typed client functions for the discovery run endpoints.
 *
 * Mirrors the backend schemas in ``app/schemas/discovery_api.py`` and the
 * routes in ``app/api/v1/discovery.py`` (M1-16).
 */

import { apiFetch } from "./client";
import type { DeviceStatus } from "./devices";

// ── Enums ─────────────────────────────────────────────────────────────────────

export type DiscoveryRunStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "partial";
export type { DeviceStatus } from "./devices";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface RunStatus {
  id: string;
  status: DiscoveryRunStatus;
  seeds: string[];
  hop_limit: number;
  allowlist: string[];
  credential_names: string[];
  stats: Record<string, unknown>;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface RunListResponse {
  items: RunStatus[];
  total: number;
  limit: number;
  offset: number;
}

export interface DiscoveredDeviceSummary {
  id: string;
  hostname: string;
  mgmt_ip: string;
  vendor_id: string | null;
  status: DeviceStatus;
  last_discovered_at: string | null;
}

export interface RunResults {
  run_id: string;
  status: DiscoveryRunStatus;
  device_count: number;
  interface_count: number;
  route_count: number;
  neighbor_count: number;
  devices: DiscoveredDeviceSummary[];
}

// ── Request shapes ────────────────────────────────────────────────────────────

export interface StartRunRequest {
  /** IP addresses of the seed devices. */
  seeds: string[];
  /** Maximum LLDP/CDP expansion hops (0 = seeds only). */
  hop_limit: number;
  /** CIDR networks discovery may touch. */
  allowlist: string[];
  /** Vault credential names to try against discovered devices. */
  credential_names: string[];
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``POST /api/v1/discovery/runs`` — start a new discovery run (202 Accepted). */
export function startRun(body: StartRunRequest): Promise<RunStatus> {
  return apiFetch<RunStatus>("/discovery/runs", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** ``GET /api/v1/discovery/runs`` — list runs, newest first, paginated. */
export function listRuns(params: { limit?: number; offset?: number } = {}): Promise<RunListResponse> {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<RunListResponse>(`/discovery/runs${query ? `?${query}` : ""}`);
}

/** ``GET /api/v1/discovery/runs/{id}`` — one run's lifecycle status. */
export function getRun(runId: string): Promise<RunStatus> {
  return apiFetch<RunStatus>(`/discovery/runs/${runId}`);
}
