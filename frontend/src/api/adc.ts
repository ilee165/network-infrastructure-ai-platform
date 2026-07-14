/**
 * Typed client functions for the ADC (F5 BIG-IP) inventory endpoints.
 *
 * Mirrors ``src/api/devices.ts``: the backend schemas in
 * ``app/schemas/adc.py`` and the routes in ``app/api/v1/adc.py`` (W1-T3).
 * Read-only — there is no write path.
 */

import { apiFetch } from "./client";

// ── Enums (match backend Adc* StrEnum values) ─────────────────────────────────

export type AdcProtocol = "tcp" | "udp" | "sctp" | "any" | "other";
export type AdcAvailability = "available" | "offline" | "disabled" | "unknown";
export type AdcAdminState = "enabled" | "disabled" | "forced_offline";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface VirtualServerRead {
  id: string;
  device_id: string;
  name: string;
  vip_address: string | null;
  port: number | null;
  protocol: AdcProtocol;
  vrf: string | null;
  enabled: boolean;
  availability: AdcAvailability;
  pool_name: string | null;
  description: string | null;
  collected_at: string;
  source_vendor: string;
}

export interface VirtualServerListResponse {
  items: VirtualServerRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface PoolMemberRead {
  name: string;
  address: string | null;
  fqdn: string | null;
  port: number;
  vrf: string | null;
  admin_state: AdcAdminState;
  availability: AdcAvailability;
}

export interface PoolRead {
  id: string;
  device_id: string;
  name: string;
  monitors: string[];
  availability: AdcAvailability;
  members: PoolMemberRead[];
  description: string | null;
  collected_at: string;
  source_vendor: string;
}

export interface PoolListResponse {
  items: PoolRead[];
  total: number;
  limit: number;
  offset: number;
}

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListVirtualServersParams {
  device_id?: string;
  availability?: AdcAvailability;
  limit?: number;
  offset?: number;
}

export interface ListPoolsParams {
  device_id?: string;
  availability?: AdcAvailability;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/adc/virtual-servers`` — paginated, filterable virtual-server list. */
export function listVirtualServers(
  params: ListVirtualServersParams = {},
  signal?: AbortSignal,
): Promise<VirtualServerListResponse> {
  const qs = new URLSearchParams();
  if (params.device_id !== undefined) qs.set("device_id", params.device_id);
  if (params.availability !== undefined) qs.set("availability", params.availability);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<VirtualServerListResponse>(`/adc/virtual-servers${query ? `?${query}` : ""}`, { signal });
}

/** ``GET /api/v1/adc/virtual-servers/{id}`` — one virtual server by id. */
export function getVirtualServer(id: string): Promise<VirtualServerRead> {
  return apiFetch<VirtualServerRead>(`/adc/virtual-servers/${id}`);
}

/** ``GET /api/v1/adc/pools`` — paginated, filterable pool list (nested members). */
export function listPools(params: ListPoolsParams = {}, signal?: AbortSignal): Promise<PoolListResponse> {
  const qs = new URLSearchParams();
  if (params.device_id !== undefined) qs.set("device_id", params.device_id);
  if (params.availability !== undefined) qs.set("availability", params.availability);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<PoolListResponse>(`/adc/pools${query ? `?${query}` : ""}`, { signal });
}

/** ``GET /api/v1/adc/pools/{id}`` — one pool with nested members by id. */
export function getPool(id: string): Promise<PoolRead> {
  return apiFetch<PoolRead>(`/adc/pools/${id}`);
}
