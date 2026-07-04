/**
 * Typed client functions for the device inventory endpoints.
 *
 * Mirrors the backend schemas in ``app/schemas/devices.py`` and the
 * routes in ``app/api/v1/devices.py`` (M1-15).
 */

import { apiFetch } from "./client";

// ── Enums (match backend DeviceStatus / normalized enums) ─────────────────────

export type DeviceStatus = "new" | "active" | "unreachable" | "decommissioned";
export type InterfaceAdminStatus = "up" | "down";
export type InterfaceOperStatus = "up" | "down" | "testing" | "unknown";
export type InterfaceDuplex = "full" | "half" | "auto" | "unknown";
export type NeighborProtocol = "lldp" | "cdp";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface DeviceRead {
  id: string;
  hostname: string;
  mgmt_ip: string;
  vendor_id: string | null;
  model: string | null;
  os_version: string | null;
  serial: string | null;
  status: DeviceStatus;
  site: string | null;
  credential_id: string | null;
  last_discovered_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeviceListResponse {
  items: DeviceRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceInterfaceRead {
  id: string;
  name: string;
  description: string | null;
  admin_status: InterfaceAdminStatus;
  oper_status: InterfaceOperStatus;
  mac_address: string | null;
  ip_address: string | null;
  mtu: number | null;
  speed_mbps: number | null;
  duplex: InterfaceDuplex | null;
  vlan_id: number | null;
  input_errors: number | null;
  output_errors: number | null;
  collected_at: string;
  source_vendor: string;
}

export interface DeviceNeighborRead {
  id: string;
  protocol: NeighborProtocol;
  local_interface: string;
  neighbor_name: string;
  neighbor_interface: string | null;
  neighbor_platform: string | null;
  neighbor_address: string | null;
  neighbor_capabilities: string[];
  collected_at: string;
  source_vendor: string;
}

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListDevicesParams {
  status?: DeviceStatus;
  vendor_id?: string;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/devices`` — paginated, filterable device list. */
export function listDevices(params: ListDevicesParams = {}): Promise<DeviceListResponse> {
  const qs = new URLSearchParams();
  if (params.status !== undefined) qs.set("status", params.status);
  if (params.vendor_id !== undefined) qs.set("vendor_id", params.vendor_id);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<DeviceListResponse>(`/devices${query ? `?${query}` : ""}`);
}

/** ``GET /api/v1/devices/{id}/interfaces`` — normalized interfaces for one device. */
export function listDeviceInterfaces(deviceId: string): Promise<DeviceInterfaceRead[]> {
  return apiFetch<DeviceInterfaceRead[]>(`/devices/${deviceId}/interfaces`);
}

/** ``GET /api/v1/devices/{id}/neighbors`` — normalized LLDP/CDP neighbors for one device. */
export function listDeviceNeighbors(deviceId: string): Promise<DeviceNeighborRead[]> {
  return apiFetch<DeviceNeighborRead[]>(`/devices/${deviceId}/neighbors`);
}
