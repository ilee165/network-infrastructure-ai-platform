/**
 * Typed client functions for the device inventory endpoints.
 *
 * Mirrors the backend schemas in ``app/schemas/devices.py`` and the
 * routes in ``app/api/v1/devices.py`` (M1-15).
 *
 * Enums and response shapes are thin aliases over the generated OpenAPI types
 * (AR-W1-T2): ``frontend/src/api/generated/openapi-types.ts`` is produced by
 * ``openapi-typescript`` from ``docs/api/openapi.json`` (itself exported from
 * the FastAPI app by ``backend/scripts/export_openapi.py``) and is re-checked
 * for drift by the ``contract-drift`` CI job — do not hand-edit either
 * generated file. This closes the H14-class enum-drift seam (the previous
 * hand-rolled ``DeviceStatus``/``InterfaceOperStatus``/``InterfaceDuplex``
 * unions had extra values — e.g. ``"active"``/``"decommissioned"`` — never
 * sent by the wire contract).
 */

import { apiFetch } from "./client";
import type { components } from "./generated/openapi-types";

// ── Enums (sourced from the generated OpenAPI schema) ──────────────────────────

export type DeviceStatus = components["schemas"]["DeviceStatus"];
export type InterfaceAdminStatus = components["schemas"]["InterfaceAdminStatus"];
export type InterfaceOperStatus = components["schemas"]["InterfaceOperStatus"];
export type InterfaceDuplex = components["schemas"]["InterfaceDuplex"];
export type NeighborProtocol = components["schemas"]["NeighborProtocol"];

// ── Response shapes (sourced from the generated OpenAPI schema) ────────────────

export type DeviceRead = components["schemas"]["DeviceRead"];
export type DeviceListResponse = components["schemas"]["DeviceListResponse"];
export type DeviceInterfaceRead = components["schemas"]["DeviceInterfaceRead"];
export type DeviceNeighborRead = components["schemas"]["DeviceNeighborRead"];

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListDevicesParams {
  status?: DeviceStatus;
  vendor_id?: string;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/devices`` — paginated, filterable device list. */
export function listDevices(params: ListDevicesParams = {}, signal?: AbortSignal): Promise<DeviceListResponse> {
  const qs = new URLSearchParams();
  if (params.status !== undefined) qs.set("status", params.status);
  if (params.vendor_id !== undefined) qs.set("vendor_id", params.vendor_id);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<DeviceListResponse>(`/devices${query ? `?${query}` : ""}`, { signal });
}

/** ``GET /api/v1/devices/{id}/interfaces`` — normalized interfaces for one device. */
export function listDeviceInterfaces(deviceId: string, signal?: AbortSignal): Promise<DeviceInterfaceRead[]> {
  return apiFetch<DeviceInterfaceRead[]>(`/devices/${deviceId}/interfaces`, { signal });
}

/** ``GET /api/v1/devices/{id}/neighbors`` — normalized LLDP/CDP neighbors for one device. */
export function listDeviceNeighbors(deviceId: string, signal?: AbortSignal): Promise<DeviceNeighborRead[]> {
  return apiFetch<DeviceNeighborRead[]>(`/devices/${deviceId}/neighbors`, { signal });
}
