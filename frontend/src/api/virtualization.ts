/**
 * Typed client functions for the virtualization (VMware) inventory endpoints.
 *
 * Mirrors ``src/api/devices.ts``: the backend schemas in
 * ``app/schemas/virtualization.py`` and the routes in
 * ``app/api/v1/virtualization.py`` (W1-T3). Read-only — there is no write path.
 */

import { apiFetch } from "./client";

// ── Enums (match backend Vm*/Host*/VirtualSwitchType StrEnum values) ─────────

export type VmPowerState = "powered_on" | "powered_off" | "suspended" | "unknown";
export type HostConnectionState = "connected" | "disconnected" | "not_responding" | "unknown";
export type VirtualSwitchType = "standard" | "distributed";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface VirtualNicRead {
  label: string;
  mac_address: string;
  port_group_name: string | null;
  switch_type: VirtualSwitchType | null;
  connected: boolean;
  ip_addresses: string[];
}

export interface VirtualMachineRead {
  id: string;
  device_id: string;
  name: string;
  moref: string;
  instance_uuid: string | null;
  is_template: boolean;
  power_state: VmPowerState;
  guest_hostname: string | null;
  guest_ip_addresses: string[];
  host_name: string | null;
  cluster_name: string | null;
  datacenter: string | null;
  nics: VirtualNicRead[];
  description: string | null;
  collected_at: string;
  source_vendor: string;
}

export interface VirtualMachineListResponse {
  items: VirtualMachineRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface PhysicalNicRead {
  name: string;
  mac_address: string;
  link_speed_mbps: number | null;
}

export interface HypervisorHostRead {
  id: string;
  device_id: string;
  name: string;
  moref: string;
  cluster_name: string | null;
  datacenter: string | null;
  vendor: string | null;
  model: string | null;
  hypervisor_version: string | null;
  connection_state: HostConnectionState;
  in_maintenance_mode: boolean;
  management_ip: string | null;
  pnics: PhysicalNicRead[];
  collected_at: string;
  source_vendor: string;
}

export interface HypervisorHostListResponse {
  items: HypervisorHostRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface ComputeClusterRead {
  id: string;
  device_id: string;
  name: string;
  moref: string;
  datacenter: string | null;
  drs_enabled: boolean | null;
  ha_enabled: boolean | null;
  collected_at: string;
  source_vendor: string;
}

export interface ComputeClusterListResponse {
  items: ComputeClusterRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface PortGroupRead {
  id: string;
  device_id: string;
  name: string;
  switch_name: string;
  switch_type: VirtualSwitchType;
  datacenter: string | null;
  host_name: string | null;
  vlan_id: number | null;
  moref: string | null;
  uplink_pnic_names: string[];
  collected_at: string;
  source_vendor: string;
}

export interface PortGroupListResponse {
  items: PortGroupRead[];
  total: number;
  limit: number;
  offset: number;
}

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListVirtualMachinesParams {
  device_id?: string;
  power_state?: VmPowerState;
  cluster_name?: string;
  limit?: number;
  offset?: number;
}

export interface ListHypervisorHostsParams {
  device_id?: string;
  connection_state?: HostConnectionState;
  cluster_name?: string;
  limit?: number;
  offset?: number;
}

export interface ListComputeClustersParams {
  device_id?: string;
  datacenter?: string;
  limit?: number;
  offset?: number;
}

export interface ListPortGroupsParams {
  device_id?: string;
  switch_type?: VirtualSwitchType;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

function buildQuery<T extends object>(params: T): string {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, string | number | undefined>)) {
    if (value !== undefined) qs.set(key, String(value));
  }
  const query = qs.toString();
  return query ? `?${query}` : "";
}

/** ``GET /api/v1/virtualization/vms`` — paginated, filterable VM list. */
export function listVirtualMachines(
  params: ListVirtualMachinesParams = {},
): Promise<VirtualMachineListResponse> {
  return apiFetch<VirtualMachineListResponse>(`/virtualization/vms${buildQuery(params)}`);
}

/** ``GET /api/v1/virtualization/vms/{id}`` — one VM by id. */
export function getVirtualMachine(id: string): Promise<VirtualMachineRead> {
  return apiFetch<VirtualMachineRead>(`/virtualization/vms/${id}`);
}

/** ``GET /api/v1/virtualization/hosts`` — paginated, filterable host list. */
export function listHypervisorHosts(
  params: ListHypervisorHostsParams = {},
): Promise<HypervisorHostListResponse> {
  return apiFetch<HypervisorHostListResponse>(`/virtualization/hosts${buildQuery(params)}`);
}

/** ``GET /api/v1/virtualization/hosts/{id}`` — one host by id. */
export function getHypervisorHost(id: string): Promise<HypervisorHostRead> {
  return apiFetch<HypervisorHostRead>(`/virtualization/hosts/${id}`);
}

/** ``GET /api/v1/virtualization/clusters`` — paginated, filterable cluster list. */
export function listComputeClusters(
  params: ListComputeClustersParams = {},
): Promise<ComputeClusterListResponse> {
  return apiFetch<ComputeClusterListResponse>(`/virtualization/clusters${buildQuery(params)}`);
}

/** ``GET /api/v1/virtualization/clusters/{id}`` — one cluster by id. */
export function getComputeCluster(id: string): Promise<ComputeClusterRead> {
  return apiFetch<ComputeClusterRead>(`/virtualization/clusters/${id}`);
}

/** ``GET /api/v1/virtualization/port-groups`` — paginated, filterable port-group list. */
export function listPortGroups(
  params: ListPortGroupsParams = {},
): Promise<PortGroupListResponse> {
  return apiFetch<PortGroupListResponse>(`/virtualization/port-groups${buildQuery(params)}`);
}

/** ``GET /api/v1/virtualization/port-groups/{id}`` — one port group by id. */
export function getPortGroup(id: string): Promise<PortGroupRead> {
  return apiFetch<PortGroupRead>(`/virtualization/port-groups/${id}`);
}
