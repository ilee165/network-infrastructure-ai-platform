/**
 * Virtualization inventory: read-only VMware VM/host/cluster/port-group view.
 *
 * Mirrors ``DevicesPage.tsx``'s inventory-table pattern: one paginated table
 * per collection, skeleton loading, error banner, and an honest empty state —
 * no write path (W1-T3). Power state/is_template and connection
 * state/maintenance mode are shown as SEPARATE columns (ADR-0051 §5.4) — never
 * collapsed into one status pill. Tools-less VMs and standalone hosts render
 * their placement/guest fields as "—", not an error.
 */

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  listComputeClusters,
  listHypervisorHosts,
  listPortGroups,
  listVirtualMachines,
  type ComputeClusterRead,
  type HostConnectionState,
  type HypervisorHostRead,
  type PortGroupRead,
  type VirtualMachineRead,
  type VmPowerState,
} from "../api/virtualization";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { SkeletonRows } from "../components/Skeleton";
import { StatusPill, type StatusPillVariant } from "../components/StatusPill";

const VM_COLS = 6;
const HOST_COLS = 5;
const CLUSTER_COLS = 4;
const PORT_GROUP_COLS = 4;
/** Rows fetched per page (matches the server-side list cap). */
const PAGE_SIZE = 100;

const POWER_STATE_VARIANT: Record<VmPowerState, StatusPillVariant> = {
  powered_on: "ok",
  powered_off: "neutral",
  suspended: "warn",
  unknown: "warn",
};

const CONNECTION_STATE_VARIANT: Record<HostConnectionState, StatusPillVariant> = {
  connected: "ok",
  disconnected: "error",
  not_responding: "error",
  unknown: "warn",
};

/** Generic empty state, matching ``DevicesPage``'s ``devices-empty-state`` idiom. */
// ── Virtual machines ──────────────────────────────────────────────────────────

function VirtualMachineTable({ items }: { items: VirtualMachineRead[] }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Power state</th>
            <th className="px-4 py-2 font-medium">Template</th>
            <th className="px-4 py-2 font-medium">Host</th>
            <th className="px-4 py-2 font-medium">Cluster</th>
            <th className="px-4 py-2 font-medium">Guest IPs</th>
          </tr>
        </thead>
        <tbody>
          {items.map((vm) => (
            <tr key={vm.id} className="border-b border-carbon-800 last:border-0">
              <td className="px-4 py-2 font-mono text-zinc-100">{vm.name}</td>
              <td className="px-4 py-2">
                <StatusPill variant={POWER_STATE_VARIANT[vm.power_state]}>
                  {vm.power_state}
                </StatusPill>
              </td>
              <td className="px-4 py-2 text-zinc-300">{vm.is_template ? "Yes" : "No"}</td>
              <td className="px-4 py-2 font-mono text-zinc-300">{vm.host_name ?? "—"}</td>
              <td className="px-4 py-2 text-zinc-300">{vm.cluster_name ?? "—"}</td>
              <td className="px-4 py-2 font-mono text-zinc-300">
                {vm.guest_ip_addresses.length > 0 ? vm.guest_ip_addresses.join(", ") : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VirtualMachinesSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["virtualization-vms", offset],
    queryFn: () => listVirtualMachines({ limit: PAGE_SIZE, offset }),
  });
  const items = data?.items ?? [];

  return (
    <section aria-label="Virtual machines" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Virtual machines {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={VM_COLS} label="Loading virtual machines…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="vms-error" /> : null}
      {!isPending && !error && items.length === 0 ? (
        <EmptyState
          data-testid="vms-empty-state"
          title="No virtual machines recorded yet"
          description="VMs appear here once a vCenter device is inventoried. Tools-less VMs still appear, with empty guest IP/hostname fields."
        />
      ) : null}
      {items.length > 0 ? <VirtualMachineTable items={items} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="vms"
        />
      ) : null}
    </section>
  );
}

// ── Hypervisor hosts ──────────────────────────────────────────────────────────

function HypervisorHostTable({ items }: { items: HypervisorHostRead[] }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Cluster</th>
            <th className="px-4 py-2 font-medium">Connection state</th>
            <th className="px-4 py-2 font-medium">Maintenance mode</th>
            <th className="px-4 py-2 font-medium">Version</th>
          </tr>
        </thead>
        <tbody>
          {items.map((host) => (
            <tr key={host.id} className="border-b border-carbon-800 last:border-0">
              <td className="px-4 py-2 font-mono text-zinc-100">{host.name}</td>
              <td className="px-4 py-2 text-zinc-300">{host.cluster_name ?? "—"}</td>
              <td className="px-4 py-2">
                <StatusPill variant={CONNECTION_STATE_VARIANT[host.connection_state]}>
                  {host.connection_state}
                </StatusPill>
              </td>
              <td className="px-4 py-2 text-zinc-300">
                {host.in_maintenance_mode ? "Yes" : "No"}
              </td>
              <td className="px-4 py-2 text-zinc-500">{host.hypervisor_version ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HypervisorHostsSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["virtualization-hosts", offset],
    queryFn: () => listHypervisorHosts({ limit: PAGE_SIZE, offset }),
  });
  const items = data?.items ?? [];

  return (
    <section aria-label="Hypervisor hosts" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Hosts {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={HOST_COLS} label="Loading hosts…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="hosts-error" /> : null}
      {!isPending && !error && items.length === 0 ? (
        <EmptyState
          data-testid="hosts-empty-state"
          title="No hosts recorded yet"
          description="Hosts appear here once a vCenter device is inventoried. Standalone hosts still appear, with no cluster."
        />
      ) : null}
      {items.length > 0 ? <HypervisorHostTable items={items} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="hosts"
        />
      ) : null}
    </section>
  );
}

// ── Compute clusters ──────────────────────────────────────────────────────────

function ComputeClusterTable({ items }: { items: ComputeClusterRead[] }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Datacenter</th>
            <th className="px-4 py-2 font-medium">DRS</th>
            <th className="px-4 py-2 font-medium">HA</th>
          </tr>
        </thead>
        <tbody>
          {items.map((cluster) => (
            <tr key={cluster.id} className="border-b border-carbon-800 last:border-0">
              <td className="px-4 py-2 font-mono text-zinc-100">{cluster.name}</td>
              <td className="px-4 py-2 text-zinc-300">{cluster.datacenter ?? "—"}</td>
              <td className="px-4 py-2 text-zinc-300">
                {cluster.drs_enabled == null ? "—" : cluster.drs_enabled ? "Yes" : "No"}
              </td>
              <td className="px-4 py-2 text-zinc-300">
                {cluster.ha_enabled == null ? "—" : cluster.ha_enabled ? "Yes" : "No"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ComputeClustersSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["virtualization-clusters", offset],
    queryFn: () => listComputeClusters({ limit: PAGE_SIZE, offset }),
  });
  const items = data?.items ?? [];

  return (
    <section aria-label="Compute clusters" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Clusters {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={CLUSTER_COLS} label="Loading clusters…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="clusters-error" /> : null}
      {!isPending && !error && items.length === 0 ? (
        <EmptyState
          data-testid="clusters-empty-state"
          title="No clusters recorded yet"
          description="Clusters appear here once a vCenter device is inventoried."
        />
      ) : null}
      {items.length > 0 ? <ComputeClusterTable items={items} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="clusters"
        />
      ) : null}
    </section>
  );
}

// ── Port groups ───────────────────────────────────────────────────────────────

function PortGroupTable({ items }: { items: PortGroupRead[] }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Switch</th>
            <th className="px-4 py-2 font-medium">Type</th>
            <th className="px-4 py-2 font-medium">VLAN</th>
          </tr>
        </thead>
        <tbody>
          {items.map((pg) => (
            <tr key={pg.id} className="border-b border-carbon-800 last:border-0">
              <td className="px-4 py-2 font-mono text-zinc-100">{pg.name}</td>
              <td className="px-4 py-2 text-zinc-300">{pg.switch_name}</td>
              <td className="px-4 py-2 uppercase text-zinc-400">{pg.switch_type}</td>
              <td className="px-4 py-2 text-zinc-300">{pg.vlan_id ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PortGroupsSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["virtualization-port-groups", offset],
    queryFn: () => listPortGroups({ limit: PAGE_SIZE, offset }),
  });
  const items = data?.items ?? [];

  return (
    <section aria-label="Port groups" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Port groups {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={PORT_GROUP_COLS} label="Loading port groups…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="port-groups-error" /> : null}
      {!isPending && !error && items.length === 0 ? (
        <EmptyState
          data-testid="port-groups-empty-state"
          title="No port groups recorded yet"
          description="Port groups appear here once a vCenter device is inventoried."
        />
      ) : null}
      {items.length > 0 ? <PortGroupTable items={items} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="port-groups"
        />
      ) : null}
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function VirtualizationPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Virtualization"
        description="VMware VM, host, cluster, and port-group inventory."
      />
      <VirtualMachinesSection />
      <HypervisorHostsSection />
      <ComputeClustersSection />
      <PortGroupsSection />
    </div>
  );
}
