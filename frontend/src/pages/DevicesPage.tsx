/**
 * Devices: normalized multi-vendor inventory view with discovery launcher.
 *
 * Populated by the discovery engine (SSH/SNMP via the Cisco IOS, Cisco
 * IOS-XE, and Arista EOS plugins). Provides:
 *  - Inventory table (hostname, mgmt IP, vendor, model, OS, status, last discovered)
 *  - Row expansion for interfaces and neighbors (keyboard-operable, audit UI_UX #5)
 *  - Discovery launcher: seed IPs, hop limit, allowlist CIDRs, credential names
 *  - Discovery runs list with status badges (polls while pending/running)
 *
 * Status pills use the shared `StatusPill` (audit UI_UX #3/#7); the
 * status/run-status → variant mapping stays here since it is page-specific.
 * The in-progress "running" run status uses the `info` (accent) variant,
 * matching its pre-shared-primitive tone; the "new" device status has no
 * prior accent precedent and stays `neutral`.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  listDeviceInterfaces,
  listDeviceNeighbors,
  listDevices,
  type DeviceInterfaceRead,
  type DeviceNeighborRead,
  type DeviceRead,
} from "../api/devices";
import { listRuns, startRun } from "../api/discovery";
import type { RunStatus, StartRunRequest } from "../api/discovery";
import { ErrorBanner } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { SkeletonRows, Spinner } from "../components/Skeleton";
import { StatusPill, type StatusPillVariant } from "../components/StatusPill";
import { useUiStore } from "../stores/ui";

// ── Constants ─────────────────────────────────────────────────────────────────

/** Refresh the runs list while any run is pending/running. */
const RUNS_POLL_MS = 3_000;

/** Number of columns in the inventory table (for the loading skeleton). */
const INVENTORY_COLS = 7;
/** Number of columns in the discovery-runs table (for the loading skeleton). */
const RUNS_COLS = 6;

type RunStatusValue = RunStatus["status"];

/** Page-level mapping from a discovery run's status to a StatusPill tone. */
const RUN_VARIANT: Record<RunStatusValue, StatusPillVariant> = {
  pending: "warn",
  running: "info",
  succeeded: "ok",
  failed: "error",
};

/** Page-level mapping from a device's status to a StatusPill tone. */
const DEVICE_VARIANT: Record<DeviceRead["status"], StatusPillVariant> = {
  active: "ok",
  new: "neutral",
  unreachable: "error",
  decommissioned: "neutral",
};

// ── Status badge ──────────────────────────────────────────────────────────────

function DeviceStatusBadge({ status }: { status: DeviceRead["status"] }) {
  return <StatusPill variant={DEVICE_VARIANT[status]}>{status}</StatusPill>;
}

// ── Expanded: interfaces table ────────────────────────────────────────────────

/** Column count of the interfaces detail table (for the loading skeleton). */
const INTERFACES_COLS = 6;
/** Column count of the neighbors detail table (for the loading skeleton). */
const NEIGHBORS_COLS = 5;

function InterfacesPanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["device-interfaces", deviceId],
    queryFn: () => listDeviceInterfaces(deviceId),
  });

  if (error) {
    return (
      <div className="px-4 py-2">
        <ErrorBanner error={error} />
      </div>
    );
  }
  if (!isPending && (!data || data.length === 0)) {
    return <p className="text-xs text-zinc-500 px-4 py-2">No interfaces recorded.</p>;
  }

  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-carbon-700 text-left text-zinc-500">
          <th className="py-1 pr-4 font-medium">Name</th>
          <th className="py-1 pr-4 font-medium">IP</th>
          <th className="py-1 pr-4 font-medium">Admin</th>
          <th className="py-1 pr-4 font-medium">Oper</th>
          <th className="py-1 pr-4 font-medium">Speed</th>
          <th className="py-1 font-medium">Description</th>
        </tr>
      </thead>
      <tbody>
        {isPending ? (
          <SkeletonRows rows={3} cols={INTERFACES_COLS} label="Loading interfaces…" />
        ) : null}
        {data?.map((iface: DeviceInterfaceRead) => (
          <tr key={iface.id} className="border-b border-carbon-800 last:border-0">
            <td className="py-1 pr-4 font-mono text-zinc-200">{iface.name}</td>
            <td className="py-1 pr-4 font-mono text-zinc-300">{iface.ip_address ?? "—"}</td>
            <td className="py-1 pr-4">{iface.admin_status}</td>
            <td className="py-1 pr-4">{iface.oper_status}</td>
            <td className="py-1 pr-4">
              {iface.speed_mbps != null ? `${iface.speed_mbps} Mbps` : "—"}
            </td>
            <td className="py-1 text-zinc-500">{iface.description ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Expanded: neighbors table ─────────────────────────────────────────────────

function NeighborsPanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["device-neighbors", deviceId],
    queryFn: () => listDeviceNeighbors(deviceId),
  });

  if (error) {
    return (
      <div className="px-4 py-2">
        <ErrorBanner error={error} />
      </div>
    );
  }
  if (!isPending && (!data || data.length === 0)) {
    return <p className="text-xs text-zinc-500 px-4 py-2">No neighbors recorded.</p>;
  }

  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-carbon-700 text-left text-zinc-500">
          <th className="py-1 pr-4 font-medium">Protocol</th>
          <th className="py-1 pr-4 font-medium">Local Port</th>
          <th className="py-1 pr-4 font-medium">Neighbor</th>
          <th className="py-1 pr-4 font-medium">Remote Port</th>
          <th className="py-1 font-medium">Platform</th>
        </tr>
      </thead>
      <tbody>
        {isPending ? (
          <SkeletonRows rows={3} cols={NEIGHBORS_COLS} label="Loading neighbors…" />
        ) : null}
        {data?.map((nb: DeviceNeighborRead) => (
          <tr key={nb.id} className="border-b border-carbon-800 last:border-0">
            <td className="py-1 pr-4 font-mono uppercase text-zinc-400">{nb.protocol}</td>
            <td className="py-1 pr-4 font-mono text-zinc-200">{nb.local_interface}</td>
            <td className="py-1 pr-4 text-zinc-200">{nb.neighbor_name}</td>
            <td className="py-1 pr-4 text-zinc-300">{nb.neighbor_interface ?? "—"}</td>
            <td className="py-1 text-zinc-500">{nb.neighbor_platform ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Expanded detail row ───────────────────────────────────────────────────────

type DetailTab = "interfaces" | "neighbors";

function DeviceDetailPanel({ deviceId }: { deviceId: string }) {
  const [tab, setTab] = useState<DetailTab>("interfaces");

  const tabBtn = (t: DetailTab, label: string) => (
    <button
      type="button"
      onClick={() => setTab(t)}
      className={`px-3 py-1 text-xs font-medium transition-colors ${
        tab === t
          ? "border-b-2 border-accent text-zinc-100"
          : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="bg-carbon-950 border-t border-carbon-700 px-4 pb-4 pt-2">
      <div className="mb-2 flex gap-1 border-b border-carbon-700">
        {tabBtn("interfaces", "Interfaces")}
        {tabBtn("neighbors", "Neighbors")}
      </div>
      {tab === "interfaces" ? (
        <InterfacesPanel deviceId={deviceId} />
      ) : (
        <NeighborsPanel deviceId={deviceId} />
      )}
    </div>
  );
}

// ── Inventory table ───────────────────────────────────────────────────────────

/**
 * Expanded detail row: mounts at opacity-0 and fades to opacity-100 on the
 * next frame, giving row expansion a ~150ms transition (audit UI_UX #4)
 * instead of popping in. Reduced motion drops the transition entirely.
 */
function ExpandedDeviceRow({ deviceId, colSpan }: { deviceId: string; colSpan: number }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const frame = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(frame);
  }, []);

  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <div
          data-testid={`device-detail-${deviceId}`}
          className={`transition-opacity duration-150 motion-reduce:transition-none ${
            visible ? "opacity-100" : "opacity-0"
          }`}
        >
          <DeviceDetailPanel deviceId={deviceId} />
        </div>
      </td>
    </tr>
  );
}

function DeviceTable({ devices }: { devices: DeviceRead[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const toggle = (id: string) => setExpanded((prev) => (prev === id ? null : id));

  function handleKeyDown(event: KeyboardEvent<HTMLTableRowElement>, id: string): void {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle(id);
    }
  }

  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Hostname</th>
            <th className="px-4 py-2 font-medium">Mgmt IP</th>
            <th className="px-4 py-2 font-medium">Vendor</th>
            <th className="px-4 py-2 font-medium">Model</th>
            <th className="px-4 py-2 font-medium">OS Version</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Last Discovered</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <Fragment key={device.id}>
              <tr
                role="button"
                tabIndex={0}
                aria-expanded={expanded === device.id}
                data-testid={`device-row-${device.id}`}
                className="cursor-pointer border-b border-carbon-800 transition-colors last:border-0 hover:bg-carbon-800/50 focus:outline-none focus:ring-1 focus:ring-inset focus:ring-accent"
                onClick={() => toggle(device.id)}
                onKeyDown={(event) => handleKeyDown(event, device.id)}
              >
                <td className="px-4 py-2 font-mono text-zinc-100">{device.hostname}</td>
                <td className="px-4 py-2 font-mono text-zinc-300">{device.mgmt_ip}</td>
                <td className="px-4 py-2 text-zinc-300">{device.vendor_id ?? "—"}</td>
                <td className="px-4 py-2 text-zinc-300">{device.model ?? "—"}</td>
                <td className="px-4 py-2 text-zinc-300">{device.os_version ?? "—"}</td>
                <td className="px-4 py-2">
                  <DeviceStatusBadge status={device.status} />
                </td>
                <td className="px-4 py-2 text-zinc-500">
                  {device.last_discovered_at
                    ? new Date(device.last_discovered_at).toLocaleString()
                    : "—"}
                </td>
              </tr>
              {expanded === device.id && <ExpandedDeviceRow deviceId={device.id} colSpan={7} />}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Discovery run row ─────────────────────────────────────────────────────────

function RunRow({ run }: { run: RunStatus }) {
  // Status is kept live by the list-level refetchInterval on ['discovery-runs']
  // in DiscoveryLauncher. No per-row poll needed — it would fire requests whose
  // results are discarded (the prop value from the parent is what renders).
  return (
    <tr className="border-b border-carbon-800 last:border-0">
      <td className="px-4 py-2 font-mono text-[11px] text-zinc-500">{run.id.slice(0, 8)}…</td>
      <td className="px-4 py-2">
        <StatusPill variant={RUN_VARIANT[run.status]} data-testid={`run-status-${run.status}`}>
          {run.status}
        </StatusPill>
      </td>
      <td className="px-4 py-2 font-mono text-xs text-zinc-300">{run.seeds.join(", ")}</td>
      <td className="px-4 py-2 text-xs text-zinc-500">{run.hop_limit}</td>
      <td className="px-4 py-2 text-xs text-zinc-500">
        {new Date(run.created_at).toLocaleString()}
      </td>
      {run.error ? (
        <td className="px-4 py-2 text-xs text-status-error">{run.error}</td>
      ) : (
        <td className="px-4 py-2 text-xs text-zinc-600">—</td>
      )}
    </tr>
  );
}

// ── Discovery launcher ────────────────────────────────────────────────────────

function DiscoveryLauncher() {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((state) => state.pushToast);

  const [seeds, setSeeds] = useState("");
  const [hopLimit, setHopLimit] = useState("1");
  const [allowlist, setAllowlist] = useState("");
  const [credentials, setCredentials] = useState("");

  const { data: runsData, isPending: runsPending } = useQuery({
    queryKey: ["discovery-runs"],
    queryFn: () => listRuns({ limit: 20 }),
    // Poll while any run is active.
    refetchInterval: (query) => {
      const runs = query.state.data?.items ?? [];
      const hasActive = runs.some(
        (r) => r.status === "pending" || r.status === "running",
      );
      return hasActive ? RUNS_POLL_MS : false;
    },
  });

  const mutation = useMutation({
    mutationFn: (req: StartRunRequest) => startRun(req),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      setSeeds("");
      setAllowlist("");
      setCredentials("");
      setHopLimit("1");
      pushToast("success", "Discovery run started.");
    },
    onError: (err) => {
      pushToast("error", err instanceof Error ? err.message : "Failed to start discovery run.");
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const seedList = seeds
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const allowlistCidrs = allowlist
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const credNames = credentials
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    mutation.mutate({
      seeds: seedList,
      hop_limit: parseInt(hopLimit, 10),
      allowlist: allowlistCidrs,
      credential_names: credNames,
    });
  }

  const runs = runsData?.items ?? [];

  return (
    <section aria-label="Discovery" className="flex flex-col gap-4">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Discovery runs
      </h3>

      {/* Launcher form */}
      <form onSubmit={handleSubmit} className="panel flex flex-wrap items-end gap-3 p-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="launcher-seeds" className="text-[11px] text-zinc-500">
            Seed IPs (comma/space separated)
          </label>
          <input
            id="launcher-seeds"
            data-testid="launcher-seeds-input"
            type="text"
            placeholder="10.0.0.1, 10.0.0.2"
            value={seeds}
            onChange={(e) => setSeeds(e.target.value)}
            className="input w-56"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="launcher-hop-limit" className="text-[11px] text-zinc-500">
            Hop limit
          </label>
          <input
            id="launcher-hop-limit"
            data-testid="launcher-hop-limit-input"
            type="number"
            min={0}
            value={hopLimit}
            onChange={(e) => setHopLimit(e.target.value)}
            className="input w-20"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="launcher-allowlist" className="text-[11px] text-zinc-500">
            Allowlist CIDRs
          </label>
          <input
            id="launcher-allowlist"
            data-testid="launcher-allowlist-input"
            type="text"
            placeholder="10.0.0.0/24"
            value={allowlist}
            onChange={(e) => setAllowlist(e.target.value)}
            className="input w-40"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="launcher-credentials" className="text-[11px] text-zinc-500">
            Credential names
          </label>
          <input
            id="launcher-credentials"
            data-testid="launcher-credentials-input"
            type="text"
            placeholder="prod-ssh"
            value={credentials}
            onChange={(e) => setCredentials(e.target.value)}
            className="input w-40"
          />
        </div>
        <button
          type="submit"
          data-testid="launcher-submit-btn"
          disabled={mutation.isPending || seeds.trim() === "" || allowlist.trim() === ""}
          className="btn flex items-center justify-center gap-2"
        >
          {mutation.isPending && <Spinner aria-label="Starting run" />}
          {mutation.isPending ? "Starting…" : "Start run"}
        </button>
      </form>

      {/* Runs list */}
      {runsPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={3} cols={RUNS_COLS} />
            </tbody>
          </table>
        </div>
      ) : null}
      {!runsPending && runs.length > 0 ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-carbon-700 text-left text-zinc-500">
                <th className="px-4 py-2 font-medium">Run ID</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Seeds</th>
                <th className="px-4 py-2 font-medium">Hops</th>
                <th className="px-4 py-2 font-medium">Started</th>
                <th className="px-4 py-2 font-medium">Error</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <RunRow key={run.id} run={run} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function DevicesPage() {
  const { data, error, isPending } = useQuery({
    queryKey: ["devices"],
    queryFn: () => listDevices({ limit: 100 }),
  });

  const devices = data?.items ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Devices"
        description="Normalized multi-vendor inventory: devices, interfaces, routes, and neighbors."
        actions={
          data ? (
            <span className="badge">
              {data.total} device{data.total !== 1 ? "s" : ""}
            </span>
          ) : null
        }
      />

      {/* Inventory section */}
      <section aria-label="Device inventory" className="flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">Inventory</h3>
        {isPending ? (
          <div className="panel overflow-x-auto">
            <table className="w-full text-xs">
              <tbody>
                <SkeletonRows rows={4} cols={INVENTORY_COLS} label="Loading inventory…" />
              </tbody>
            </table>
          </div>
        ) : null}
        {error ? <ErrorBanner error={error} data-testid="inventory-error" /> : null}
        {!isPending && !error && devices.length === 0 ? (
          <div
            data-testid="devices-empty-state"
            className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
          >
            <p className="text-sm font-medium text-zinc-200">No devices discovered yet</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              Start a discovery run below to seed the inventory from your network devices via
              SSH/SNMP. The discovery engine uses the Cisco IOS, Cisco IOS-XE, and Arista EOS
              plugins.
            </p>
          </div>
        ) : null}
        {devices.length > 0 ? <DeviceTable devices={devices} /> : null}
      </section>

      <DiscoveryLauncher />
    </div>
  );
}
