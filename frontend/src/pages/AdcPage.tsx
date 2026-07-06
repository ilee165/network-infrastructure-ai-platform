/**
 * ADC inventory: read-only F5 BIG-IP virtual-server + pool/member view.
 *
 * Mirrors ``DevicesPage.tsx``'s inventory-table pattern: a paginated table per
 * collection, row expansion for a pool's nested members (the
 * interfaces/neighbors expansion precedent), skeleton loading, error banner,
 * and an honest empty state — no write path (W1-T3).
 *
 * Availability and enabled/admin-state are shown as SEPARATE columns (ADR-0050
 * §4.4) — never collapsed into one status pill.
 */

import { useQuery } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  listPools,
  listVirtualServers,
  type AdcAvailability,
  type PoolMemberRead,
  type PoolRead,
  type VirtualServerRead,
} from "../api/adc";
import { ErrorBanner } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { SkeletonRows } from "../components/Skeleton";
import { StatusPill, type StatusPillVariant } from "../components/StatusPill";

/** Number of columns in the virtual-servers table (for the loading skeleton). */
const VS_COLS = 6;
/** Number of columns in the pools table (for the loading skeleton). */
const POOL_COLS = 4;
/** Rows fetched per page (matches the server-side list cap). */
const PAGE_SIZE = 100;

/** Page-level mapping from an ADC availability state to a StatusPill tone. */
const AVAILABILITY_VARIANT: Record<AdcAvailability, StatusPillVariant> = {
  available: "ok",
  offline: "error",
  disabled: "neutral",
  unknown: "warn",
};

function AvailabilityBadge({ availability }: { availability: AdcAvailability }) {
  return (
    <StatusPill variant={AVAILABILITY_VARIANT[availability]}>{availability}</StatusPill>
  );
}

// ── Virtual servers ───────────────────────────────────────────────────────────

function VirtualServerTable({ items }: { items: VirtualServerRead[] }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">VIP</th>
            <th className="px-4 py-2 font-medium">Protocol</th>
            <th className="px-4 py-2 font-medium">Pool</th>
            <th className="px-4 py-2 font-medium">Enabled</th>
            <th className="px-4 py-2 font-medium">Availability</th>
          </tr>
        </thead>
        <tbody>
          {items.map((vs) => (
            <tr key={vs.id} className="border-b border-carbon-800 last:border-0">
              <td className="px-4 py-2 font-mono text-zinc-100">{vs.name}</td>
              <td className="px-4 py-2 font-mono text-zinc-300">
                {vs.vip_address ?? "—"}
                {vs.port != null ? `:${vs.port}` : ""}
              </td>
              <td className="px-4 py-2 uppercase text-zinc-400">{vs.protocol}</td>
              <td className="px-4 py-2 font-mono text-zinc-300">{vs.pool_name ?? "—"}</td>
              <td className="px-4 py-2 text-zinc-300">{vs.enabled ? "Yes" : "No"}</td>
              <td className="px-4 py-2">
                <AvailabilityBadge availability={vs.availability} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VirtualServersSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["adc-virtual-servers", offset],
    queryFn: () => listVirtualServers({ limit: PAGE_SIZE, offset }),
  });

  const items = data?.items ?? [];

  return (
    <section aria-label="Virtual servers" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Virtual servers {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={VS_COLS} label="Loading virtual servers…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="virtual-servers-error" /> : null}
      {!isPending && !error && items.length === 0 ? (
        <div
          data-testid="virtual-servers-empty-state"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">No virtual servers recorded yet</p>
          <p className="max-w-md text-xs leading-relaxed text-zinc-500">
            Virtual servers appear here once an F5 BIG-IP device is inventoried.
          </p>
        </div>
      ) : null}
      {items.length > 0 ? <VirtualServerTable items={items} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="virtual-servers"
        />
      ) : null}
    </section>
  );
}

// ── Pools + nested members ───────────────────────────────────────────────────

function PoolMembersTable({ members }: { members: PoolMemberRead[] }) {
  if (members.length === 0) {
    return <p className="text-xs text-zinc-500 px-4 py-2">No members in this pool.</p>;
  }
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-carbon-700 text-left text-zinc-500">
          <th className="py-1 pr-4 font-medium">Member</th>
          <th className="py-1 pr-4 font-medium">Address</th>
          <th className="py-1 pr-4 font-medium">Port</th>
          <th className="py-1 pr-4 font-medium">Admin state</th>
          <th className="py-1 font-medium">Availability</th>
        </tr>
      </thead>
      <tbody>
        {members.map((member) => (
          <tr key={member.name} className="border-b border-carbon-800 last:border-0">
            <td className="py-1 pr-4 font-mono text-zinc-200">{member.name}</td>
            <td className="py-1 pr-4 font-mono text-zinc-300">
              {member.address ?? member.fqdn ?? "—"}
            </td>
            <td className="py-1 pr-4 text-zinc-300">{member.port}</td>
            <td className="py-1 pr-4 text-zinc-400">{member.admin_state}</td>
            <td className="py-1">
              <AvailabilityBadge availability={member.availability} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ExpandedPoolRow({ pool, colSpan }: { pool: PoolRead; colSpan: number }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const frame = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(frame);
  }, []);

  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <div
          data-testid={`pool-detail-${pool.id}`}
          className={`bg-carbon-950 border-t border-carbon-700 px-4 pb-4 pt-2 transition-opacity duration-150 motion-reduce:transition-none ${
            visible ? "opacity-100" : "opacity-0"
          }`}
        >
          <h4 className="mb-2 font-mono text-[11px] uppercase tracking-widest text-zinc-500">
            Members
          </h4>
          <PoolMembersTable members={pool.members} />
        </div>
      </td>
    </tr>
  );
}

function PoolTable({ pools }: { pools: PoolRead[] }) {
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
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Members</th>
            <th className="px-4 py-2 font-medium">Monitors</th>
            <th className="px-4 py-2 font-medium">Availability</th>
          </tr>
        </thead>
        <tbody>
          {pools.map((pool) => (
            <Fragment key={pool.id}>
              <tr
                role="button"
                tabIndex={0}
                aria-expanded={expanded === pool.id}
                data-testid={`pool-row-${pool.id}`}
                className="cursor-pointer border-b border-carbon-800 transition-colors last:border-0 hover:bg-carbon-800/50 focus:outline-none focus:ring-1 focus:ring-inset focus:ring-accent"
                onClick={() => toggle(pool.id)}
                onKeyDown={(event) => handleKeyDown(event, pool.id)}
              >
                <td className="px-4 py-2 font-mono text-zinc-100">{pool.name}</td>
                <td className="px-4 py-2 text-zinc-300">{pool.members.length}</td>
                <td className="px-4 py-2 text-zinc-300">
                  {pool.monitors.length > 0 ? pool.monitors.join(", ") : "—"}
                </td>
                <td className="px-4 py-2">
                  <AvailabilityBadge availability={pool.availability} />
                </td>
              </tr>
              {expanded === pool.id && <ExpandedPoolRow pool={pool} colSpan={POOL_COLS} />}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PoolsSection() {
  const [offset, setOffset] = useState(0);
  const { data, error, isPending } = useQuery({
    queryKey: ["adc-pools", offset],
    queryFn: () => listPools({ limit: PAGE_SIZE, offset }),
  });

  const pools = data?.items ?? [];

  return (
    <section aria-label="Pools" className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Pools {data ? `(${data.total})` : null}
      </h3>
      {isPending ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <tbody>
              <SkeletonRows rows={4} cols={POOL_COLS} label="Loading pools…" />
            </tbody>
          </table>
        </div>
      ) : null}
      {error ? <ErrorBanner error={error} data-testid="pools-error" /> : null}
      {!isPending && !error && pools.length === 0 ? (
        <div
          data-testid="pools-empty-state"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">No pools recorded yet</p>
          <p className="max-w-md text-xs leading-relaxed text-zinc-500">
            Pools (and their members) appear here once an F5 BIG-IP device is inventoried.
          </p>
        </div>
      ) : null}
      {pools.length > 0 ? <PoolTable pools={pools} /> : null}
      {data ? (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
          label="pools"
        />
      ) : null}
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function AdcPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="ADC"
        description="F5 BIG-IP virtual-server and pool/member inventory."
      />
      <VirtualServersSection />
      <PoolsSection />
    </div>
  );
}
