/**
 * Applications: the manual application-tagging surface (P4 W2-T3).
 *
 * Read surface (rider P2): a paginated application list with per-origin badges
 * and expandable per-application dependency detail carrying per-source badges —
 * the AdcPage inventory-table + row-expansion pattern. Reads are viewer+.
 *
 * Write flows + role gating (rider P3) layer on top: create/edit/delete of
 * ``manual``-origin applications and manual dependency rows, gated to
 * ``engineer``+ as defense-in-depth over the backend ``require_role`` (the
 * source of truth). ``derived`` applications are lifecycle-owned by derivation:
 * the UI never offers to delete one (the backend refuses it with a 409).
 */

import { useQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  listApplicationDependencies,
  listApplications,
  type ApplicationOrigin,
  type ApplicationRead,
  type DependencySource,
} from "../api/applications";
import { ErrorBanner } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { SkeletonRows } from "../components/Skeleton";

/** Rows fetched per page (matches the server-side list cap of 500; 100 is plenty). */
const PAGE_SIZE = 100;
/** Column count of the applications table (for the loading skeleton). */
const APP_COLS = 4;

/** Tailwind tone per application origin — derived vs user-owned are visually distinct. */
const ORIGIN_TONE: Record<ApplicationOrigin, string> = {
  manual: "bg-accent/15 text-accent",
  derived: "bg-carbon-700 text-zinc-300",
};

/** Tailwind tone per dependency source, so an edge's provenance reads at a glance. */
const SOURCE_TONE: Record<DependencySource, string> = {
  manual: "bg-accent/15 text-accent",
  f5: "bg-sky-500/15 text-sky-300",
  vmware: "bg-emerald-500/15 text-emerald-300",
  dns: "bg-amber-500/15 text-amber-300",
};

function OriginBadge({ application }: { application: ApplicationRead }) {
  return (
    <span
      data-testid={`application-origin-${application.id}`}
      className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${ORIGIN_TONE[application.origin]}`}
    >
      {application.origin}
    </span>
  );
}

function SourceBadge({ id, source }: { id: string; source: DependencySource }) {
  return (
    <span
      data-testid={`dependency-source-${id}`}
      className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SOURCE_TONE[source]}`}
    >
      {source}
    </span>
  );
}

// ── Dependency detail (expanded row) ───────────────────────────────────────────

function DependencyDetail({ application, colSpan }: { application: ApplicationRead; colSpan: number }) {
  const { data, error, isPending } = useQuery({
    queryKey: ["application-dependencies", application.id],
    queryFn: () => listApplicationDependencies(application.id),
  });

  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <div
          data-testid={`application-detail-${application.id}`}
          className="border-t border-carbon-700 bg-carbon-950 px-4 pb-4 pt-2"
        >
          <h4 className="mb-2 font-mono text-[11px] uppercase tracking-widest text-zinc-500">
            Dependencies
          </h4>
          {isPending ? <p className="px-1 py-2 text-xs text-zinc-500">Loading dependencies…</p> : null}
          {error ? <ErrorBanner error={error} data-testid={`dependency-error-${application.id}`} /> : null}
          {!isPending && !error && (data?.length ?? 0) === 0 ? (
            <p className="px-1 py-2 text-xs text-zinc-500">No dependencies recorded for this application.</p>
          ) : null}
          {data && data.length > 0 ? (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-carbon-700 text-left text-zinc-500">
                  <th className="py-1 pr-4 font-medium">Target kind</th>
                  <th className="py-1 pr-4 font-medium">Target</th>
                  <th className="py-1 font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {data.map((dep) => (
                  <tr key={dep.id} className="border-b border-carbon-800 last:border-0">
                    <td className="py-1 pr-4 text-zinc-300">{dep.target_kind}</td>
                    <td className="py-1 pr-4 font-mono text-zinc-400">{dep.target_ref}</td>
                    <td className="py-1">
                      <SourceBadge id={dep.id} source={dep.source} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

// ── Applications table ─────────────────────────────────────────────────────────

function ApplicationsTable({ items }: { items: ApplicationRead[] }) {
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
            <th className="px-4 py-2 font-medium">Origin</th>
            <th className="px-4 py-2 font-medium">Owner</th>
            <th className="px-4 py-2 font-medium">FQDNs</th>
          </tr>
        </thead>
        <tbody>
          {items.map((app) => (
            <Fragment key={app.id}>
              <tr
                role="button"
                tabIndex={0}
                aria-expanded={expanded === app.id}
                data-testid={`application-row-${app.id}`}
                className="cursor-pointer border-b border-carbon-800 transition-colors last:border-0 hover:bg-carbon-800/50 focus:outline-none focus:ring-1 focus:ring-inset focus:ring-accent"
                onClick={() => toggle(app.id)}
                onKeyDown={(event) => handleKeyDown(event, app.id)}
              >
                <td className="px-4 py-2 font-mono text-zinc-100">{app.name}</td>
                <td className="px-4 py-2">
                  <OriginBadge application={app} />
                </td>
                <td className="px-4 py-2 text-zinc-300">{app.owner ?? "—"}</td>
                <td className="px-4 py-2 font-mono text-zinc-400">
                  {app.fqdns.length > 0 ? app.fqdns.join(", ") : "—"}
                </td>
              </tr>
              {expanded === app.id && <DependencyDetail application={app} colSpan={APP_COLS} />}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────────

export function ApplicationsPage() {
  const [offset, setOffset] = useState(0);
  const [origin, setOrigin] = useState<ApplicationOrigin | "all">("all");

  const { data, error, isPending } = useQuery({
    queryKey: ["applications", offset, origin],
    queryFn: () =>
      listApplications({
        limit: PAGE_SIZE,
        offset,
        ...(origin === "all" ? {} : { origin }),
      }),
  });

  const items = data?.items ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Applications"
        description="Application-dependency inventory — derived (F5 / VMware / DNS) and manually tagged."
      />

      <section aria-label="Applications" className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Applications {data ? `(${data.total})` : null}
          </h3>
          <label className="flex items-center gap-2 text-xs text-zinc-500">
            Origin
            <select
              data-testid="applications-origin-filter"
              value={origin}
              onChange={(event) => {
                setOrigin(event.target.value as ApplicationOrigin | "all");
                setOffset(0);
              }}
              className="rounded border border-carbon-700 bg-carbon-900 px-2 py-1 text-xs text-zinc-200"
            >
              <option value="all">All</option>
              <option value="manual">Manual</option>
              <option value="derived">Derived</option>
            </select>
          </label>
        </div>

        {isPending ? (
          <div className="panel overflow-x-auto">
            <table className="w-full text-xs">
              <tbody>
                <SkeletonRows rows={4} cols={APP_COLS} label="Loading applications…" />
              </tbody>
            </table>
          </div>
        ) : null}
        {error ? <ErrorBanner error={error} data-testid="applications-error" /> : null}
        {!isPending && !error && items.length === 0 ? (
          <div
            data-testid="applications-empty-state"
            className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
          >
            <p className="text-sm font-medium text-zinc-200">No applications recorded yet</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              Applications appear here once the derivation pipeline runs, or when you tag one manually.
            </p>
          </div>
        ) : null}
        {items.length > 0 ? <ApplicationsTable items={items} /> : null}
        {data ? (
          <Pagination
            offset={offset}
            limit={PAGE_SIZE}
            total={data.total}
            onChange={setOffset}
            label="applications"
          />
        ) : null}
      </section>
    </div>
  );
}
