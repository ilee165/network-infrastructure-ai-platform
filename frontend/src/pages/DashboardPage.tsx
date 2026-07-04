/**
 * Dashboard: the operations landing page.
 *
 * The platform-health section is real in M0: it polls
 * `GET /api/v1/health/ready` through TanStack Query and renders one status
 * card per backend dependency (postgres / neo4j / redis). The activity feed
 * is an honest empty state until M1 delivers inventory and discovery.
 *
 * Status pills use the shared `StatusPill` (audit UI_UX #3/#7) — the
 * dependency/overall status → variant mapping stays here since it's specific
 * to this page's data. The readiness-load error uses the shared
 * `ErrorBanner`, and the probing state uses `Skeleton` cards matching the
 * dependency-card layout instead of plain "Loading…" text (audit UI_UX #4).
 */

import { useQuery } from "@tanstack/react-query";
import { getReadiness, type DependencyStatus, type ReadinessReport } from "../api/health";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { Skeleton } from "../components/Skeleton";
import { StatusPill, type StatusPillVariant } from "../components/StatusPill";

/** Poll readiness on this interval so the console reflects outages quickly. */
const READINESS_REFETCH_MS = 15_000;

/** Page-level mapping from the overall readiness status to a StatusPill tone. */
const OVERALL_VARIANT: Record<ReadinessReport["status"], StatusPillVariant> = {
  ok: "ok",
  degraded: "warn",
};

/** Page-level mapping from a single dependency's status to a StatusPill tone. */
const DEPENDENCY_VARIANT: Record<DependencyStatus["status"], StatusPillVariant> = {
  ok: "ok",
  error: "error",
};

interface DependencyCardProps {
  /** Dependency key from the readiness report, e.g. "postgres". */
  name: string;
  dependency: DependencyStatus;
}

function DependencyCard({ name, dependency }: DependencyCardProps) {
  return (
    <article data-testid={`dependency-card-${name}`} className="panel flex flex-col gap-2 p-4">
      <div className="flex items-center justify-between gap-2">
        <h4 className="font-mono text-xs uppercase tracking-widest text-zinc-400">{name}</h4>
        <StatusPill variant={DEPENDENCY_VARIANT[dependency.status]}>{dependency.status}</StatusPill>
      </div>
      <p className="font-mono text-xl text-zinc-100">
        {dependency.latency_ms.toFixed(1)}
        <span className="ml-1 text-xs text-zinc-500">ms</span>
      </p>
      {dependency.error !== null ? (
        <p className="break-words font-mono text-[11px] leading-relaxed text-status-error">
          {dependency.error}
        </p>
      ) : (
        <p className="text-[11px] text-zinc-500">probe ok</p>
      )}
    </article>
  );
}

/** Skeleton placeholder matching DependencyCard's layout, shown while probing. */
function DependencyCardSkeleton({ index }: { index: number }) {
  return (
    <div data-testid={`dependency-card-skeleton-${index}`} className="panel flex flex-col gap-2 p-4">
      <div className="flex items-center justify-between gap-2">
        <Skeleton className="h-3 w-16" />
        <Skeleton className="h-4 w-12" />
      </div>
      <Skeleton className="h-6 w-20" />
      <Skeleton className="h-3 w-24" />
    </div>
  );
}

export function DashboardPage() {
  const { data, error, isPending } = useQuery({
    queryKey: ["health", "ready"],
    queryFn: getReadiness,
    refetchInterval: READINESS_REFETCH_MS,
  });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Dashboard"
        description="Platform health and operational overview."
        actions={
          data ? (
            <StatusPill variant={OVERALL_VARIANT[data.status]} data-testid="overall-status">
              {data.status}
            </StatusPill>
          ) : null
        }
      />

      <section aria-label="Dependency health" className="flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">Dependencies</h3>
        {isPending ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {[0, 1, 2].map((index) => (
              <DependencyCardSkeleton key={index} index={index} />
            ))}
          </div>
        ) : null}
        {error ? <ErrorBanner error={error} data-testid="readiness-error" /> : null}
        {data ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {Object.entries(data.dependencies).map(([name, dependency]) => (
              <DependencyCard key={name} name={name} dependency={dependency} />
            ))}
          </div>
        ) : null}
      </section>

      <EmptyState
        title="No operational activity yet"
        description="Discovery runs, configuration backups, and change-request activity will surface here once the inventory and discovery engine land."
        milestone="M1"
      />
    </div>
  );
}
