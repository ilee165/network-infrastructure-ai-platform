/**
 * Dashboard: the operations landing page.
 *
 * The platform-health section is real in M0: it polls
 * `GET /api/v1/health/ready` through TanStack Query and renders one status
 * card per backend dependency (postgres / neo4j / redis). The activity feed
 * is an honest empty state until M1 delivers inventory and discovery.
 */

import { useQuery } from "@tanstack/react-query";
import { getReadiness, type DependencyStatus, type ReadinessReport } from "../api/health";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

/** Poll readiness on this interval so the console reflects outages quickly. */
const READINESS_REFETCH_MS = 15_000;

const PILL_BASE =
  "inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider";

const OVERALL_PILL_STYLES: Record<ReadinessReport["status"], string> = {
  ok: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  degraded: "border-status-warn/40 bg-status-warn/10 text-status-warn",
};

const DEPENDENCY_PILL_STYLES: Record<DependencyStatus["status"], string> = {
  ok: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  error: "border-status-error/40 bg-status-error/10 text-status-error",
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
        <span className={`${PILL_BASE} ${DEPENDENCY_PILL_STYLES[dependency.status]}`}>
          {dependency.status}
        </span>
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
            <span
              data-testid="overall-status"
              className={`${PILL_BASE} ${OVERALL_PILL_STYLES[data.status]}`}
            >
              {data.status}
            </span>
          ) : null
        }
      />

      <section aria-label="Dependency health" className="flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">Dependencies</h3>
        {isPending ? (
          <p role="status" className="text-xs text-zinc-500">
            Probing dependencies…
          </p>
        ) : null}
        {error ? (
          <div
            role="alert"
            className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
          >
            Readiness check failed: {error.message}
          </div>
        ) : null}
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
