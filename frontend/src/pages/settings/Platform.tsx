import { useQuery } from "@tanstack/react-query";

import { getPlatformConfig, getPlatformHealth } from "../../api/auth";
import { messageFor } from "../../components/ErrorBanner";
import { StatusPill } from "../../components/StatusPill";

function pad2(n: number): string {
  return n.toString().padStart(2, "0");
}

function utcSchedule(hour: number, minute: number): string {
  return `${pad2(hour)}:${pad2(minute)} UTC`;
}

export function SettingsPlatformSection() {
  const {
    data: health,
    isPending: healthPending,
    error: healthError,
    dataUpdatedAt: healthUpdatedAt,
    refetch: refetchHealth,
    isFetching: healthFetching,
  } = useQuery({
    queryKey: ["platform-health"],
    queryFn: getPlatformHealth,
  });

  const {
    data: config,
    isPending: configPending,
    error: configError,
  } = useQuery({
    queryKey: ["platform-config"],
    queryFn: getPlatformConfig,
  });

  const lastFetched =
    healthUpdatedAt > 0
      ? new Date(healthUpdatedAt).toLocaleTimeString()
      : null;

  return (
    <section
      aria-label="Platform health and retention"
      data-testid="settings-platform"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Platform health
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            {lastFetched && (
              <span className="text-[11px] text-zinc-500" data-testid="platform-health-fetched">
                Last fetched {lastFetched}
              </span>
            )}
            <button
              type="button"
              className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-300 hover:border-carbon-600"
              onClick={() => void refetchHealth()}
              disabled={healthFetching}
              data-testid="platform-health-refresh"
            >
              {healthFetching ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
        <p className="text-sm text-zinc-300">
          Dependency probes reuse the same checks as orchestrator readiness.
          Public <code className="font-mono text-[11px]">/health/ready</code> stays
          unauthenticated for K8s; this panel is admin-gated.
        </p>

        {healthPending && (
          <p role="status" className="text-xs text-zinc-500">
            Probing dependencies…
          </p>
        )}
        {healthError && (
          <p role="alert" className="text-xs text-status-error">
            {messageFor(healthError)}
          </p>
        )}
        {health && (
          <div className="flex flex-col gap-3">
            <StatusPill
              variant={health.status === "ok" ? "ok" : "error"}
              data-testid="platform-health-overall"
            >
              {health.status === "ok" ? "all dependencies ok" : "degraded"}
            </StatusPill>
            <div
              className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3"
              data-testid="platform-health-deps"
            >
              {Object.entries(health.dependencies).map(([name, dep]) => (
                <div
                  key={name}
                  className="rounded border border-carbon-800 px-3 py-2"
                  data-testid={`platform-dep-${name}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-zinc-200">{name}</span>
                    <StatusPill variant={dep.status === "ok" ? "ok" : "error"}>
                      {dep.status}
                    </StatusPill>
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-500">
                    {dep.latency_ms.toFixed(0)} ms
                    {dep.error ? ` · ${dep.error}` : ""}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="panel p-4 flex flex-col gap-3" data-testid="platform-retention">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Retention & export (effective config)
        </h3>
        <p className="text-sm text-zinc-300">
          Read-only deploy configuration. Change via Helm/env, not this form.
        </p>
        {configPending && (
          <p role="status" className="text-xs text-zinc-500">
            Loading effective config…
          </p>
        )}
        {configError && (
          <p role="alert" className="text-xs text-status-error">
            {messageFor(configError)}
          </p>
        )}
        {config && (
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div className="rounded border border-carbon-800 px-3 py-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Pcap retention
              </dt>
              <dd className="mt-0.5 text-zinc-200" data-testid="pcap-retention-days">
                {config.pcap_retention_days} day
                {config.pcap_retention_days === 1 ? "" : "s"} · purge schedule{" "}
                {utcSchedule(config.pcap_retention_hour, config.pcap_retention_minute)}
              </dd>
            </div>
            <div className="rounded border border-carbon-800 px-3 py-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Raw artifact retention
              </dt>
              <dd className="mt-0.5 text-zinc-200" data-testid="raw-artifact-retention-days">
                {config.raw_artifact_retention_days === 0
                  ? "disabled (keep forever)"
                  : `${config.raw_artifact_retention_days} days`}{" "}
                · schedule{" "}
                {utcSchedule(
                  config.raw_artifact_retention_hour,
                  config.raw_artifact_retention_minute,
                )}
              </dd>
            </div>
            <div className="rounded border border-carbon-800 px-3 py-2 sm:col-span-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Audit → SIEM export
              </dt>
              <dd className="mt-0.5 flex flex-wrap items-center gap-2 text-zinc-200">
                <StatusPill
                  variant={config.audit_export_configured ? "ok" : "neutral"}
                  data-testid="audit-export-pill"
                >
                  {config.audit_export_configured
                    ? `export: ${config.audit_export_format}`
                    : "export disabled"}
                </StatusPill>
                <span className="text-xs text-zinc-500">
                  Host, URL, and bearer token are never shown here.
                </span>
              </dd>
            </div>
          </dl>
        )}
      </div>
    </section>
  );
}
