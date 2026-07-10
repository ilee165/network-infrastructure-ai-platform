/**
 * Health API types and calls, mirroring `backend/app/api/v1/health.py`.
 *
 * `GET /api/v1/health/ready` returns HTTP 200 even when dependencies are
 * down — degradation is reported in the body, never as an error status.
 */

import { apiFetch } from "./client";

/** Health of one external dependency as seen from the API process. */
export interface DependencyStatus {
  status: "ok" | "error";
  latency_ms: number;
  error: string | null;
}

/** Aggregate readiness: degraded if any dependency probe fails. */
export interface ReadinessReport {
  status: "ok" | "degraded";
  /** Keyed by dependency name; probes include postgres, schema, neo4j, redis. */
  dependencies: Record<string, DependencyStatus>;
}

/** Liveness payload: the API process and event loop are responsive. */
export interface LivenessReport {
  status: string;
}

/** `GET /api/v1/health/live` — no dependencies touched. */
export function getLiveness(): Promise<LivenessReport> {
  return apiFetch<LivenessReport>("/health/live");
}

/** `GET /api/v1/health/ready` — per-dependency postgres/schema/neo4j/redis status. */
export function getReadiness(): Promise<ReadinessReport> {
  return apiFetch<ReadinessReport>("/health/ready");
}
