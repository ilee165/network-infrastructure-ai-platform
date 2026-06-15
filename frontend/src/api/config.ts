/**
 * Typed client functions for the M4 config-snapshot, drift, and compliance
 * endpoints (T14).
 *
 * Routes (all read-only; write paths hard-rejected until M5):
 *   GET /devices/{id}/config-snapshots             viewer+  list (no content)
 *   GET /devices/{id}/config-snapshots/{snap}/content  engineer+  raw content
 *   GET /devices/{id}/drift                        engineer+  unified diff
 *   GET /devices/{id}/compliance                   engineer+  policy findings
 *
 * Mirrors ``backend/app/schemas/config_mgmt.py`` and
 * ``backend/app/api/v1/config_snapshots.py``.
 */

import { apiFetch } from "./client";

// ── Enum literals (match backend ConfigSource / Severity / FindingStatus) ─────

export type ConfigSource = "scheduled" | "on_demand";
export type Severity = "info" | "warn" | "violation";
export type FindingStatus = "pass" | "violation" | "skipped";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface ConfigSnapshotRead {
  id: string;
  device_id: string;
  captured_at: string;
  content_hash: string;
  source: ConfigSource;
  capture_run_id: string | null;
  baseline: boolean;
  created_at: string;
  updated_at: string;
}

export interface ConfigSnapshotListResponse {
  items: ConfigSnapshotRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface ConfigSnapshotContent {
  id: string;
  device_id: string;
  content_hash: string;
  /** Raw unredacted config — engineer+ only; never log or display in bulk. */
  content: string;
  baseline: boolean;
  captured_at: string;
}

export interface DriftResponse {
  device_id: string;
  has_drift: boolean;
  /** Unified diff text (empty string when has_drift is false). */
  diff: string;
  hunks: string[];
  baseline_hash: string;
  current_hash: string;
}

export interface FindingRead {
  device_id: string;
  policy_id: string;
  policy_version: number;
  rule_id: string;
  severity: Severity;
  status: FindingStatus;
  evidence: string;
}

export interface ComplianceRunResponse {
  device_id: string;
  policy_id: string;
  policy_version: number;
  findings: FindingRead[];
  violation_count: number;
  warn_count: number;
  pass_count: number;
  skipped_count: number;
}

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListSnapshotsParams {
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/devices/{id}/config-snapshots`` — paginated list (no content). */
export function listConfigSnapshots(
  deviceId: string,
  params: ListSnapshotsParams = {},
): Promise<ConfigSnapshotListResponse> {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<ConfigSnapshotListResponse>(
    `/devices/${deviceId}/config-snapshots${query ? `?${query}` : ""}`,
  );
}

/** ``GET /api/v1/devices/{id}/config-snapshots/{snapId}/content`` — engineer+ only. */
export function getSnapshotContent(
  deviceId: string,
  snapshotId: string,
): Promise<ConfigSnapshotContent> {
  return apiFetch<ConfigSnapshotContent>(
    `/devices/${deviceId}/config-snapshots/${snapshotId}/content`,
  );
}

/** ``GET /api/v1/devices/{id}/drift`` — unified diff vs approved baseline. */
export function getDeviceDrift(deviceId: string): Promise<DriftResponse> {
  return apiFetch<DriftResponse>(`/devices/${deviceId}/drift`);
}

/** ``GET /api/v1/devices/{id}/compliance`` — policy evaluation findings. */
export function getDeviceCompliance(
  deviceId: string,
  policyId?: string,
): Promise<ComplianceRunResponse> {
  const qs = new URLSearchParams();
  if (policyId !== undefined) qs.set("policy_id", policyId);
  const query = qs.toString();
  return apiFetch<ComplianceRunResponse>(
    `/devices/${deviceId}/compliance${query ? `?${query}` : ""}`,
  );
}
