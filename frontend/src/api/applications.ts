/**
 * Typed client functions for the manual application-tagging endpoints
 * (P4 W2-T3, rider P1).
 *
 * Mirrors the backend schemas in ``app/schemas/applications.py`` and the routes
 * in ``app/api/v1/applications.py``: reads are viewer+, mutations engineer+
 * (the backend ``require_role`` is the source of truth; the store/pages gate the
 * UI as defense-in-depth). ``origin``/``origin_ref``/``source``/``provenance``
 * are all server-assigned — the create bodies here carry only user-supplied
 * fields, so the client can never forge a ``derived`` row or a non-manual edge.
 */

import { apiFetch } from "./client";

// ── Enums (match backend Application* / Dependency* StrEnum values) ────────────

/** How an application row came to exist (ADR-0052 §1). */
export type ApplicationOrigin = "manual" | "derived";

/** Which source asserts a dependency row (ADR-0052 §2; ``manual`` is user-owned). */
export type DependencySource = "manual" | "f5" | "vmware" | "dns";

/** Rebuild-safe target kinds a manual tag may point at (ADR-0052 §2.3). */
export type DependencyTargetKind = "device" | "ip_address";

// ── Response shapes ───────────────────────────────────────────────────────────

/** One application as returned by every application endpoint. */
export interface ApplicationRead {
  id: string;
  name: string;
  description: string | null;
  fqdns: string[];
  origin: ApplicationOrigin;
  origin_ref: string | null;
  owner: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

/** Paginated application collection (``GET /applications``). */
export interface ApplicationListResponse {
  items: ApplicationRead[];
  total: number;
  limit: number;
  offset: number;
}

/** One dependency row (any source) as returned by the dependency endpoints. */
export interface ApplicationDependencyRead {
  id: string;
  application_id: string;
  target_kind: DependencyTargetKind;
  target_ref: string;
  source: DependencySource;
  /** Ordered evidence chain — refs only, never embedded content (ADR-0052 §2). */
  provenance: Array<Record<string, unknown>>;
  derived_at: string;
  created_by: string | null;
  created_at: string;
}

// ── Request bodies (only user-supplied fields; the server assigns the rest) ────

/** Body of ``POST /applications`` — always creates a ``manual``-origin row. */
export interface ApplicationCreate {
  name: string;
  description?: string | null;
  owner?: string | null;
  fqdns: string[];
}

/** Body of ``PATCH /applications/{id}`` — every field optional, unset = unchanged. */
export interface ApplicationUpdate {
  name?: string | null;
  description?: string | null;
  owner?: string | null;
  fqdns?: string[] | null;
}

/** Body of ``POST /applications/{id}/dependencies`` — one manual tag. */
export interface ApplicationDependencyCreate {
  target_kind: DependencyTargetKind;
  target_ref: string;
}

// ── Query-string params ───────────────────────────────────────────────────────

/** Optional filters for ``GET /applications``. */
export interface ListApplicationsParams {
  /** Scope to one origin (``manual`` / ``derived``). */
  origin?: ApplicationOrigin;
  /** Case-insensitive name substring. */
  q?: string;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/applications`` — paginated, filterable application list (viewer+). */
export function listApplications(
  params: ListApplicationsParams = {},
): Promise<ApplicationListResponse> {
  const qs = new URLSearchParams();
  if (params.origin !== undefined) qs.set("origin", params.origin);
  if (params.q !== undefined) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<ApplicationListResponse>(`/applications${query ? `?${query}` : ""}`);
}

/** ``GET /api/v1/applications/{id}`` — one application by id (viewer+). */
export function getApplication(id: string): Promise<ApplicationRead> {
  return apiFetch<ApplicationRead>(`/applications/${id}`);
}

/** ``GET /api/v1/applications/{id}/dependencies`` — every dependency row (viewer+). */
export function listApplicationDependencies(id: string): Promise<ApplicationDependencyRead[]> {
  return apiFetch<ApplicationDependencyRead[]>(`/applications/${id}/dependencies`);
}

/** ``POST /api/v1/applications`` — create one ``manual``-origin application (engineer+). */
export function createApplication(body: ApplicationCreate): Promise<ApplicationRead> {
  return apiFetch<ApplicationRead>("/applications", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** ``PATCH /api/v1/applications/{id}`` — update attributes (engineer+). */
export function updateApplication(id: string, body: ApplicationUpdate): Promise<ApplicationRead> {
  return apiFetch<ApplicationRead>(`/applications/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

/** ``DELETE /api/v1/applications/{id}`` — delete one ``manual`` application (engineer+). */
export function deleteApplication(id: string): Promise<void> {
  return apiFetch<void>(`/applications/${id}`, { method: "DELETE" });
}

/**
 * ``POST /api/v1/applications/{id}/dependencies`` — tag one object into an
 * application as a single ``source='manual'`` row (engineer+).
 */
export function createApplicationDependency(
  id: string,
  body: ApplicationDependencyCreate,
): Promise<ApplicationDependencyRead> {
  return apiFetch<ApplicationDependencyRead>(`/applications/${id}/dependencies`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * ``DELETE /api/v1/applications/{id}/dependencies/{dependencyId}`` — remove one
 * ``manual`` dependency row (engineer+; the backend refuses derivation-owned rows).
 */
export function deleteApplicationDependency(id: string, dependencyId: string): Promise<void> {
  return apiFetch<void>(`/applications/${id}/dependencies/${dependencyId}`, { method: "DELETE" });
}
