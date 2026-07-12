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
 *
 * The enums and response shapes below are thin aliases over the generated
 * OpenAPI types (AR-W1-T2): ``frontend/src/api/generated/openapi-types.ts`` is
 * produced by ``openapi-typescript`` from ``docs/api/openapi.json`` (itself
 * exported from the FastAPI app by ``backend/scripts/export_openapi.py``) and
 * is re-checked for drift by the ``contract-drift`` CI job — do not hand-edit
 * either generated file. Request bodies (``ApplicationCreate`` /
 * ``ApplicationUpdate`` / ``ApplicationDependencyCreate``) stay hand-written:
 * they intentionally carry only the user-supplied subset of fields (the
 * server assigns the rest), which is narrower than the generated request
 * schemas.
 */

import { apiFetch } from "./client";
import type { components } from "./generated/openapi-types";

// ── Enums (sourced from the generated OpenAPI schema) ──────────────────────────

/** How an application row came to exist (ADR-0052 §1). */
export type ApplicationOrigin = components["schemas"]["ApplicationOrigin"];

/** Which source asserts a dependency row (ADR-0052 §2; ``manual`` is user-owned). */
export type DependencySource = components["schemas"]["DependencySource"];

/** Rebuild-safe target kinds a manual tag may point at (ADR-0052 §2.3). */
export type DependencyTargetKind = components["schemas"]["DependencyTargetKind"];

// ── Response shapes (sourced from the generated OpenAPI schema) ────────────────

/** One application as returned by every application endpoint. */
export type ApplicationRead = components["schemas"]["ApplicationRead"];

/** Paginated application collection (``GET /applications``). */
export type ApplicationListResponse = components["schemas"]["ApplicationListResponse"];

/** One dependency row (any source) as returned by the dependency endpoints. */
export type ApplicationDependencyRead = components["schemas"]["ApplicationDependencyRead"];

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

/**
 * ``PATCH /api/v1/applications/{id}`` — update attributes (engineer+).
 *
 * Optimistic concurrency (N1): the PATCH is mandatory-conditional. Pass the
 * ``updated_at`` of the {@link ApplicationRead} the caller last read as
 * ``expectedVersion``; it travels as the ``If-Match`` ETag so a stale edit
 * cannot silently clobber a concurrent writer (the backend replies 409
 * ``stale-precondition`` when it no longer matches, 428 when omitted).
 */
export function updateApplication(
  id: string,
  body: ApplicationUpdate,
  expectedVersion: string,
): Promise<ApplicationRead> {
  return apiFetch<ApplicationRead>(`/applications/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
    headers: { "If-Match": `"${expectedVersion}"` },
  });
}

/**
 * ``DELETE /api/v1/applications/{id}`` — delete one ``manual`` application (engineer+).
 *
 * ``expectedVersion`` is OPTIONAL (unlike the PATCH): when given, the row's
 * ``updated_at`` travels as ``If-Match`` so a delete issued from a stale view is
 * refused 409 rather than destroying a row that changed underneath the user;
 * when omitted, no precondition is sent and the delete is unconditional.
 */
export function deleteApplication(id: string, expectedVersion?: string): Promise<void> {
  return apiFetch<void>(`/applications/${id}`, {
    method: "DELETE",
    ...(expectedVersion !== undefined
      ? { headers: { "If-Match": `"${expectedVersion}"` } }
      : {}),
  });
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
