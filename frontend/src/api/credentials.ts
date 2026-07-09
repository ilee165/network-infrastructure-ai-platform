/**
 * Typed client for the device credential vault (``/api/v1/credentials``).
 *
 * Secrets are write-only: create/rotate accept a secret; list/read return
 * metadata only. Never store returned secrets in the SPA — create does not
 * echo the secret, and rotate does not either.
 */

import { apiFetch } from "./client";

/** Matches ``backend/app/models/inventory.py`` ``CredentialKind``. */
export type CredentialKind = "ssh" | "snmp_v2c" | "snmp_v3" | "oidc";

export interface CredentialRead {
  id: string;
  name: string;
  kind: CredentialKind;
  username: string | null;
  params: Record<string, unknown> | null;
  scope_site: string | null;
  scope_role: string | null;
  scope_device_group: string | null;
  kek_version: string;
  created_at: string;
  updated_at: string;
}

export interface CredentialListResponse {
  items: CredentialRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface CredentialCreatePayload {
  name: string;
  kind: CredentialKind;
  username?: string | null;
  secret: string;
  params?: Record<string, unknown> | null;
  scope_site?: string | null;
  scope_role?: string | null;
  scope_device_group?: string | null;
}

export interface CredentialRotatePayload {
  secret: string;
}

/** ``GET /api/v1/credentials`` — metadata only, paginated. */
export function listCredentials(opts?: {
  limit?: number;
  offset?: number;
}): Promise<CredentialListResponse> {
  const params = new URLSearchParams();
  if (opts?.limit !== undefined) {
    params.set("limit", String(opts.limit));
  }
  if (opts?.offset !== undefined) {
    params.set("offset", String(opts.offset));
  }
  const query = params.toString();
  return apiFetch<CredentialListResponse>(`/credentials${query ? `?${query}` : ""}`);
}

/** ``POST /api/v1/credentials`` — encrypt and store; response has no secret. */
export function createCredential(payload: CredentialCreatePayload): Promise<CredentialRead> {
  return apiFetch<CredentialRead>("/credentials", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** ``POST /api/v1/credentials/{id}/rotate`` — replace secret; response has no secret. */
export function rotateCredential(
  id: string,
  payload: CredentialRotatePayload,
): Promise<CredentialRead> {
  // Encode the path segment so a malicious or corrupted id cannot reshape the
  // URL (e.g. ``../..``) and send the secret body to an unintended route.
  return apiFetch<CredentialRead>(`/credentials/${encodeURIComponent(id)}/rotate`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
