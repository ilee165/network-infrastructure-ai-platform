/**
 * Typed client functions for the M4 document-library endpoints (T14 / T16).
 *
 * Routes (all read-only; viewer+ RBAC; ADR-0019):
 *   GET /docs                  viewer+  list generated documents (paginated, filterable)
 *   GET /docs/{id}             viewer+  document detail (includes content)
 *   GET /docs/{id}/download    viewer+  download payload (title + format + content)
 *
 * Mirrors ``backend/app/schemas/config_mgmt.py`` DocumentRead / DocumentDownload
 * and ``backend/app/api/v1/docs.py``.
 */

import { apiFetch } from "./client";

// ── Enum literals (match backend DocumentKind / DocumentFormat) ───────────────

export type DocumentKind = "inventory" | "diagram" | "runbook" | "incident_report";
export type DocumentFormat = "md" | "csv" | "mermaid";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface DocumentRead {
  id: string;
  kind: DocumentKind;
  title: string;
  format: DocumentFormat;
  content: string;
  source_refs: Record<string, unknown>;
  generated_at: string;
  generated_by_session_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DocumentListResponse {
  items: DocumentRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface DocumentDownload {
  id: string;
  title: string;
  format: DocumentFormat;
  content: string;
  generated_at: string;
}

// ── Query-string params ───────────────────────────────────────────────────────

export interface ListDocumentsParams {
  kind?: DocumentKind;
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/docs`` — paginated list, optionally filtered by kind. */
export function listDocuments(
  params: ListDocumentsParams = {},
): Promise<DocumentListResponse> {
  const qs = new URLSearchParams();
  if (params.kind !== undefined) qs.set("kind", params.kind);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<DocumentListResponse>(`/docs${query ? `?${query}` : ""}`);
}

/** ``GET /api/v1/docs/{id}`` — document detail including content. */
export function getDocument(docId: string): Promise<DocumentRead> {
  return apiFetch<DocumentRead>(`/docs/${docId}`);
}

/** ``GET /api/v1/docs/{id}/download`` — download payload (title + format + content). */
export function downloadDocument(docId: string): Promise<DocumentDownload> {
  return apiFetch<DocumentDownload>(`/docs/${docId}/download`);
}
