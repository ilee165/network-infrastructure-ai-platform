/**
 * Typed client functions for the M5 ChangeRequest approval-queue endpoints
 * (T15 changes surface) — the human change gate.
 *
 * Routes (engineer+ RBAC; ADR-0020):
 *   GET  /agents/changes               engineer+  list pending CRs (paginated)
 *   GET  /agents/changes/{id}          engineer+  one CR (lifecycle metadata)
 *   POST /agents/changes/{id}/approve  engineer+  pending_approval -> approved
 *   POST /agents/changes/{id}/reject   engineer+  pending_approval -> draft
 *
 * The secret-bearing CR ``payload`` (the exact config diff / DDI body) is never
 * surfaced over this read surface (ADR-0020 §4 data minimization): only lifecycle
 * state, the requester, four-eyes posture, and the id-only ``target_refs`` ride
 * out. The approve/reject decision carries only an optional reviewer comment — the
 * approver + their RBAC role are taken from the authenticated principal server-side
 * (never the body), so the four-eyes ``approver != requester`` predicate cannot be
 * spoofed through the request.
 *
 * Mirrors ``backend/app/schemas/changes_api.py`` and the ``/changes`` handlers in
 * ``backend/app/api/v1/agents.py``.
 */

import { apiFetch } from "./client";

// ── Enum literals (match backend ChangeRequestState / ChangeRequestKind) ──────

export type ChangeRequestState =
  | "draft"
  | "pending_approval"
  | "approved"
  | "executing"
  | "completed"
  | "failed"
  | "rolled_back";

export type ChangeRequestKind = "config" | "ddi";

// ── Response shapes ───────────────────────────────────────────────────────────

export interface ChangeRequestRead {
  id: string;
  state: ChangeRequestState;
  kind: ChangeRequestKind;
  requester_id: string;
  four_eyes_required: boolean;
  /** Id-only references the change touches (e.g. ``{ device_ids: [...] }``). */
  target_refs: Record<string, unknown> | null;
  reasoning_trace_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface ChangeRequestListResponse {
  items: ChangeRequestRead[];
  total: number;
  limit: number;
  offset: number;
}

// ── Request bodies / params ─────────────────────────────────────────────────

/** Body of the approve / reject endpoints — an optional reviewer comment only. */
export interface ChangeDecisionRequest {
  comment?: string;
}

export interface ListChangeRequestsParams {
  limit?: number;
  offset?: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``GET /api/v1/agents/changes`` — paginated list, newest first. */
export function listChangeRequests(
  params: ListChangeRequestsParams = {},
): Promise<ChangeRequestListResponse> {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return apiFetch<ChangeRequestListResponse>(
    `/agents/changes${query ? `?${query}` : ""}`,
  );
}

/** ``GET /api/v1/agents/changes/{id}`` — one ChangeRequest by id. */
export function getChangeRequest(crId: string): Promise<ChangeRequestRead> {
  return apiFetch<ChangeRequestRead>(`/agents/changes/${crId}`);
}

/**
 * ``POST /api/v1/agents/changes/{id}/approve`` — ``pending_approval -> approved``.
 *
 * The server enforces RBAC (engineer+) and the four-eyes guard (approver !=
 * requester); a self-approval or under-privileged caller is rejected server-side
 * and surfaces here as an {@link import("./client").ApiError}.
 */
export function approveChangeRequest(
  crId: string,
  body: ChangeDecisionRequest = {},
): Promise<ChangeRequestRead> {
  return apiFetch<ChangeRequestRead>(`/agents/changes/${crId}/approve`, {
    method: "POST",
    body: JSON.stringify({ comment: body.comment ?? null }),
  });
}

/** ``POST /api/v1/agents/changes/{id}/reject`` — ``pending_approval -> draft``. */
export function rejectChangeRequest(
  crId: string,
  body: ChangeDecisionRequest = {},
): Promise<ChangeRequestRead> {
  return apiFetch<ChangeRequestRead>(`/agents/changes/${crId}/reject`, {
    method: "POST",
    body: JSON.stringify({ comment: body.comment ?? null }),
  });
}
