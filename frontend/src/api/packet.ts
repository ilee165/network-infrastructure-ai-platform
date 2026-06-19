/**
 * Typed client functions for the M5-T15 packet-capture / analysis endpoints.
 *
 * Routes (all under ``/api/v1/agents``; engineer+ RBAC; ADR-0023):
 *   POST /agents/captures                    — launch a capture (async, 202)
 *   GET  /agents/captures/{capture_id}       — poll lifecycle status
 *   GET  /agents/captures/{capture_id}/analysis — analysis findings (read-only)
 *
 * Mirrors ``backend/app/schemas/packet_api.py`` and
 * ``backend/app/engines/packet/analysis.py``.
 * Data minimization (ADR-0023 §1): analysis findings contain only aggregated
 * counts (top talkers, protocol counts, TCP-anomaly indicators) — never raw
 * packet bytes.
 */

import { apiFetch } from "./client";

// ── Enums (match backend CaptureStatus) ───────────────────────────────────────

export type CaptureStatus = "queued" | "completed" | "tombstoned";

// ── Request / response shapes ─────────────────────────────────────────────────

/** Body of ``POST /api/v1/agents/captures``. */
export interface CaptureLaunchRequest {
  interface: string;
  capture_filter?: string | null;
  device_id?: string | null;
  duration_seconds?: number | null;
  size_bytes?: number | null;
}

/** Result of ``POST /api/v1/agents/captures`` (202 queued). */
export interface CaptureLaunchResponse {
  capture_id: string;
  status: CaptureStatus;
  interface: string;
  device_id: string | null;
}

/** Metadata + lifecycle status for one capture (no raw pcap content). */
export interface CaptureStatusResponse {
  capture_id: string;
  status: CaptureStatus;
  interface: string;
  device_id: string | null;
  byte_count: number | null;
  packet_count: number | null;
  sha256: string | null;
  started_at: string;
  ended_at: string | null;
  retention_expires_at: string;
  tombstoned_at: string | null;
}

/**
 * One src→dst endpoint pair and how many packets/bytes it carried.
 * Mirrors ``Conversation`` in ``analysis.py``.
 */
export interface Conversation {
  src: string;
  dst: string;
  packets: number;
  bytes: number;
}

/** Packet count for one protocol. Mirrors ``ProtocolCount`` in ``analysis.py``. */
export interface ProtocolCount {
  protocol: string;
  packets: number;
}

/**
 * Normalized, LLM-safe summary of one pcap (no raw payload bytes).
 * Mirrors ``PacketFindings`` in ``backend/app/engines/packet/analysis.py``.
 */
export interface PacketFindings {
  packet_count: number;
  top_talkers: Conversation[];
  protocol_hierarchy: ProtocolCount[];
  tcp_resets: number;
  tcp_retransmissions: number;
}

// ── API functions ─────────────────────────────────────────────────────────────

/**
 * ``POST /api/v1/agents/captures`` — launch a capture asynchronously.
 *
 * Returns 202 with the capture id + ``queued`` status; poll
 * ``getCaptureStatus`` for lifecycle progress.
 *
 * @throws {ApiError} 422 for invalid BPF filter; 403 for insufficient RBAC.
 */
export function launchCapture(body: CaptureLaunchRequest): Promise<CaptureLaunchResponse> {
  return apiFetch<CaptureLaunchResponse>("/agents/captures", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * ``GET /api/v1/agents/captures/{capture_id}`` — poll one capture's lifecycle.
 *
 * @throws {ApiError} 404 when the capture id is unknown.
 */
export function getCaptureStatus(captureId: string): Promise<CaptureStatusResponse> {
  return apiFetch<CaptureStatusResponse>(`/agents/captures/${captureId}`);
}

/**
 * ``GET /api/v1/agents/captures/{capture_id}/analysis`` — analysis findings.
 *
 * Returns structured findings (top talkers / protocol hierarchy / TCP anomalies)
 * for a completed capture. Never returns raw packet bytes (ADR-0023 §1).
 *
 * @param captureId - UUID of the completed capture.
 * @param displayFilter - Optional tshark display filter string.
 * @throws {ApiError} 404 when the capture is unknown; 409 when not yet completed.
 */
export function getCaptureAnalysis(
  captureId: string,
  displayFilter?: string,
): Promise<PacketFindings> {
  const qs = new URLSearchParams();
  if (displayFilter !== undefined) qs.set("display_filter", displayFilter);
  const query = qs.toString();
  return apiFetch<PacketFindings>(
    `/agents/captures/${captureId}/analysis${query ? `?${query}` : ""}`,
  );
}
