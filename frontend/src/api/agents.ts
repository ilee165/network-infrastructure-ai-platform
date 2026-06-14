/**
 * Typed client for the agent-session endpoints (M3-15 / M3-16).
 *
 * Mirrors the backend contracts in ``app/schemas/agents_api.py`` and the routes
 * in ``app/api/v1/agents.py``:
 *  - ``POST /api/v1/agents``            — start a session, drive it to completion.
 *  - ``GET  /api/v1/agents/{id}``       — reload a persisted session + its traces.
 *  - ``WS   /api/v1/agents/{id}/stream``— stream reasoning steps, then a terminal
 *    ``end`` frame. The socket authenticates with a short-lived single-use ticket
 *    obtained via ``POST /agents/{id}/stream-ticket`` (the JWT is exchanged
 *    server-side and never embedded in the URL), so a peer who could not read
 *    the trace over REST never receives it.
 */

import { API_BASE, apiFetch } from "./client";

// ── Enums (match backend AgentSessionStatus / TraceStepKind) ──────────────────

/** Lifecycle of one agent session row. */
export type AgentSessionStatus = "running" | "succeeded" | "failed";

/**
 * Kind of one reasoning step. Mirrors ``traces.TraceStepKind``; rendered as an
 * ordered timeline in the trace viewer. Unknown future kinds degrade to a plain
 * label rather than breaking the view.
 */
export type TraceStepKind = "plan" | "tool_call" | "observation" | "conclusion";

// ── Response shapes ───────────────────────────────────────────────────────────

/** A pointer to evidence supporting a reasoning step (mirrors ``EvidenceRef``). */
export interface AgentEvidence {
  kind: string;
  reference: string;
  description: string | null;
}

/** One ordered reasoning step (mirrors ``AgentTraceStepRead``). */
export interface AgentTraceStep {
  kind: TraceStepKind | string;
  summary: string;
  detail: string | null;
  tool_name: string | null;
  evidence: AgentEvidence[];
  occurred_at: string;
}

/** The full reasoning record of one agent run (mirrors ``AgentTraceRead``). */
export interface AgentTrace {
  trace_id: string;
  agent_name: string;
  started_at: string;
  completed_at: string | null;
  steps: AgentTraceStep[];
}

/** One agent session row (mirrors ``AgentSessionRead``). */
export interface AgentSession {
  id: string;
  user_id: string;
  invoking_role: string;
  intent: string;
  status: AgentSessionStatus;
  started_at: string;
  completed_at: string | null;
}

/** Result of ``POST /agents`` and ``GET /agents/{id}`` (mirrors ``StartSessionResponse``). */
export interface StartSessionResponse {
  session: AgentSession;
  answer: string;
  traces: AgentTrace[];
}

/** Body of ``POST /agents``. */
export interface StartSessionRequest {
  intent: string;
}

/** Terminal WebSocket frame (mirrors ``AgentStreamEnd``). */
export interface AgentStreamEnd {
  event: "end";
  status: AgentSessionStatus;
  answer: string;
}

/**
 * One WebSocket frame: either a reasoning step or the terminal ``end`` marker.
 * The ``end`` frame is discriminated by its literal ``event`` field; every other
 * frame is an {@link AgentTraceStep}.
 */
export type AgentStreamFrame = AgentTraceStep | AgentStreamEnd;

/** Narrow a stream frame to the terminal ``end`` marker. */
export function isStreamEnd(frame: AgentStreamFrame): frame is AgentStreamEnd {
  return (frame as AgentStreamEnd).event === "end";
}

// ── API functions ─────────────────────────────────────────────────────────────

/** ``POST /api/v1/agents`` — start a session and drive the supervisor to completion. */
export function startSession(body: StartSessionRequest): Promise<StartSessionResponse> {
  return apiFetch<StartSessionResponse>("/agents", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** ``GET /api/v1/agents/{id}`` — reload one persisted session and its full traces. */
export function getSession(sessionId: string): Promise<StartSessionResponse> {
  return apiFetch<StartSessionResponse>(`/agents/${sessionId}`);
}

// ── WebSocket streaming ───────────────────────────────────────────────────────

/**
 * Exchange the caller's JWT for a short-lived, single-use opaque stream ticket
 * from the backend.
 *
 * The access token is attached by {@link apiFetch} as an in-memory
 * `Authorization: Bearer` header (Auth & Account UI, F1) — the JWT lives only
 * in the auth store, never in localStorage. The ticket is good for 30 seconds
 * and is consumed on first use, so the bearer JWT never appears in a WebSocket
 * URL (and therefore never in server access logs, browser history, or Referer
 * headers).
 */
export function requestStreamTicket(sessionId: string): Promise<string> {
  return apiFetch<{ ticket: string }>(`/agents/${sessionId}/stream-ticket`, {
    method: "POST",
  }).then((r) => r.ticket);
}

/**
 * Build the absolute ``ws[s]://`` URL for a session's trace stream.
 *
 * Same-origin as the SPA (dev proxies ``/api`` to the backend; prod uses nginx),
 * with the scheme upgraded to ``ws``/``wss`` from the page's ``http``/``https``.
 * An opaque one-time ticket is appended as the ``ticket`` query parameter;
 * the JWT itself never appears in a URL.
 */
export function streamUrl(sessionId: string, ticket: string): string {
  const { protocol, host } = globalThis.location;
  const wsProtocol = protocol === "https:" ? "wss:" : "ws:";
  const base = `${wsProtocol}//${host}${API_BASE}/agents/${sessionId}/stream`;
  return `${base}?ticket=${encodeURIComponent(ticket)}`;
}

/** Callbacks for {@link openSessionStream}. */
export interface StreamHandlers {
  /** A reasoning step arrived. */
  onStep: (step: AgentTraceStep) => void;
  /** The terminal ``end`` frame arrived; the stream is complete. */
  onEnd: (end: AgentStreamEnd) => void;
  /** The socket errored or closed abnormally before an ``end`` frame. */
  onError: (message: string) => void;
}

/**
 * Open a trace stream for *sessionId* and dispatch each decoded frame.
 *
 * Obtains a short-lived one-time ticket from ``POST /agents/{id}/stream-ticket``
 * (authenticated via the normal Authorization header) and opens the WebSocket
 * with that ticket as a query parameter.  This ensures the bearer JWT never
 * appears in a URL.
 *
 * Returns a Promise that resolves to the underlying {@link WebSocket} so the
 * caller can close it on unmount.  Frames are validated defensively: a
 * malformed payload routes to ``onError`` rather than corrupting the trace view.
 */
export async function openSessionStream(
  sessionId: string,
  handlers: StreamHandlers,
): Promise<WebSocket> {
  let ticket: string;
  try {
    ticket = await requestStreamTicket(sessionId);
  } catch {
    handlers.onError("Failed to obtain a stream ticket.");
    // Return a dummy closed socket so callers always get a WebSocket back.
    const dummy = new WebSocket("ws://localhost");
    dummy.close();
    return dummy;
  }
  const socket = new WebSocket(streamUrl(sessionId, ticket));

  socket.onmessage = (event: MessageEvent) => {
    let frame: AgentStreamFrame;
    try {
      frame = JSON.parse(String(event.data)) as AgentStreamFrame;
    } catch {
      handlers.onError("Received a malformed stream frame.");
      return;
    }
    if (isStreamEnd(frame)) {
      handlers.onEnd(frame);
    } else {
      handlers.onStep(frame);
    }
  };

  socket.onerror = () => {
    handlers.onError("The trace stream connection failed.");
  };

  socket.onclose = (ev: CloseEvent) => {
    if (!ev.wasClean || ev.code !== 1000) {
      handlers.onError("The trace stream closed unexpectedly.");
    }
  };

  return socket;
}
