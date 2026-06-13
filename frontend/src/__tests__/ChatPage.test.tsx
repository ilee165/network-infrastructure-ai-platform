/**
 * ChatPage tests: streaming console + reasoning-trace viewer.
 *
 * The REST `POST /agents` start is mocked via global `fetch`; the live trace
 * stream is mocked with a hand-rolled WebSocket double (no real socket, no
 * network). Covers: streamed steps render in order, the trace viewer shows
 * ordered steps + tool calls + evidence links, the final answer renders, and
 * stream/REST error states surface.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StartSessionResponse } from "../api/agents";
import { ChatPage } from "../pages/ChatPage";

// ── WebSocket double ──────────────────────────────────────────────────────────

type Listener = (event: { data: string }) => void;

interface MockCloseEvent {
  wasClean: boolean;
  code: number;
}

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly url: string;
  readyState = MockWebSocket.CONNECTING;
  onmessage: Listener | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onopen: ((event: unknown) => void) | null = null;
  onclose: ((event: MockCloseEvent) => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  /** Test helper: deliver one JSON frame as if the server sent it. */
  emit(frame: unknown): void {
    this.readyState = MockWebSocket.OPEN;
    this.onmessage?.({ data: JSON.stringify(frame) });
  }

  /** Test helper: deliver a raw (possibly malformed) frame body. */
  emitRaw(data: string): void {
    this.onmessage?.({ data });
  }

  /** Test helper: trigger the socket error path. */
  fail(): void {
    this.onerror?.({});
  }

  /** Test helper: trigger an abnormal close (e.g. network drop). */
  closeAbnormally(code = 1006): void {
    this.onclose?.({ wasClean: false, code });
  }

  close(): void {
    this.closed = true;
    this.readyState = MockWebSocket.CLOSED;
  }
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const START_RESPONSE: StartSessionResponse = {
  session: {
    id: "55555555-5555-5555-5555-555555555555",
    user_id: "99999999-9999-9999-9999-999999999999",
    invoking_role: "viewer",
    intent: "Why is BGP peer 10.0.0.2 down on core-sw-01?",
    status: "running",
    started_at: "2024-01-15T12:00:00Z",
    completed_at: null,
  },
  answer: "",
  traces: [],
};

const PLAN_STEP = {
  kind: "plan",
  summary: "Route to the Troubleshooting Agent for BGP analysis.",
  detail: null,
  tool_name: null,
  evidence: [],
  occurred_at: "2024-01-15T12:00:01Z",
};

const TOOL_STEP = {
  kind: "tool_call",
  summary: "Inspect BGP peer state on core-sw-01.",
  detail: "analyze_bgp(device=core-sw-01)",
  tool_name: "analyze_bgp",
  evidence: [],
  occurred_at: "2024-01-15T12:00:02Z",
};

const OBSERVATION_STEP = {
  kind: "observation",
  summary: "Peer 10.0.0.2 is in Active state; no established session.",
  detail: null,
  tool_name: null,
  evidence: [
    {
      kind: "device",
      reference: "core-sw-01:bgp",
      description: "BGP summary",
    },
  ],
  occurred_at: "2024-01-15T12:00:03Z",
};

const CONCLUSION_STEP = {
  kind: "conclusion",
  summary: "BGP peer 10.0.0.2 is down because the interface to it is admin-down.",
  detail: null,
  tool_name: null,
  evidence: [],
  occurred_at: "2024-01-15T12:00:04Z",
};

const END_FRAME = {
  event: "end",
  status: "succeeded",
  answer: "BGP peer 10.0.0.2 is down because the interface to it is admin-down.",
};

// ── Harness ───────────────────────────────────────────────────────────────────

function mockStartFetch(response: StartSessionResponse = START_RESPONSE) {
  return vi.fn((url: string, init?: RequestInit): Promise<Response> => {
    if ((init as RequestInit | undefined)?.method === "POST") {
      // stream-ticket endpoint returns a one-time opaque ticket.
      if (String(url).includes("stream-ticket")) {
        return Promise.resolve(
          new Response(JSON.stringify({ ticket: "test-stream-ticket" }), {
            status: 201,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      // POST /agents — start a session.
      return Promise.resolve(
        new Response(JSON.stringify(response), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    return Promise.resolve(new Response("{}", { status: 200 }));
  });
}

function renderPage(): void {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ChatPage />
    </QueryClientProvider>,
  );
}

function latestSocket(): MockWebSocket {
  const socket = MockWebSocket.instances.at(-1);
  if (!socket) throw new Error("no WebSocket was opened");
  return socket;
}

async function startConversation(intent = "Why is BGP peer down?"): Promise<void> {
  fireEvent.change(screen.getByLabelText("Chat message"), { target: { value: intent } });
  fireEvent.click(screen.getByRole("button", { name: /send/i }));
  await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
}

beforeEach(() => {
  MockWebSocket.instances = [];
  vi.stubGlobal("WebSocket", MockWebSocket);
  vi.stubGlobal("fetch", mockStartFetch());
  globalThis.localStorage.setItem("netops.access_token", "test-jwt");
});

afterEach(() => {
  vi.unstubAllGlobals();
  globalThis.localStorage.clear();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("ChatPage — session start", () => {
  it("posts the intent to /api/v1/agents and opens a token-authenticated stream", async () => {
    const fetchMock = mockStartFetch();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    await startConversation("Why is BGP peer 10.0.0.2 down?");

    const postCall = fetchMock.mock.calls.find(
      ([, init]) => (init as RequestInit | undefined)?.method === "POST",
    );
    expect(postCall?.[0]).toContain("/api/v1/agents");
    const body = JSON.parse((postCall![1] as RequestInit).body as string) as { intent: string };
    expect(body.intent).toBe("Why is BGP peer 10.0.0.2 down?");

    const socket = latestSocket();
    expect(socket.url).toContain(`/api/v1/agents/${START_RESPONSE.session.id}/stream`);
    expect(socket.url).toContain("ticket=test-stream-ticket");
    expect(socket.url).not.toContain("token=");
  });

  it("echoes the user's message into the transcript", async () => {
    renderPage();
    await startConversation("Why is BGP peer 10.0.0.2 down?");
    expect(screen.getByText("Why is BGP peer 10.0.0.2 down?")).toBeInTheDocument();
  });
});

describe("ChatPage — streaming + trace viewer", () => {
  it("renders streamed reasoning steps in arrival order", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => {
      socket.emit(PLAN_STEP);
      socket.emit(TOOL_STEP);
      socket.emit(OBSERVATION_STEP);
    });

    const steps = await screen.findAllByTestId("trace-step");
    expect(steps).toHaveLength(3);
    expect(steps[0]).toHaveTextContent(PLAN_STEP.summary);
    expect(steps[1]).toHaveTextContent(TOOL_STEP.summary);
    expect(steps[2]).toHaveTextContent(OBSERVATION_STEP.summary);
  });

  it("labels each step with its kind and surfaces tool-call names", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => {
      socket.emit(PLAN_STEP);
      socket.emit(TOOL_STEP);
    });

    expect(await screen.findByTestId("step-kind-plan")).toBeInTheDocument();
    expect(screen.getByTestId("step-kind-tool_call")).toBeInTheDocument();
    expect(screen.getByText("analyze_bgp")).toBeInTheDocument();
  });

  it("renders evidence references attached to a step", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => socket.emit(OBSERVATION_STEP));

    const evidence = await screen.findByTestId("evidence-ref");
    expect(evidence).toHaveTextContent("core-sw-01:bgp");
  });

  it("renders the final synthesized answer on the end frame", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => {
      socket.emit(CONCLUSION_STEP);
      socket.emit(END_FRAME);
    });

    expect(await screen.findByTestId("agent-answer")).toHaveTextContent(
      "interface to it is admin-down",
    );
  });

  it("closes the socket once the end frame arrives", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => socket.emit(END_FRAME));

    await waitFor(() => expect(socket.closed).toBe(true));
  });
});

describe("ChatPage — error states", () => {
  it("shows an error when the session fails to start", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) => {
        if ((init as RequestInit | undefined)?.method === "POST") {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                type: "about:blank",
                title: "Bad Request",
                status: 400,
                detail: "intent must not be empty",
              }),
              { status: 400, headers: { "Content-Type": "application/problem+json" } },
            ),
          );
        }
        return Promise.resolve(new Response("{}", { status: 200 }));
      }),
    );
    renderPage();

    fireEvent.change(screen.getByLabelText("Chat message"), {
      target: { value: "hello" },
    });
    fireEvent.click(screen.getByRole("button", { name: /send/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/intent must not be empty/);
  });

  it("surfaces a stream error when the socket fails", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => socket.fail());

    expect(await screen.findByRole("alert")).toHaveTextContent(/stream/i);
  });

  it("surfaces an error on a malformed stream frame", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => socket.emitRaw("not-json"));

    expect(await screen.findByRole("alert")).toHaveTextContent(/malformed/i);
  });

  it("surfaces an error when the socket closes abnormally without an end frame", async () => {
    renderPage();
    await startConversation();
    const socket = latestSocket();

    act(() => socket.closeAbnormally(1006));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/stream/i);
    // Chat input must be re-enabled (busy cleared) so the user can retry.
    expect(screen.getByLabelText("Chat message")).not.toBeDisabled();
  });
});
