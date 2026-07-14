import { act, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHookWithQueryClient } from "../test/test-utils";
import type { AgentStreamEnd, AgentTraceStep, StartSessionResponse, StreamHandlers } from "../api/agents";
import { queryKeys } from "../hooks/queryKeys";
import { useAgentStream } from "../hooks/useAgentStream";

const { startSession, openSessionStream } = vi.hoisted(() => ({
  startSession: vi.fn(),
  openSessionStream: vi.fn(),
}));

vi.mock("../api/agents", async () => (await import("../test/test-utils")).mockAgentsApi(() => ({
  startSession,
  openSessionStream,
}))());

const SESSION_ID = "55555555-5555-5555-5555-555555555555";
const START_RESPONSE: StartSessionResponse = {
  session: {
    id: SESSION_ID,
    user_id: "99999999-9999-9999-9999-999999999999",
    invoking_role: "viewer",
    intent: "inspect bgp",
    status: "running",
    started_at: "2026-07-13T12:00:00Z",
    completed_at: null,
  },
  answer: "",
  traces: [],
};
const STEP: AgentTraceStep = {
  kind: "observation",
  summary: "peer is active",
  detail: null,
  tool_name: null,
  evidence: [],
  occurred_at: "2026-07-13T12:00:01Z",
};
const END: AgentStreamEnd = { event: "end", status: "succeeded", answer: "done" };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function start(result: { current: ReturnType<typeof useAgentStream> }) {
  act(() => result.current.start("inspect bgp"));
  await waitFor(() => expect(openSessionStream).toHaveBeenCalled());
}

describe("useAgentStream ownership", () => {
  let handlers: StreamHandlers;
  let socket: Pick<WebSocket, "close">;

  beforeEach(() => {
    vi.clearAllMocks();
    socket = { close: vi.fn() };
    startSession.mockResolvedValue(START_RESPONSE);
    openSessionStream.mockImplementation(async (_id: string, next: StreamHandlers) => {
      handlers = next;
      return socket as WebSocket;
    });
    vi.stubGlobal("requestAnimationFrame", vi.fn(() => 1));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("keeps a late socket owned after the StrictMode setup-cleanup-setup cycle", async () => {
    const lateSocket = deferred<WebSocket>();
    openSessionStream.mockImplementation((_id: string, next: StreamHandlers) => {
      handlers = next;
      return lateSocket.promise;
    });
    const view = renderHookWithQueryClient(() => useAgentStream(), {
      reactStrictMode: true,
    });

    await start(view.result);
    await act(async () => lateSocket.resolve(socket as WebSocket));

    expect(socket.close).not.toHaveBeenCalled();
    view.unmount();
    expect(socket.close).toHaveBeenCalledOnce();
  });

  it("batches multiple steps into one animation-frame update", async () => {
    const frames: FrameRequestCallback[] = [];
    vi.stubGlobal("requestAnimationFrame", vi.fn((callback: FrameRequestCallback) => {
      frames.push(callback);
      return frames.length;
    }));
    const view = renderHookWithQueryClient(() => useAgentStream());
    await start(view.result);

    act(() => { handlers.onStep(STEP); handlers.onStep({ ...STEP, summary: "peer recovered" }); });
    expect(view.result.current.steps).toEqual([]);
    expect(requestAnimationFrame).toHaveBeenCalledOnce();
    act(() => frames.shift()?.(0));
    expect(view.result.current.steps.map((step) => step.summary)).toEqual(["peer is active", "peer recovered"]);
  });

  it("projects each animation-frame batch through the consumer callback", async () => {
    const frames: FrameRequestCallback[] = [];
    const onSteps = vi.fn();
    vi.stubGlobal("requestAnimationFrame", vi.fn((callback: FrameRequestCallback) => {
      frames.push(callback);
      return frames.length;
    }));
    const view = renderHookWithQueryClient(() => useAgentStream({ onSteps }));
    await start(view.result);

    act(() => {
      handlers.onStep(STEP);
      handlers.onStep({ ...STEP, summary: "peer recovered" });
    });
    expect(onSteps).not.toHaveBeenCalled();

    act(() => frames.shift()?.(0));

    expect(onSteps).toHaveBeenCalledOnce();
    expect(onSteps).toHaveBeenCalledWith([
      STEP,
      { ...STEP, summary: "peer recovered" },
    ]);
  });

  it.each(["end", "error"] as const)("invalidates persisted session queries on terminal %s", async (terminal) => {
    const view = renderHookWithQueryClient(() => useAgentStream());
    const { queryClient } = view;
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    const setData = vi.spyOn(queryClient, "setQueryData");
    await start(view.result);

    act(() => terminal === "end" ? handlers.onEnd(END) : handlers.onError("stream failed"));

    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.chat.session(SESSION_ID) });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.chat.history(SESSION_ID) });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.chat.trace(SESSION_ID) });
    expect(setData).not.toHaveBeenCalled();
    expect(queryClient.getQueryCache().getAll()).toEqual([]);
    expect(socket.close).toHaveBeenCalledOnce();
  });

  it("closes a socket that resolves after unmount and cancels queued frames", async () => {
    const lateSocket = deferred<WebSocket>();
    openSessionStream.mockImplementation((_id: string, next: StreamHandlers) => {
      handlers = next;
      return lateSocket.promise;
    });
    const view = renderHookWithQueryClient(() => useAgentStream());
    await start(view.result);
    act(() => handlers.onStep(STEP));
    view.unmount();
    await act(async () => lateSocket.resolve(socket as WebSocket));

    expect(cancelAnimationFrame).toHaveBeenCalledWith(1);
    expect(socket.close).toHaveBeenCalledOnce();
  });
});
