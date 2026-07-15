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
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
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

  it("reports a stream-open failure and leaves streaming state recoverable", async () => {
    const onError = vi.fn();
    openSessionStream.mockRejectedValueOnce(new Error("socket construction failed"));
    const view = renderHookWithQueryClient(() => useAgentStream({ onError }));

    await start(view.result);

    await waitFor(() => {
      expect(view.result.current.error).toBe("Failed to open the agent session stream.");
    });
    expect(view.result.current.streaming).toBe(false);
    expect(onError).toHaveBeenCalledWith("Failed to open the agent session stream.");
  });

  it("reports only the first failure when the stream opener reports and then rejects", async () => {
    const lateSocket = deferred<WebSocket>();
    const onError = vi.fn();
    openSessionStream.mockImplementationOnce((_id: string, next: StreamHandlers) => {
      next.onError("Failed to obtain a stream ticket.");
      return lateSocket.promise;
    });
    const view = renderHookWithQueryClient(() => useAgentStream({ onError }));

    await start(view.result);
    expect(onError).toHaveBeenCalledOnce();

    await act(async () => lateSocket.reject(new Error("fallback socket construction failed")));

    expect(view.result.current.error).toBe("Failed to obtain a stream ticket.");
    expect(onError).toHaveBeenCalledOnce();
  });

  it("ignores a stream-open rejection that arrives after unmount", async () => {
    const lateSocket = deferred<WebSocket>();
    const onError = vi.fn();
    openSessionStream.mockReturnValueOnce(lateSocket.promise);
    const view = renderHookWithQueryClient(() => useAgentStream({ onError }));

    await start(view.result);
    view.unmount();
    await act(async () => lateSocket.reject(new Error("late stream failure")));

    expect(onError).not.toHaveBeenCalled();
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
