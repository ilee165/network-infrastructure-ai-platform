import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useReducer, useRef, useTransition } from "react";
import { openSessionStream, startSession, type AgentStreamEnd, type AgentTraceStep } from "../api/agents";
import { ApiError } from "../api/client";
import { queryKeys } from "./queryKeys";

interface StreamState { steps: AgentTraceStep[]; answer: string; error: string | null; streaming: boolean; revision: number }
type Action = { type: "start" } | { type: "steps"; steps: AgentTraceStep[] } | { type: "end"; end: AgentStreamEnd } | { type: "error"; message: string };
const initialState: StreamState = { steps: [], answer: "", error: null, streaming: false, revision: 0 };
function reducer(state: StreamState, action: Action): StreamState {
  if (action.type === "start") return { ...initialState, streaming: true, revision: state.revision + 1 };
  if (action.type === "steps") return { ...state, steps: [...state.steps, ...action.steps], revision: state.revision + 1 };
  if (action.type === "end") return { ...state, answer: action.end.answer, streaming: false, revision: state.revision + 1 };
  return { ...state, error: action.message, streaming: false, revision: state.revision + 1 };
}

export function useAgentStream() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [, startTransition] = useTransition();
  const client = useQueryClient();
  const socketRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(true);
  const sessionRef = useRef<string | null>(null);
  const pendingStepsRef = useRef<AgentTraceStep[]>([]);
  const rafRef = useRef<number | null>(null);

  const flush = useCallback(() => {
    rafRef.current = null;
    const steps = pendingStepsRef.current;
    pendingStepsRef.current = [];
    if (steps.length) startTransition(() => dispatch({ type: "steps", steps }));
  }, []);
  const append = useCallback((step: AgentTraceStep) => {
    pendingStepsRef.current.push(step);
    rafRef.current ??= requestAnimationFrame(flush);
  }, [flush]);
  const invalidatePersisted = useCallback(() => {
    const id = sessionRef.current;
    if (!id) return;
    void client.invalidateQueries({ queryKey: queryKeys.chat.session(id) });
    void client.invalidateQueries({ queryKey: queryKeys.chat.history(id) });
    void client.invalidateQueries({ queryKey: queryKeys.chat.trace(id) });
  }, [client]);
  const close = useCallback(() => { socketRef.current?.close(); socketRef.current = null; }, []);

  const mutation = useMutation({
    mutationFn: startSession,
    onMutate: () => dispatch({ type: "start" }),
    onSuccess: async (response) => {
      sessionRef.current = response.session.id;
      const socket = await openSessionStream(response.session.id, {
        onStep: append,
        onEnd: (end) => { dispatch({ type: "end", end }); invalidatePersisted(); close(); },
        onError: (message) => { dispatch({ type: "error", message }); invalidatePersisted(); close(); },
      });
      if (!mountedRef.current) socket.close(); else socketRef.current = socket;
    },
    onError: (error) => dispatch({ type: "error", message: error instanceof ApiError ? error.problem.detail : "Failed to start the agent session." }),
  });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      close();
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      pendingStepsRef.current = [];
    };
  }, [close]);

  return { ...state, start: (intent: string) => mutation.mutate({ intent }), sessionId: sessionRef.current };
}
