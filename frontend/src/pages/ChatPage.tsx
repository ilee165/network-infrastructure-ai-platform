/**
 * Chat: the AI network-engineer console.
 *
 * Flow (M3-15 contract):
 *  1. `POST /api/v1/agents` starts a session and drives the supervisor to
 *     completion, returning the persisted session id.
 *  2. A WebSocket to `/agents/{id}/stream` replays the recorded reasoning steps
 *     in order, then a terminal `end` frame carrying the synthesized answer.
 *
 * Every answer carries its reasoning trace inline — plan / tool_call /
 * observation / conclusion steps, the tools each invoked, and evidence
 * references — so "explain all AI decisions" holds for the operator reading it.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  openSessionStream,
  startSession,
  type AgentStreamEnd,
  type AgentTraceStep,
} from "../api/agents";
import { ApiError } from "../api/client";
import { PageHeader } from "../components/PageHeader";

// ── Step presentation ─────────────────────────────────────────────────────────

/** Human label + accent class per reasoning-step kind. */
const STEP_META: Record<string, { label: string; className: string }> = {
  plan: { label: "Plan", className: "border-accent/40 bg-accent/10 text-accent" },
  tool_call: {
    label: "Tool call",
    className: "border-status-warn/40 bg-status-warn/10 text-status-warn",
  },
  observation: {
    label: "Observation",
    className: "border-carbon-600 bg-carbon-800 text-zinc-300",
  },
  conclusion: {
    label: "Conclusion",
    className: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  },
};

function stepMeta(kind: string): { label: string; className: string } {
  return STEP_META[kind] ?? { label: kind, className: "border-carbon-600 bg-carbon-800 text-zinc-400" };
}

// ── Reasoning-trace viewer ────────────────────────────────────────────────────

function TraceStepRow({ step }: { step: AgentTraceStep }) {
  const meta = stepMeta(step.kind);
  return (
    <li data-testid="trace-step" className="flex flex-col gap-1 border-l-2 border-carbon-700 pl-3">
      <div className="flex flex-wrap items-center gap-2">
        <span
          data-testid={`step-kind-${step.kind}`}
          className="inline-flex items-center rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
        >
          <span className={`rounded px-1 ${meta.className}`}>{meta.label}</span>
        </span>
        {step.tool_name ? (
          <code className="rounded bg-carbon-900 px-1.5 py-0.5 font-mono text-[11px] text-zinc-200">
            {step.tool_name}
          </code>
        ) : null}
        <time className="font-mono text-[10px] text-zinc-600">
          {new Date(step.occurred_at).toLocaleTimeString()}
        </time>
      </div>
      <p className="text-xs text-zinc-200">{step.summary}</p>
      {step.detail ? (
        <p className="font-mono text-[11px] text-zinc-500">{step.detail}</p>
      ) : null}
      {step.evidence.length > 0 ? (
        <ul className="flex flex-wrap gap-1.5">
          {step.evidence.map((ev, i) => (
            <li
              key={`${ev.reference}-${i}`}
              data-testid="evidence-ref"
              title={ev.description ?? undefined}
              className="inline-flex items-center gap-1 rounded border border-carbon-600 bg-carbon-900 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300"
            >
              <span className="text-zinc-500">{ev.kind}</span>
              <span className="text-zinc-200">{ev.reference}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function TraceViewer({ steps }: { steps: AgentTraceStep[] }) {
  if (steps.length === 0) {
    return null;
  }
  return (
    <details open className="panel mt-2 px-3 py-2">
      <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-widest text-zinc-500">
        Reasoning trace · {steps.length} step{steps.length !== 1 ? "s" : ""}
      </summary>
      <ol className="mt-2 flex flex-col gap-3">
        {steps.map((step, i) => (
          <TraceStepRow key={`${step.occurred_at}-${i}`} step={step} />
        ))}
      </ol>
    </details>
  );
}

// ── Transcript ────────────────────────────────────────────────────────────────

interface UserTurn {
  role: "user";
  text: string;
}

interface AgentTurn {
  role: "agent";
  steps: AgentTraceStep[];
  answer: string;
  streaming: boolean;
}

type Turn = UserTurn | AgentTurn;

function UserBubble({ text }: { text: string }) {
  return (
    <div className="flex justify-end">
      <p className="max-w-xl rounded-lg bg-accent/10 px-3 py-2 text-xs text-zinc-100">{text}</p>
    </div>
  );
}

function AgentBubble({ turn }: { turn: AgentTurn }) {
  return (
    <div className="flex flex-col gap-1">
      {turn.streaming && turn.answer === "" ? (
        <p role="status" className="text-xs text-zinc-500">
          Agent is reasoning…
        </p>
      ) : null}
      {turn.answer ? (
        <p data-testid="agent-answer" className="max-w-xl text-xs leading-relaxed text-zinc-100">
          {turn.answer}
        </p>
      ) : null}
      <TraceViewer steps={turn.steps} />
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function ChatPage() {
  const [intent, setIntent] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  // Close any open socket on unmount so a streaming run never leaks.
  useEffect(() => {
    return () => socketRef.current?.close();
  }, []);

  const appendStep = useCallback((step: AgentTraceStep) => {
    setTurns((prev) => {
      const next = [...prev];
      const last = next[next.length - 1];
      if (last && last.role === "agent") {
        next[next.length - 1] = { ...last, steps: [...last.steps, step] };
      }
      return next;
    });
  }, []);

  const finishStream = useCallback((end: AgentStreamEnd) => {
    setTurns((prev) => {
      const next = [...prev];
      const last = next[next.length - 1];
      if (last && last.role === "agent") {
        next[next.length - 1] = { ...last, answer: end.answer, streaming: false };
      }
      return next;
    });
    setBusy(false);
    socketRef.current?.close();
    socketRef.current = null;
  }, []);

  const failStream = useCallback((message: string) => {
    setError(message);
    setBusy(false);
    setTurns((prev) => {
      const next = [...prev];
      const last = next[next.length - 1];
      if (last && last.role === "agent") {
        next[next.length - 1] = { ...last, streaming: false };
      }
      return next;
    });
    socketRef.current?.close();
    socketRef.current = null;
  }, []);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = intent.trim();
    if (trimmed === "" || busy) {
      return;
    }
    setError(null);
    setBusy(true);
    setIntent("");
    setTurns((prev) => [
      ...prev,
      { role: "user", text: trimmed },
      { role: "agent", steps: [], answer: "", streaming: true },
    ]);

    try {
      const response = await startSession({ intent: trimmed });
      socketRef.current = await openSessionStream(response.session.id, {
        onStep: appendStep,
        onEnd: finishStream,
        onError: failStream,
      });
    } catch (err) {
      const message =
        err instanceof ApiError ? err.problem.detail : "Failed to start the agent session.";
      failStream(message);
    }
  }

  return (
    <div className="flex h-full flex-col gap-6">
      <PageHeader
        title="Chat"
        description="Ask the AI network engineer; every answer is grounded in collected data and carries a reasoning trace."
      />

      <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
        {turns.length === 0 ? (
          <div
            data-testid="chat-empty-state"
            className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
          >
            <p className="text-sm font-medium text-zinc-200">Ask a question to start</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              The Master Architect supervisor routes your intent to a read-only specialist agent and
              streams back its reasoning. Try: “Why is BGP peer 10.0.0.2 down on core-sw-01?”
            </p>
          </div>
        ) : null}

        {turns.map((turn, i) =>
          turn.role === "user" ? (
            <UserBubble key={i} text={turn.text} />
          ) : (
            <AgentBubble key={i} turn={turn} />
          ),
        )}
      </div>

      {error ? (
        <div
          role="alert"
          className="panel border-status-error/40 px-4 py-2 text-xs text-status-error"
        >
          {error}
        </div>
      ) : null}

      <form aria-label="Chat composer" className="flex gap-2" onSubmit={handleSubmit}>
        <input
          type="text"
          aria-label="Chat message"
          className="input flex-1"
          placeholder="Ask about routing, BGP, OSPF, or an ACL…"
          value={intent}
          onChange={(e) => setIntent(e.target.value)}
          disabled={busy}
        />
        <button type="submit" className="btn" disabled={busy || intent.trim() === ""}>
          {busy ? "Working…" : "Send"}
        </button>
      </form>
    </div>
  );
}
