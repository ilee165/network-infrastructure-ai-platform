/**
 * Audit: agent tool-action view over the reasoning trace.
 *
 * Every tool an agent invokes is a recorded, auditable action ("audit
 * everything", "explain all AI decisions"). This view loads one agent session
 * by id (`GET /api/v1/agents/{id}`) and lists its `tool_call` reasoning steps —
 * the agent's tool actions — each linked to the evidence it produced.
 *
 * The append-only `audit_log` table itself ships from M0; a filterable browser
 * over the full log (by actor/action/target) rides a dedicated `/audit` router
 * in a later milestone — the brief fixes ten v1 routers and no audit-read
 * endpoint exists yet, so this view sources agent actions from the session trace
 * the M3-15 API already exposes.
 */

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getSession, type AgentTraceStep } from "../api/agents";
import { PageHeader } from "../components/PageHeader";

// ── Tool-audit row ────────────────────────────────────────────────────────────

interface ToolEvent {
  step: AgentTraceStep;
  agentName: string;
}

function ToolEventRow({ event }: { event: ToolEvent }) {
  const { step, agentName } = event;
  return (
    <tr data-testid="tool-audit-event" className="border-b border-carbon-800 last:border-0">
      <td className="px-4 py-2 font-mono text-[11px] text-zinc-500">
        {new Date(step.occurred_at).toLocaleTimeString()}
      </td>
      <td className="px-4 py-2 text-zinc-300">{agentName}</td>
      <td className="px-4 py-2">
        <code className="rounded bg-carbon-900 px-1.5 py-0.5 font-mono text-[11px] text-zinc-200">
          {step.tool_name ?? "—"}
        </code>
      </td>
      <td className="px-4 py-2 text-xs text-zinc-300">{step.summary}</td>
      <td className="px-4 py-2 text-xs text-zinc-500">
        {step.evidence.length > 0
          ? step.evidence.map((ev) => ev.reference).join(", ")
          : "—"}
      </td>
    </tr>
  );
}

// ── Results ───────────────────────────────────────────────────────────────────

function ToolAuditResults({ sessionId }: { sessionId: string }) {
  const { data, error, isPending } = useQuery({
    queryKey: ["agent-session", sessionId],
    queryFn: () => getSession(sessionId),
  });

  if (isPending) {
    return (
      <p role="status" className="text-xs text-zinc-500">
        Loading agent actions…
      </p>
    );
  }
  if (error) {
    return (
      <div role="alert" className="panel border-status-error/40 px-4 py-3 text-xs text-status-error">
        Session load failed: {error.message}
      </div>
    );
  }

  const events: ToolEvent[] = data.traces.flatMap((trace) =>
    trace.steps
      .filter((step) => step.kind === "tool_call")
      .map((step) => ({ step, agentName: trace.agent_name })),
  );

  if (events.length === 0) {
    return (
      <div
        data-testid="audit-empty-state"
        className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-12 text-center"
      >
        <p className="text-sm font-medium text-zinc-200">No tool actions recorded</p>
        <p className="max-w-md text-xs leading-relaxed text-zinc-500">
          This session answered without invoking any tool (read-only reasoning), so there are no
          tool-audit events to show.
        </p>
      </div>
    );
  }

  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Time</th>
            <th className="px-4 py-2 font-medium">Agent</th>
            <th className="px-4 py-2 font-medium">Tool</th>
            <th className="px-4 py-2 font-medium">Action</th>
            <th className="px-4 py-2 font-medium">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => (
            <ToolEventRow key={`${event.step.occurred_at}-${i}`} event={event} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function AuditPage() {
  const [draft, setDraft] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = draft.trim();
    if (trimmed !== "") {
      setSessionId(trimmed);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Audit"
        description="Append-only audit log: every actor, action, and AI decision, linked to reasoning traces."
      />

      <form onSubmit={handleSubmit} className="panel flex flex-wrap items-end gap-3 p-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="audit-session-id" className="text-[11px] text-zinc-500">
            Agent session ID
          </label>
          <input
            id="audit-session-id"
            type="text"
            aria-label="Session ID"
            placeholder="55555555-5555-5555-5555-555555555555"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            className="input w-96"
          />
        </div>
        <button type="submit" className="btn" disabled={draft.trim() === ""}>
          Load actions
        </button>
      </form>

      {sessionId ? (
        <section aria-label="Agent tool actions" className="flex flex-col gap-3">
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Agent tool actions
          </h3>
          <ToolAuditResults sessionId={sessionId} />
        </section>
      ) : (
        <p className="text-xs text-zinc-500">
          Enter an agent session ID to review the tool actions the agent took during that run.
        </p>
      )}
    </div>
  );
}
