/**
 * Chat: the agent console.
 *
 * Populated in M3: LangGraph supervisor + read-only Troubleshooting Agent,
 * WebSocket token streaming, and a reasoning-trace viewer next to every
 * answer ("explain all AI decisions"). The composer ships disabled — no fake
 * conversations.
 */

import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function ChatPage() {
  return (
    <div className="flex h-full flex-col gap-6">
      <PageHeader
        title="Chat"
        description="Ask the AI network engineer; every answer is grounded in collected data and carries a reasoning trace."
      />
      <div className="flex flex-1 flex-col justify-center">
        <EmptyState
          title="Agent chat is not wired yet"
          description="The LangGraph supervisor, the read-only Troubleshooting Agent, and streaming chat with a persisted reasoning-trace viewer arrive with the agent framework."
          milestone="M3"
        />
      </div>
      <form
        aria-label="Chat composer"
        className="flex gap-2"
        onSubmit={(event) => event.preventDefault()}
      >
        <input
          type="text"
          aria-label="Chat message"
          className="input flex-1"
          placeholder="Agent chat is enabled in M3"
          disabled
        />
        <button type="submit" className="btn" disabled>
          Send
        </button>
      </form>
    </div>
  );
}
