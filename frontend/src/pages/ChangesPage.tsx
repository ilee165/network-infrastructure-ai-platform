/**
 * Changes: the ChangeRequest approval queue — the human gate of D11.
 *
 * Populated in M5: full lifecycle (draft → pending_approval → approved →
 * executing → completed | failed → rolled_back) with four-eyes approval.
 * Until M5, all write paths are hard-rejected backend-side by design.
 */

import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function ChangesPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Changes"
        description="ChangeRequest approval queue — every state-changing action requires human approval."
      />
      <EmptyState
        title="No change requests"
        description="The full ChangeRequest lifecycle (draft → pending approval → approved → executing → completed) and the four-eyes approval UI ship with the change workflow. Until then, every write path is hard-rejected by design — agents are read-only by construction."
        milestone="M5"
      />
    </div>
  );
}
