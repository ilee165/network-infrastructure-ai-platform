/**
 * Audit: read-only browser over the append-only audit log.
 *
 * The audit_log table itself ships with the M0 backend; the read-only audit
 * browser with reasoning-trace links lands in M3 alongside the agent
 * framework ("audit everything", "explain all AI decisions").
 */

import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function AuditPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Audit"
        description="Append-only audit log: every actor, action, and AI decision, linked to reasoning traces."
      />
      <EmptyState
        title="Audit browser not wired yet"
        description="The append-only audit_log table exists from M0; this read-only browser — filterable by actor, action, and target, with links to agent reasoning traces — arrives with the agent framework."
        milestone="M3"
      />
    </div>
  );
}
