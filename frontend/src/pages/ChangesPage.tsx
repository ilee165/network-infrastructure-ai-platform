/**
 * Changes: the ChangeRequest approval queue — the human change gate of D11.
 *
 * Left: the queue of ChangeRequests (newest first). Selecting a row opens the
 * detail panel on the right, which shows the change **intent preview** — the
 * change kind, lifecycle state, four-eyes posture, and the id-only ``target_refs``
 * (which devices / DDI records the change touches) — and lets an authorized
 * engineer **approve or reject with a comment**.
 *
 * Security:
 *  - The secret-bearing CR ``payload`` (the exact config diff / DDI body) is never
 *    sent over the read surface (ADR-0020 §4); the preview renders only the id-only
 *    ``target_refs`` and lifecycle metadata, already A9-redacted server-side.
 *  - The intent is rendered as TEXT (``JSON.stringify`` into a ``<pre>`` whose child
 *    is a React text node) — never through a ``dangerouslySetInnerHTML`` sink — so a
 *    hostile ref string cannot inject markup into the DOM.
 *  - Four-eyes is enforced server-side (the canonical guard, ADR-0020 §3); the UI
 *    additionally hides/disables **approve** on a CR the current user requested so a
 *    reviewer never sees a control the backend would reject. A server-side rejection
 *    (403 four-eyes / RBAC, 409 wrong state) is surfaced clearly to the user.
 *
 * Wired to ``api/changes.ts`` (T15 endpoints). Engineer+ surface (ADR-0020 §5).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  approveChangeRequest,
  listChangeRequests,
  rejectChangeRequest,
  type ChangeRequestKind,
  type ChangeRequestListResponse,
  type ChangeRequestRead,
  type ChangeRequestState,
} from "../api/changes";
import { ApiError } from "../api/client";
import { PageHeader } from "../components/PageHeader";
import { useAuthStore } from "../stores/auth";

// ── Constants / styling ───────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider";

const KIND_STYLES: Record<ChangeRequestKind, string> = {
  config: "border-accent/40 bg-accent/10 text-accent",
  ddi: "border-status-ok/40 bg-status-ok/10 text-status-ok",
};

const STATE_STYLES: Record<ChangeRequestState, string> = {
  draft: "border-carbon-600 bg-carbon-800 text-zinc-400",
  pending_approval: "border-status-warn/40 bg-status-warn/10 text-status-warn",
  approved: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  executing: "border-accent/40 bg-accent/10 text-accent",
  completed: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  failed: "border-status-error/40 bg-status-error/10 text-status-error",
  rolled_back: "border-status-error/40 bg-status-error/10 text-status-error",
};

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.problem.detail || err.problem.title;
  if (err instanceof Error) return err.message;
  return "Request failed";
}

// ── Badges ────────────────────────────────────────────────────────────────────

function KindBadge({ crId, kind }: { crId: string; kind: ChangeRequestKind }) {
  return (
    <span data-testid={`cr-kind-${crId}`} className={`${PILL_BASE} ${KIND_STYLES[kind]}`}>
      {kind}
    </span>
  );
}

function StateBadge({ crId, state }: { crId: string; state: ChangeRequestState }) {
  return (
    <span data-testid={`cr-state-${crId}`} className={`${PILL_BASE} ${STATE_STYLES[state]}`}>
      {state.replace(/_/g, " ")}
    </span>
  );
}

// ── Queue row ─────────────────────────────────────────────────────────────────

function CrRow({
  cr,
  selected,
  onView,
}: {
  cr: ChangeRequestRead;
  selected: boolean;
  onView: (cr: ChangeRequestRead) => void;
}) {
  return (
    <tr
      data-testid={`cr-row-${cr.id}`}
      className={`border-b border-carbon-800 last:border-0 ${
        selected ? "bg-carbon-800/60" : ""
      }`}
    >
      <td className="px-4 py-3 font-mono text-[11px] text-zinc-400">{cr.id.slice(0, 8)}</td>
      <td className="px-4 py-3">
        <KindBadge crId={cr.id} kind={cr.kind} />
      </td>
      <td className="px-4 py-3">
        <StateBadge crId={cr.id} state={cr.state} />
      </td>
      <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">
        {new Date(cr.created_at).toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <button
          type="button"
          data-testid={`cr-view-${cr.id}`}
          onClick={() => onView(cr)}
          className="rounded border border-carbon-600 px-2 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
        >
          Review
        </button>
      </td>
    </tr>
  );
}

// ── Detail / decision panel ───────────────────────────────────────────────────

function DetailPanel({
  cr,
  currentUserId,
  onClose,
  onDecided,
}: {
  cr: ChangeRequestRead;
  currentUserId: string | null;
  onClose: () => void;
  onDecided: () => void;
}) {
  const [comment, setComment] = useState("");
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // Four-eyes UI guard (defence in depth; the backend is canonical): a reviewer
  // may not approve a CR they themselves requested when four_eyes_required.
  const isOwnCr = currentUserId !== null && cr.requester_id === currentUserId;
  const approveBlocked = cr.four_eyes_required && isOwnCr;
  // Approve/reject only make sense while the CR is awaiting a decision.
  const decidable = cr.state === "pending_approval";

  const approveM = useMutation({
    mutationFn: () => approveChangeRequest(cr.id, { comment: comment.trim() || undefined }),
    onSuccess: () => {
      setDecisionError(null);
      onDecided();
    },
    onError: (err) => setDecisionError(errMessage(err)),
  });

  const rejectM = useMutation({
    mutationFn: () => rejectChangeRequest(cr.id, { comment: comment.trim() || undefined }),
    onSuccess: () => {
      setDecisionError(null);
      onDecided();
    },
    onError: (err) => setDecisionError(errMessage(err)),
  });

  const pending = approveM.isPending || rejectM.isPending;

  return (
    <div
      data-testid="cr-detail-panel"
      className="flex flex-col gap-4 rounded-md border border-carbon-700 bg-carbon-900 p-4"
    >
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-widest text-zinc-300">
          Change Request {cr.id.slice(0, 8)}
        </h3>
        <button
          type="button"
          data-testid="cr-panel-close"
          onClick={onClose}
          className="rounded border border-carbon-600 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
        >
          Close
        </button>
      </div>

      {/* Lifecycle metadata */}
      <div className="flex flex-wrap items-center gap-2">
        <KindBadge crId={cr.id} kind={cr.kind} />
        <StateBadge crId={cr.id} state={cr.state} />
        {cr.four_eyes_required && (
          <span className={`${PILL_BASE} border-carbon-600 bg-carbon-800 text-zinc-400`}>
            four-eyes
          </span>
        )}
      </div>

      {/* Intent preview — id-only target_refs rendered as escaped TEXT (no HTML
          injection sink). The secret-bearing payload is never on this surface. */}
      <div className="flex flex-col gap-1">
        <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">
          Change intent (affected references)
        </span>
        <pre
          data-testid="cr-intent-preview"
          aria-label="Change intent preview"
          className="overflow-x-auto rounded bg-carbon-950 p-4 font-mono text-[11px] leading-relaxed text-zinc-300"
        >
          {JSON.stringify(cr.target_refs ?? {}, null, 2)}
        </pre>
        <p className="font-mono text-[10px] text-zinc-600">
          Only the references this change touches are shown. The exact config /
          DNS body is withheld from the approval surface by design.
        </p>
      </div>

      {/* Reviewer comment + decision controls */}
      {decidable ? (
        <div className="flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">
              Reviewer comment (optional)
            </span>
            <textarea
              data-testid="cr-comment-input"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              maxLength={2048}
              className="w-full rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-xs text-zinc-200 focus:border-accent focus:outline-none"
              placeholder="Why are you approving or rejecting this change?"
            />
          </label>

          {approveBlocked && (
            <p
              data-testid="cr-four-eyes-note"
              role="note"
              className="font-mono text-[10px] leading-relaxed text-status-warn"
            >
              Four-eyes control: you requested this change, so you cannot approve
              it yourself. Another engineer must approve it. You may still reject
              (withdraw) it.
            </p>
          )}

          {decisionError !== null && (
            <div
              role="alert"
              data-testid="cr-decision-error"
              className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
            >
              Decision rejected: {decisionError}
            </div>
          )}

          <div className="flex items-center gap-2">
            {!approveBlocked && (
              <button
                type="button"
                data-testid="cr-approve-btn"
                disabled={pending}
                onClick={() => approveM.mutate()}
                className="rounded border border-status-ok/50 bg-status-ok/10 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-status-ok transition-colors hover:bg-status-ok/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Approve
              </button>
            )}
            <button
              type="button"
              data-testid="cr-reject-btn"
              disabled={pending}
              onClick={() => rejectM.mutate()}
              className="rounded border border-status-error/50 bg-status-error/10 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-status-error transition-colors hover:bg-status-error/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Reject
            </button>
          </div>
        </div>
      ) : (
        <p className="font-mono text-[10px] text-zinc-600">
          This change request is not awaiting approval — no decision can be made
          from this surface.
        </p>
      )}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function ChangesPage() {
  const currentUserId = useAuthStore((state) => state.user?.id ?? null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data, isPending, error } = useQuery<ChangeRequestListResponse>({
    queryKey: ["change-requests"],
    queryFn: () => listChangeRequests({ limit: 50 }),
  });

  const items = data?.items ?? [];
  const selected = items.find((cr) => cr.id === selectedId) ?? null;

  function handleDecided(): void {
    // A decision moved the CR out of pending_approval — refresh the queue and
    // collapse the panel.
    void queryClient.invalidateQueries({ queryKey: ["change-requests"] });
    setSelectedId(null);
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Changes"
        description="ChangeRequest approval queue — every state-changing action requires human approval. Review the change intent, then approve or reject with a comment."
      />

      {/* Loading */}
      {isPending && (
        <p role="status" className="text-xs text-zinc-500">
          Loading change requests…
        </p>
      )}

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
        >
          Change requests load failed: {error.message}
        </div>
      )}

      {/* Empty */}
      {!isPending && !error && items.length === 0 && (
        <div
          data-testid="cr-empty-state"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">No change requests</p>
          <p className="max-w-md text-xs leading-relaxed text-zinc-500">
            There are no pending change requests to review. When an agent drafts a
            config or DNS change, it appears here for human approval.
          </p>
        </div>
      )}

      {/* Queue + detail */}
      {!isPending && !error && items.length > 0 && (
        <div className="flex flex-col gap-4">
          <div className="panel overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-carbon-700 text-left text-zinc-500">
                  <th className="px-4 py-2 font-medium">ID</th>
                  <th className="px-4 py-2 font-medium">Kind</th>
                  <th className="px-4 py-2 font-medium">State</th>
                  <th className="px-4 py-2 font-medium">Created</th>
                  <th className="px-4 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((cr) => (
                  <CrRow
                    key={cr.id}
                    cr={cr}
                    selected={cr.id === selectedId}
                    onView={(c) => setSelectedId(c.id)}
                  />
                ))}
              </tbody>
            </table>
            <p data-testid="cr-total-count" className="px-4 py-2 text-[11px] text-zinc-600">
              {data?.total ?? 0}
            </p>
          </div>

          {selected !== null && (
            <div className="mt-2">
              <DetailPanel
                key={selected.id}
                cr={selected}
                currentUserId={currentUserId}
                onClose={() => setSelectedId(null)}
                onDecided={handleDecided}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
