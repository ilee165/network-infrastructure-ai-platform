/**
 * Applications: the manual application-tagging surface (P4 W2-T3).
 *
 * Read surface (rider P2): a paginated application list with per-origin badges
 * and expandable per-application dependency detail carrying per-source badges —
 * the AdcPage inventory-table + row-expansion pattern. Reads are viewer+.
 *
 * Write flows + role gating (rider P3): create/edit/delete of ``manual``-origin
 * applications and add/remove of ``source='manual'`` dependency rows, gated to
 * ``engineer``+ as defense-in-depth over the backend ``require_role`` (the
 * source of truth). Two invariants the UI enforces to match the backend:
 *  - ``derived`` applications are lifecycle-owned by derivation — no delete
 *    control is ever offered for one (the backend returns 409).
 *  - only ``source='manual'`` dependency rows get a remove control — a
 *    derivation-owned edge retracts when its source stops asserting it.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import type { FormEvent, KeyboardEvent } from "react";
import {
  createApplication,
  createApplicationDependency,
  deleteApplication,
  deleteApplicationDependency,
  listApplicationDependencies,
  listApplications,
  updateApplication,
  type ApplicationDependencyRead,
  type ApplicationOrigin,
  type ApplicationRead,
  type DependencySource,
  type DependencyTargetKind,
} from "../api/applications";
import { ApiError } from "../api/client";
import { ErrorBanner, messageFor } from "../components/ErrorBanner";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Modal } from "../components/Modal";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { SkeletonRows } from "../components/Skeleton";
import { useAuthStore } from "../stores/auth";
import { hasMinimumRole } from "../stores/roles";
import { useUiStore } from "../stores/ui";

/** Rows fetched per page (matches the server-side list cap of 500; 100 is plenty). */
const PAGE_SIZE = 100;
/** Target kinds a manual tag may point at (ADR-0052 §2.3 rebuild-safe kinds). */
const TARGET_KINDS: DependencyTargetKind[] = ["device", "ip_address"];

/** Problem ``type`` the backend uses for an optimistic-concurrency (N1) conflict. */
const STALE_PRECONDITION_TYPE = "urn:netops:error:stale-precondition";

/** Message shown when a write lost the optimistic-concurrency race (N1). */
const STALE_MESSAGE =
  "This application was changed by someone else since you opened it. Reload to load " +
  "the latest values, then re-apply your change.";

/**
 * True only for the lost-update 409 (``stale-precondition``) — NOT the sibling
 * name-collision 409 (``conflict``), which shares the status but differs by
 * problem ``type`` and is fixed by just changing the name.
 */
function isStalePrecondition(err: unknown): boolean {
  return err instanceof ApiError && err.problem.type === STALE_PRECONDITION_TYPE;
}

/** Tailwind tone per application origin — derived vs user-owned are visually distinct. */
const ORIGIN_TONE: Record<ApplicationOrigin, string> = {
  manual: "bg-accent/15 text-accent",
  derived: "bg-carbon-700 text-zinc-300",
};

/** Tailwind tone per dependency source, so an edge's provenance reads at a glance. */
const SOURCE_TONE: Record<DependencySource, string> = {
  manual: "bg-accent/15 text-accent",
  f5: "bg-sky-500/15 text-sky-300",
  vmware: "bg-emerald-500/15 text-emerald-300",
  dns: "bg-amber-500/15 text-amber-300",
};

function OriginBadge({ application }: { application: ApplicationRead }) {
  return (
    <span
      data-testid={`application-origin-${application.id}`}
      className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${ORIGIN_TONE[application.origin]}`}
    >
      {application.origin}
    </span>
  );
}

function SourceBadge({ id, source }: { id: string; source: DependencySource }) {
  return (
    <span
      data-testid={`dependency-source-${id}`}
      className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SOURCE_TONE[source]}`}
    >
      {source}
    </span>
  );
}

// ── Create / edit application modal ────────────────────────────────────────────

function ApplicationFormModal({
  application,
  onClose,
}: {
  /** When present, the modal edits this application (PATCH); otherwise creates. */
  application?: ApplicationRead;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((state) => state.pushToast);
  const editing = application !== undefined;

  const [name, setName] = useState(application?.name ?? "");
  const [description, setDescription] = useState(application?.description ?? "");
  const [owner, setOwner] = useState(application?.owner ?? "");
  const [fqdns, setFqdns] = useState((application?.fqdns ?? []).join(", "));
  const [formError, setFormError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  const mutation = useMutation({
    mutationFn: () => {
      const payload = {
        name: name.trim(),
        description: description.trim() || null,
        owner: owner.trim() || null,
        fqdns: fqdns
          .split(",")
          .map((entry) => entry.trim())
          .filter(Boolean),
      };
      // Optimistic concurrency (N1): send the version the modal opened with as
      // the If-Match precondition so a concurrent edit is not silently clobbered.
      return editing
        ? updateApplication(application.id, payload, application.updated_at)
        : createApplication(payload);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["applications"] });
      pushToast("success", editing ? "Application updated." : "Application created.");
      onClose();
    },
    onError: (err) => {
      if (isStalePrecondition(err)) {
        // Someone else changed the row: surface the reload affordance, refresh the
        // list in the background, and do NOT toast success.
        setStale(true);
        setFormError(STALE_MESSAGE);
        void queryClient.invalidateQueries({ queryKey: ["applications"] });
      } else {
        // Any other error (including a name-collision 409) is fixable in place.
        setStale(false);
        setFormError(messageFor(err));
      }
    },
  });

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setFormError(null);
    setStale(false);
    mutation.mutate();
  }

  function reloadAndClose(): void {
    void queryClient.invalidateQueries({ queryKey: ["applications"] });
    onClose();
  }

  return (
    <Modal aria-label={editing ? "Edit application" : "Create application"}>
        <h3 className="text-sm font-semibold text-zinc-100">
          {editing ? "Edit application" : "Create application"}
        </h3>
        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3" noValidate>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Name
            <input
              type="text"
              data-testid="application-form-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoComplete="off"
              className="input"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Description (optional)
            <input
              type="text"
              data-testid="application-form-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              autoComplete="off"
              className="input"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Owner (optional)
            <input
              type="text"
              data-testid="application-form-owner"
              value={owner}
              onChange={(event) => setOwner(event.target.value)}
              autoComplete="off"
              className="input"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            FQDNs (comma-separated, optional)
            <input
              type="text"
              data-testid="application-form-fqdns"
              value={fqdns}
              onChange={(event) => setFqdns(event.target.value)}
              autoComplete="off"
              className="input"
            />
          </label>
          {formError !== null ? (
            <div role="alert" className="flex flex-col gap-1 text-xs text-status-error">
              <span>{formError}</span>
              {stale ? (
                <button
                  type="button"
                  data-testid="application-reload-button"
                  onClick={reloadAndClose}
                  className="self-start underline hover:no-underline"
                >
                  Reload
                </button>
              ) : null}
            </div>
          ) : null}
          <div className="mt-2 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={mutation.isPending}
              className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400 transition-colors hover:text-zinc-100 disabled:opacity-60"
            >
              Cancel
            </button>
            <button
              type="submit"
              data-testid="application-form-submit"
              disabled={mutation.isPending || name.trim() === ""}
              className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-carbon-950 transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {mutation.isPending ? "Saving…" : editing ? "Save" : "Create"}
            </button>
          </div>
        </form>
    </Modal>
  );
}

// ── Add-dependency inline form (tag an object into an application) ──────────────

function DependencyAddForm({ appId, onClose }: { appId: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((state) => state.pushToast);
  const [targetKind, setTargetKind] = useState<DependencyTargetKind>("device");
  const [targetRef, setTargetRef] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      createApplicationDependency(appId, {
        target_kind: targetKind,
        target_ref: targetRef.trim(),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["application-dependencies", appId] });
      pushToast("success", "Dependency tagged.");
      onClose();
    },
    onError: (err) => setFormError(messageFor(err)),
  });

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setFormError(null);
    mutation.mutate();
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="mt-3 flex flex-wrap items-end gap-2 rounded border border-carbon-700 bg-carbon-900 p-3"
      noValidate
    >
      <label className="flex flex-col gap-1 text-[11px] text-zinc-400">
        Target kind
        <select
          data-testid="dependency-form-kind"
          value={targetKind}
          onChange={(event) => setTargetKind(event.target.value as DependencyTargetKind)}
          className="input"
        >
          {TARGET_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {kind}
            </option>
          ))}
        </select>
      </label>
      <label className="flex min-w-[18rem] flex-1 flex-col gap-1 text-[11px] text-zinc-400">
        Target id (UUID)
        <input
          type="text"
          data-testid="dependency-form-ref"
          value={targetRef}
          onChange={(event) => setTargetRef(event.target.value)}
          required
          autoComplete="off"
          className="input font-mono"
        />
      </label>
      {formError !== null ? (
        <p role="alert" className="w-full text-xs text-status-error">
          {formError}
        </p>
      ) : null}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onClose}
          disabled={mutation.isPending}
          className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400 transition-colors hover:text-zinc-100 disabled:opacity-60"
        >
          Cancel
        </button>
        <button
          type="submit"
          data-testid="dependency-form-submit"
          disabled={mutation.isPending || targetRef.trim() === ""}
          className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-carbon-950 transition-opacity hover:opacity-90 disabled:opacity-60"
        >
          {mutation.isPending ? "Tagging…" : "Add"}
        </button>
      </div>
    </form>
  );
}

// ── Dependency detail (expanded row) ───────────────────────────────────────────

function DependencyRow({
  appId,
  dep,
  canWrite,
}: {
  appId: string;
  dep: ApplicationDependencyRead;
  canWrite: boolean;
}) {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((state) => state.pushToast);
  const [confirming, setConfirming] = useState(false);
  const [confirmError, setConfirmError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => deleteApplicationDependency(appId, dep.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["application-dependencies", appId] });
      pushToast("success", "Dependency removed.");
      setConfirming(false);
    },
    onError: (err) => setConfirmError(messageFor(err)),
  });

  // Only manual rows are user-removable — a derivation-owned edge retracts when
  // its source stops asserting it (the backend returns 409 otherwise).
  const removable = canWrite && dep.source === "manual";

  return (
    <tr className="border-b border-carbon-800 last:border-0">
      <td className="py-1 pr-4 text-zinc-300">{dep.target_kind}</td>
      <td className="py-1 pr-4 font-mono text-zinc-400">{dep.target_ref}</td>
      <td className="py-1 pr-4">
        <SourceBadge id={dep.id} source={dep.source} />
      </td>
      <td className="py-1 text-right">
        {removable ? (
          <button
            type="button"
            data-testid={`dependency-remove-${dep.id}`}
            onClick={() => {
              setConfirmError(null);
              setConfirming(true);
            }}
            className="text-xs text-status-error hover:underline"
          >
            Remove
          </button>
        ) : null}
        {confirming ? (
          <ConfirmDialog
            confirmTestId="confirm-action"
            message={`Remove the manual dependency on ${dep.target_kind} ${dep.target_ref}?`}
            onConfirm={() => mutation.mutate()}
            onCancel={() => setConfirming(false)}
            isPending={mutation.isPending}
            error={confirmError}
          />
        ) : null}
      </td>
    </tr>
  );
}

function DependencyDetail({
  application,
  colSpan,
  canWrite,
}: {
  application: ApplicationRead;
  colSpan: number;
  canWrite: boolean;
}) {
  const [adding, setAdding] = useState(false);
  const { data, error, isPending } = useQuery({
    queryKey: ["application-dependencies", application.id],
    queryFn: () => listApplicationDependencies(application.id),
  });

  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <div
          data-testid={`application-detail-${application.id}`}
          className="border-t border-carbon-700 bg-carbon-950 px-4 pb-4 pt-2"
        >
          <div className="mb-2 flex items-center justify-between">
            <h4 className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
              Dependencies
            </h4>
            {canWrite ? (
              <button
                type="button"
                data-testid={`dependency-add-${application.id}`}
                onClick={() => setAdding((open) => !open)}
                className="text-xs text-accent hover:underline"
              >
                {adding ? "Close" : "Add dependency"}
              </button>
            ) : null}
          </div>
          {adding ? (
            <DependencyAddForm appId={application.id} onClose={() => setAdding(false)} />
          ) : null}
          {isPending ? (
            <p className="px-1 py-2 text-xs text-zinc-500">Loading dependencies…</p>
          ) : null}
          {error ? (
            <ErrorBanner error={error} data-testid={`dependency-error-${application.id}`} />
          ) : null}
          {!isPending && !error && (data?.length ?? 0) === 0 ? (
            <p className="px-1 py-2 text-xs text-zinc-500">
              No dependencies recorded for this application.
            </p>
          ) : null}
          {data && data.length > 0 ? (
            <table className="mt-2 w-full text-xs">
              <thead>
                <tr className="border-b border-carbon-700 text-left text-zinc-500">
                  <th className="py-1 pr-4 font-medium">Target kind</th>
                  <th className="py-1 pr-4 font-medium">Target</th>
                  <th className="py-1 pr-4 font-medium">Source</th>
                  <th className="py-1" />
                </tr>
              </thead>
              <tbody>
                {data.map((dep) => (
                  <DependencyRow key={dep.id} appId={application.id} dep={dep} canWrite={canWrite} />
                ))}
              </tbody>
            </table>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

// ── Applications table ─────────────────────────────────────────────────────────

function ApplicationsTable({
  items,
  canWrite,
  onEdit,
}: {
  items: ApplicationRead[];
  canWrite: boolean;
  onEdit: (application: ApplicationRead) => void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((state) => state.pushToast);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ApplicationRead | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const colSpan = canWrite ? 5 : 4;

  const deleteMutation = useMutation({
    // Optimistic concurrency (N1): pass the row version as the If-Match precondition
    // so a delete from a stale view cannot destroy a row that changed underneath us.
    mutationFn: (application: ApplicationRead) =>
      deleteApplication(application.id, application.updated_at),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["applications"] });
      pushToast("success", "Application deleted.");
      setPendingDelete(null);
    },
    onError: (err) => {
      if (isStalePrecondition(err)) {
        setConfirmError(STALE_MESSAGE);
        void queryClient.invalidateQueries({ queryKey: ["applications"] });
      } else {
        setConfirmError(messageFor(err));
      }
    },
  });

  const toggle = (id: string) => setExpanded((prev) => (prev === id ? null : id));

  function handleKeyDown(event: KeyboardEvent<HTMLTableRowElement>, id: string): void {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle(id);
    }
  }

  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Origin</th>
            <th className="px-4 py-2 font-medium">Owner</th>
            <th className="px-4 py-2 font-medium">FQDNs</th>
            {canWrite ? <th className="px-4 py-2 font-medium">Actions</th> : null}
          </tr>
        </thead>
        <tbody>
          {items.map((app) => {
            const manual = app.origin === "manual";
            return (
              <Fragment key={app.id}>
                <tr
                  role="button"
                  tabIndex={0}
                  aria-expanded={expanded === app.id}
                  data-testid={`application-row-${app.id}`}
                  className="cursor-pointer border-b border-carbon-800 transition-colors last:border-0 hover:bg-carbon-800/50 focus:outline-none focus:ring-1 focus:ring-inset focus:ring-accent"
                  onClick={() => toggle(app.id)}
                  onKeyDown={(event) => handleKeyDown(event, app.id)}
                >
                  <td className="px-4 py-2 font-mono text-zinc-100">{app.name}</td>
                  <td className="px-4 py-2">
                    <OriginBadge application={app} />
                  </td>
                  <td className="px-4 py-2 text-zinc-300">{app.owner ?? "—"}</td>
                  <td className="px-4 py-2 font-mono text-zinc-400">
                    {app.fqdns.length > 0 ? app.fqdns.join(", ") : "—"}
                  </td>
                  {canWrite ? (
                    <td className="px-4 py-2" onClick={(event) => event.stopPropagation()}>
                      {manual ? (
                        <div className="flex items-center gap-3">
                          <button
                            type="button"
                            data-testid={`application-edit-${app.id}`}
                            onClick={() => onEdit(app)}
                            className="text-xs text-zinc-400 hover:underline"
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            data-testid={`application-delete-${app.id}`}
                            onClick={() => {
                              setConfirmError(null);
                              setPendingDelete(app);
                            }}
                            className="text-xs text-status-error hover:underline"
                          >
                            Delete
                          </button>
                        </div>
                      ) : (
                        <span className="text-[11px] text-zinc-600">derivation-owned</span>
                      )}
                    </td>
                  ) : null}
                </tr>
                {expanded === app.id && (
                  <DependencyDetail application={app} colSpan={colSpan} canWrite={canWrite} />
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>

      {pendingDelete !== null ? (
        <ConfirmDialog
            confirmTestId="confirm-action"
          message={`Delete the manual application "${pendingDelete.name}"? Its manual dependency rows are removed with it.`}
          onConfirm={() => deleteMutation.mutate(pendingDelete)}
          onCancel={() => setPendingDelete(null)}
          isPending={deleteMutation.isPending}
          error={confirmError}
        />
      ) : null}
    </div>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────────

export function ApplicationsPage() {
  const user = useAuthStore((state) => state.user);
  const canWrite = hasMinimumRole(user?.role, "engineer");

  const [offset, setOffset] = useState(0);
  const [origin, setOrigin] = useState<ApplicationOrigin | "all">("all");
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ApplicationRead | null>(null);

  const { data, error, isPending } = useQuery({
    queryKey: ["applications", offset, origin],
    queryFn: () =>
      listApplications({
        limit: PAGE_SIZE,
        offset,
        ...(origin === "all" ? {} : { origin }),
      }),
  });

  const items = data?.items ?? [];

  function closeForm(): void {
    setFormOpen(false);
    setEditing(null);
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Applications"
        description="Application-dependency inventory — derived (F5 / VMware / DNS) and manually tagged."
        actions={
          canWrite ? (
            <button
              type="button"
              data-testid="application-create-button"
              onClick={() => {
                setEditing(null);
                setFormOpen(true);
              }}
              className="btn"
            >
              Create application
            </button>
          ) : undefined
        }
      />

      <section aria-label="Applications" className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Applications {data ? `(${data.total})` : null}
          </h3>
          <label className="flex items-center gap-2 text-xs text-zinc-500">
            Origin
            <select
              data-testid="applications-origin-filter"
              value={origin}
              onChange={(event) => {
                setOrigin(event.target.value as ApplicationOrigin | "all");
                setOffset(0);
              }}
              className="rounded border border-carbon-700 bg-carbon-900 px-2 py-1 text-xs text-zinc-200"
            >
              <option value="all">All</option>
              <option value="manual">Manual</option>
              <option value="derived">Derived</option>
            </select>
          </label>
        </div>

        {isPending ? (
          <div className="panel overflow-x-auto">
            <table className="w-full text-xs">
              <tbody>
                <SkeletonRows rows={4} cols={canWrite ? 5 : 4} label="Loading applications…" />
              </tbody>
            </table>
          </div>
        ) : null}
        {error ? <ErrorBanner error={error} data-testid="applications-error" /> : null}
        {!isPending && !error && items.length === 0 ? (
          <div
            data-testid="applications-empty-state"
            className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
          >
            <p className="text-sm font-medium text-zinc-200">No applications recorded yet</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              Applications appear here once the derivation pipeline runs, or when you tag one manually.
            </p>
          </div>
        ) : null}
        {items.length > 0 ? (
          <ApplicationsTable
            items={items}
            canWrite={canWrite}
            onEdit={(application) => {
              setEditing(application);
              setFormOpen(true);
            }}
          />
        ) : null}
        {data ? (
          <Pagination
            offset={offset}
            limit={PAGE_SIZE}
            total={data.total}
            onChange={setOffset}
            label="applications"
          />
        ) : null}
      </section>

      {formOpen ? (
        <ApplicationFormModal application={editing ?? undefined} onClose={closeForm} />
      ) : null}
    </div>
  );
}
