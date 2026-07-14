/**
 * UsersPage (Auth & Account UI, F5): admin-only account management.
 *
 * Features:
 *  - Table of all users: username, email, display_name, role, is_active,
 *    must_change_password. Data from GET /auth/users.
 *  - Create-user modal (POST /auth/users): on success, shows the returned
 *    temp password EXACTLY ONCE with a copy affordance and a clear warning
 *    that it will not be shown again.
 *  - Per-row actions, each with a confirmation dialog before execution:
 *      · Edit role — PATCH /auth/users/{id} with { role }
 *      · Activate/deactivate — PATCH /auth/users/{id} with { is_active };
 *        surfaces the backend 409 last-admin-guard error to the user.
 *      · Reset password — POST /auth/users/{id}/reset-password; shows the
 *        new temp password once.
 *      · Revoke sessions — POST /auth/users/{id}/revoke-sessions.
 *
 * Role guards here are defense-in-depth only; the backend require_role
 * ("admin") is the canonical source of truth.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  createUser,
  listUsers,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from "../api/auth";
import type { UserSummary } from "../api/auth";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { messageFor } from "../components/ErrorBanner";
import { Modal } from "../components/Modal";
import { PageHeader } from "../components/PageHeader";
import type { Role } from "../stores/roles";

// ── Constants ─────────────────────────────────────────────────────────────────

const ROLES: Role[] = ["viewer", "operator", "engineer", "admin"];

// ── Temp-password reveal dialog ───────────────────────────────────────────────

interface TempPasswordDialogProps {
  tempPassword: string;
  onClose: () => void;
}

function TempPasswordDialog({ tempPassword, onClose }: TempPasswordDialogProps) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const copyAttempt = useRef(0);

  async function handleCopy() {
    const attempt = ++copyAttempt.current;
    setCopied(false);
    setCopyError(false);
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(tempPassword);
      if (attempt === copyAttempt.current) setCopied(true);
    } catch {
      if (attempt === copyAttempt.current) setCopyError(true);
    }
  }

  return (
    <Modal aria-label="Temporary password">
        <h3 className="text-sm font-semibold text-zinc-100">Temporary password</h3>
        <p className="mt-2 text-xs text-status-warn">
          This password will not be shown again. Copy it now and share it securely with the user.
        </p>
        <div className="mt-4 flex items-center gap-2 rounded border border-carbon-700 bg-carbon-950 px-3 py-2">
          <code className="flex-1 break-all font-mono text-sm text-zinc-100">{tempPassword}</code>
          <button
            type="button"
            onClick={handleCopy}
            aria-label="Copy"
            className="shrink-0 rounded border border-carbon-700 px-2 py-1 text-xs text-zinc-400 transition-colors hover:text-zinc-100"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
{copyError ? <p role="alert" className="mt-3 text-xs text-status-error">Could not copy the password. Copy it manually.</p> : null}
        <div className="mt-5 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-carbon-950 transition-opacity hover:opacity-90"
          >
            Done
          </button>
        </div>
    </Modal>
  );
}

// ── Create-user modal ─────────────────────────────────────────────────────────

interface CreateUserModalProps {
  onClose: () => void;
  onCreated: () => void;
}

function CreateUserModal({ onClose, onCreated }: CreateUserModalProps) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      createUser({
        username,
        role,
        email: email.trim() || null,
        display_name: displayName.trim() || null,
      }),
    onSuccess: (result) => {
      setTempPassword(result.temp_password);
      onCreated();
    },
    onError: (err) => {
      setFormError(messageFor(err));
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    mutation.mutate();
  }

  // After creation, show the temp-password reveal dialog.
  if (tempPassword !== null) {
    return <TempPasswordDialog tempPassword={tempPassword} onClose={onClose} />;
  }

  return (
    <Modal aria-label="Create user">
        <h3 className="text-sm font-semibold text-zinc-100">Create user</h3>
        <p className="mt-1 text-xs text-zinc-500">
          A temporary password will be generated. The user must change it on first login.
        </p>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3" noValidate>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Username
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="off"
              className="input"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Role
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="input"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Email (optional)
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="off"
              className="input"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Display name (optional)
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              autoComplete="off"
              className="input"
            />
          </label>

          {formError !== null && (
            <p role="alert" className="text-xs text-status-error">
              {formError}
            </p>
          )}

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
              disabled={mutation.isPending || username.trim() === ""}
              className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-carbon-950 transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {mutation.isPending ? "Creating…" : "Create"}
            </button>
          </div>
        </form>
    </Modal>
  );
}

// ── Pending action types ──────────────────────────────────────────────────────

type PendingAction =
  | { kind: "deactivate"; user: UserSummary }
  | { kind: "activate"; user: UserSummary }
  | { kind: "reset-password"; user: UserSummary }
  | { kind: "revoke-sessions"; user: UserSummary }
  | { kind: "role-change"; user: UserSummary; newRole: Role };

// ── User table row ────────────────────────────────────────────────────────────

interface UserRowProps {
  user: UserSummary;
  onAction: (action: PendingAction) => void;
}

function UserRow({ user, onAction }: UserRowProps) {
  return (
    <tr className="border-b border-carbon-800 last:border-0">
      <td className="px-4 py-2 font-mono text-xs text-zinc-100">{user.username}</td>
      <td className="px-4 py-2 text-xs text-zinc-300">{user.email ?? "—"}</td>
      <td className="px-4 py-2 text-xs text-zinc-300">{user.display_name ?? "—"}</td>
      <td className="px-4 py-2">
        <select
          aria-label="Change role"
          value={user.role}
          onChange={(e) => {
            const newRole = e.target.value as Role;
            if (newRole !== user.role) {
              onAction({ kind: "role-change", user, newRole });
            }
          }}
          className="rounded border border-carbon-700 bg-carbon-900 px-2 py-1 text-xs text-zinc-200 focus:outline-none"
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-2 text-xs">
        <span
          className={
            user.is_active
              ? "text-status-ok"
              : "text-zinc-500"
          }
        >
          {user.is_active ? "Yes" : "No"}
        </span>
      </td>
      <td className="px-4 py-2 text-xs text-zinc-500">
        {user.must_change_password ? (
          <span className="text-status-warn">Yes</span>
        ) : (
          "No"
        )}
      </td>
      <td className="px-4 py-2">
        <div className="flex items-center gap-2">
          {user.is_active ? (
            <button
              type="button"
              onClick={() => onAction({ kind: "deactivate", user })}
              className="text-xs text-status-error hover:underline"
            >
              Deactivate
            </button>
          ) : (
            <button
              type="button"
              onClick={() => onAction({ kind: "activate", user })}
              className="text-xs text-status-ok hover:underline"
            >
              Activate
            </button>
          )}
          <button
            type="button"
            onClick={() => onAction({ kind: "reset-password", user })}
            className="text-xs text-zinc-400 hover:underline"
          >
            Reset password
          </button>
          <button
            type="button"
            onClick={() => onAction({ kind: "revoke-sessions", user })}
            className="text-xs text-zinc-400 hover:underline"
          >
            Revoke sessions
          </button>
        </div>
      </td>
    </tr>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function UsersPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [confirmPending, setConfirmPending] = useState(false);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  const { data: users, isPending: loading } = useQuery({
    queryKey: ["users"],
    queryFn: listUsers,
  });

  function handleAction(action: PendingAction) {
    setConfirmError(null);
    setPending(action);
  }

  async function handleConfirm() {
    if (pending === null) return;
    setConfirmError(null);
    setConfirmPending(true);

    try {
      switch (pending.kind) {
        case "deactivate":
          await updateUser(pending.user.id, { is_active: false });
          await queryClient.invalidateQueries({ queryKey: ["users"] });
          break;
        case "activate":
          await updateUser(pending.user.id, { is_active: true });
          await queryClient.invalidateQueries({ queryKey: ["users"] });
          break;
        case "role-change":
          await updateUser(pending.user.id, { role: pending.newRole });
          await queryClient.invalidateQueries({ queryKey: ["users"] });
          break;
        case "reset-password": {
          const result = await resetUserPassword(pending.user.id, undefined);
          setTempPassword(result.temp_password);
          await queryClient.invalidateQueries({ queryKey: ["users"] });
          break;
        }
        case "revoke-sessions":
          await revokeUserSessions(pending.user.id);
          break;
      }
      if (pending.kind !== "reset-password") {
        setPending(null);
      } else {
        // Keep pending until the temp-password dialog is closed
        setPending(null);
      }
    } catch (err) {
      setConfirmError(messageFor(err));
    } finally {
      setConfirmPending(false);
    }
  }

  function handleCancelConfirm() {
    setPending(null);
    setConfirmError(null);
  }

  function confirmMessage(): string {
    if (pending === null) return "";
    switch (pending.kind) {
      case "deactivate":
        return `Deactivate "${pending.user.username}"? Their active sessions will be revoked immediately.`;
      case "activate":
        return `Reactivate "${pending.user.username}"?`;
      case "role-change":
        return `Change "${pending.user.username}" role from "${pending.user.role}" to "${pending.newRole}"?`;
      case "reset-password":
        return `Reset password for "${pending.user.username}"? A new temporary password will be generated and all their sessions revoked.`;
      case "revoke-sessions":
        return `Revoke all active sessions for "${pending.user.username}"?`;
    }
  }

  return (
    <div className="flex flex-col gap-6" data-testid="users-page">
      <PageHeader
        title="Users"
        description="Create accounts, assign roles, and manage access (admin only)."
        actions={
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn"
          >
            Create user
          </button>
        }
      />

      {/* Users table */}
      <section aria-label="User accounts" className="flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">Accounts</h3>

        <DataTable
          headers={["Username", "Email", "Display name", "Role", "Active", "Must change password", "Actions"]}
          loading={loading}
          loadingLabel="Loading users…"
          empty={!loading && users?.length === 0 ? <p className="text-xs text-zinc-500">No users found.</p> : undefined}
        >
          {users?.map((user) => <UserRow key={user.id} user={user} onAction={handleAction} />)}
        </DataTable>
      </section>

      {/* Create-user modal */}
      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            void queryClient.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}

      {/* Confirmation dialog for destructive actions */}
      {pending !== null && tempPassword === null && (
        <ConfirmDialog
          message={confirmMessage()}
          onConfirm={() => void handleConfirm()}
          onCancel={handleCancelConfirm}
          isPending={confirmPending}
          error={confirmError}
        />
      )}

      {/* Temp-password reveal after reset-password */}
      {tempPassword !== null && (
        <TempPasswordDialog
          tempPassword={tempPassword}
          onClose={() => setTempPassword(null)}
        />
      )}
    </div>
  );
}
