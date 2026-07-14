/**
 * ProfilePage (Auth & Account UI, F4): self-service account view.
 *
 * Sections:
 *  1. Profile info + edit email / display_name (PATCH /auth/me)
 *  2. Change-password section (reuses POST /auth/me/password flow)
 *  3. Sessions list (GET /auth/sessions) with per-row revoke and revoke-all
 *
 * The own-audit section is intentionally omitted: the backend audit_log has no
 * endpoint filterable by the current actor, so we do not invent one.
 *
 * Data fetching uses TanStack Query. Mutations call the auth API functions and
 * update the auth store's cached user on success.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";
import {
  changePassword,
  getMe,
  listSessions,
  revokeAllSessions,
  revokeSession,
  updateMe,
} from "../api/auth";
import type { SessionInfo } from "../api/auth";
import { messageFor } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { useAuthStore } from "../stores/auth";

// ── Constants ─────────────────────────────────────────────────────────────────

const MIN_PASSWORD_LENGTH = 8;
// ── Profile edit form ─────────────────────────────────────────────────────────

function ProfileEditSection() {
  const user = useAuthStore((state) => state.user);
  const setUser = useAuthStore((state) => state.setUser);

  const [email, setEmail] = useState(user?.email ?? "");
  const [displayName, setDisplayName] = useState(user?.display_name ?? "");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const mutation = useMutation({
    mutationFn: () => updateMe({ email: email || null, display_name: displayName || null }),
    onSuccess: (updated) => {
      setUser(updated);
      setSaveSuccess(true);
      setSaveError(null);
    },
    onError: (err) => {
      setSaveError(messageFor(err));
      setSaveSuccess(false);
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaveError(null);
    setSaveSuccess(false);
    mutation.mutate();
  }

  return (
    <section aria-label="Profile information" className="panel p-4 flex flex-col gap-4">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Profile
      </h3>

      {/* Read-only info */}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <dt className="text-zinc-500">Username</dt>
        <dd className="font-mono text-zinc-100">{user?.username}</dd>
        <dt className="text-zinc-500">Role</dt>
        <dd className="font-mono text-zinc-100">{user?.role}</dd>
      </dl>

      {/* Editable fields */}
      <form onSubmit={handleSubmit} className="flex flex-col gap-3" noValidate>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input"
            autoComplete="email"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Display name
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="input"
            autoComplete="name"
          />
        </label>

        {saveError !== null && (
          <p role="alert" className="text-xs text-status-error">
            {saveError}
          </p>
        )}
        {saveSuccess && (
          <p className="text-xs text-status-ok">Profile saved.</p>
        )}

        <button type="submit" disabled={mutation.isPending} className="btn self-start">
          {mutation.isPending ? "Saving…" : "Save profile"}
        </button>
      </form>
    </section>
  );
}

// ── Change-password section ───────────────────────────────────────────────────

function ChangePasswordSection() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [pending, setPending] = useState(false);
  const setUser = useAuthStore((state) => state.setUser);

  // Import getMe lazily to avoid circular issues
  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    if (next.length < MIN_PASSWORD_LENGTH) {
      setError(`New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (next !== confirm) {
      setError("New password and confirmation do not match.");
      return;
    }

    setPending(true);
    try {
      await changePassword(current, next);
      // Refetch /me to sync must_change_password flag
      const user = await getMe();
      setUser(user);
      setCurrent("");
      setNext("");
      setConfirm("");
      setSuccess(true);
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setPending(false);
    }
  }

  return (
    <section aria-label="Change password" className="panel p-4 flex flex-col gap-4">
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Change password
      </h3>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3" noValidate>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Current password
          <input
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className="input"
            autoComplete="current-password"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          New password
          <input
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            className="input"
            autoComplete="new-password"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          Confirm new password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="input"
            autoComplete="new-password"
          />
        </label>

        {error !== null && (
          <p role="alert" className="text-xs text-status-error">
            {error}
          </p>
        )}
        {success && (
          <p className="text-xs text-status-ok">Password changed successfully.</p>
        )}

        <button type="submit" disabled={pending} className="btn self-start">
          {pending ? "Changing…" : "Change password"}
        </button>
      </form>
    </section>
  );
}

// ── Sessions section ──────────────────────────────────────────────────────────

function SessionRow({
  session,
  onRevoke,
  revoking,
}: {
  session: SessionInfo;
  onRevoke: (sid: string) => void;
  revoking: boolean;
}) {
  return (
    <tr className="border-b border-carbon-800 last:border-0">
      <td className="px-4 py-2 text-xs text-zinc-300">
        {session.ip ?? "—"}
        {session.is_current && (
          <span
            data-testid="session-current"
            className="ml-2 inline-flex items-center rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent"
          >
            current
          </span>
        )}
      </td>
      <td className="px-4 py-2 text-xs text-zinc-500 max-w-xs truncate">
        {session.user_agent ?? "—"}
      </td>
      <td className="px-4 py-2 text-xs text-zinc-500">
        {new Date(session.created_at).toLocaleString()}
      </td>
      <td className="px-4 py-2 text-xs text-zinc-500">
        {new Date(session.last_used_at).toLocaleString()}
      </td>
      <td className="px-4 py-2">
        {session.revoked_at !== null || session.is_current ? (
          <span className="text-xs text-zinc-600">
            {session.is_current ? "Current session" : "Revoked"}
          </span>
        ) : (
          <button
            type="button"
            onClick={() => onRevoke(session.sid)}
            disabled={revoking}
            className="text-xs text-status-error hover:underline disabled:opacity-60"
          >
            Revoke
          </button>
        )}
      </td>
    </tr>
  );
}

function SessionsSection() {
  const queryClient = useQueryClient();

  const { data: sessions, isPending, error } = useQuery({
    queryKey: ["my-sessions"],
    queryFn: () => listSessions(),
  });

  const revokeMutation = useMutation({
    mutationFn: (sid: string) => revokeSession(sid),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["my-sessions"] }),
  });

  const revokeAllMutation = useMutation({
    mutationFn: () => revokeAllSessions(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["my-sessions"] }),
  });

  return (
    <section aria-label="Active sessions" className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Sessions
        </h3>
        {sessions && sessions.length > 0 && (
          <button
            type="button"
            onClick={() => revokeAllMutation.mutate()}
            disabled={revokeAllMutation.isPending}
            className="text-xs text-status-error hover:underline disabled:opacity-60"
          >
            {revokeAllMutation.isPending ? "Revoking…" : "Revoke all"}
          </button>
        )}
      </div>

      {isPending && (
        <p role="status" className="text-xs text-zinc-500">Loading sessions…</p>
      )}
      {error && (
        <p role="alert" className="text-xs text-status-error">{messageFor(error)}</p>
      )}

      {sessions && sessions.length > 0 && (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-carbon-700 text-left text-zinc-500">
                <th className="px-4 py-2 font-medium">IP</th>
                <th className="px-4 py-2 font-medium">User agent</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 font-medium">Last used</th>
                <th className="px-4 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <SessionRow
                  key={s.sid}
                  session={s}
                  onRevoke={(sid) => revokeMutation.mutate(sid)}
                  revoking={revokeMutation.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {sessions && sessions.length === 0 && (
        <p className="text-xs text-zinc-500">No active sessions.</p>
      )}
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function ProfilePage() {
  const user = useAuthStore((state) => state.user);

  return (
    <div className="flex flex-col gap-6" data-testid="profile-page">
      <PageHeader
        title="Profile"
        description="Your account details, sessions, and password."
        actions={
          user ? (
            <span className="badge font-mono text-zinc-400">{user.username}</span>
          ) : null
        }
      />

      <ProfileEditSection />
      <ChangePasswordSection />
      <SessionsSection />
    </div>
  );
}
