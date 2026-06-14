/**
 * ChangePasswordPage (Auth & Account UI, F3): change-own-password flow.
 *
 * Serves BOTH the voluntary change (reached from the profile) and the forced
 * first-login gate: ``ProtectedRoute`` pins a user with ``must_change_password``
 * here until it clears, so this page lives outside the gate.
 *
 * Flow: validate client-side (new length >= 8 and confirm matches new) → call
 * ``changePassword(current, new)`` → refetch ``getMe()`` and cache it so the
 * store's ``must_change_password`` flips false (releasing the forced gate) →
 * navigate to "/". Backend errors (e.g. a wrong current password) render via the
 * ``ApiError`` detail and keep the user on the page.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { changePassword, getMe } from "../api/auth";
import { ApiError } from "../api/client";
import { useAuthStore } from "../stores/auth";

/** Minimum length the backend enforces for a new password (mirrored client-side). */
const MIN_PASSWORD_LENGTH = 8;

/** Generic fallback when an error is not a structured ``ApiError``. */
const GENERIC_ERROR = "Could not change your password. Please try again.";

/** Extract a user-facing message from a thrown value (problem-details detail). */
function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.problem.detail;
  }
  return GENERIC_ERROR;
}

export function ChangePasswordPage() {
  const setUser = useAuthStore((state) => state.setUser);
  const navigate = useNavigate();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(null);

    // Client-side guards run before any network call (defense-in-depth over the
    // backend's own min-length + the fact it has no confirm field).
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
      // Refetch /me so must_change_password flips false and the forced gate (if
      // any) releases; cache it before navigating into the app.
      const user = await getMe();
      setUser(user);
      navigate("/", { replace: true });
    } catch (err) {
      setError(errorMessage(err));
      setPending(false);
    }
  }

  return (
    <main className="flex h-screen items-center justify-center bg-carbon-950 px-4 text-zinc-300">
      <section
        data-testid="change-password-page"
        className="w-full max-w-sm rounded border border-carbon-700 bg-carbon-900 p-6"
      >
        <h1 className="text-lg font-semibold text-zinc-100">Change password</h1>
        <p className="mt-1 text-xs text-zinc-500">Set a new password to continue.</p>

        <form className="mt-6 flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Current password
            <input
              type="password"
              name="current_password"
              autoComplete="current-password"
              required
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            New password
            <input
              type="password"
              name="new_password"
              autoComplete="new-password"
              required
              value={next}
              onChange={(e) => setNext(e.target.value)}
              className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Confirm new password
            <input
              type="password"
              name="confirm_password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
            />
          </label>

          {error !== null && (
            <p role="alert" className="text-xs text-red-400">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={pending}
            className="mt-2 rounded bg-accent px-3 py-2 text-sm font-medium text-carbon-950 transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending ? "Changing…" : "Change password"}
          </button>
        </form>
      </section>
    </main>
  );
}
