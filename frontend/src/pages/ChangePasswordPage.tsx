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
 * push a success toast → navigate to "/". Backend errors from the change call
 * itself (e.g. a wrong current password) render via the shared ``ErrorBanner``
 * and keep the user on the page; the post-success ``getMe()`` refresh is
 * best-effort — if it fails, the forced-gate flag is cleared on the cached
 * user instead, and it never presents as a change failure.
 *
 * All three inputs are wrapped in ``FormField`` for real label/control
 * association (audit UI_UX #5 — this page previously had zero aria
 * attributes). Client-side validation errors are field-specific and surface
 * through the relevant FormField's error slot; the backend/API error is a
 * panel-level outcome and surfaces through ``ErrorBanner`` instead. The
 * submit button shows a ``Spinner`` while pending.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ErrorBanner } from "../components/ErrorBanner";
import { FormField } from "../components/FormField";
import { Spinner } from "../components/Skeleton";
import { useUiStore } from "../stores/ui";
import { useChangePassword, validatePasswordChange } from "../hooks/useChangePassword";

/** Minimum length the backend enforces for a new password (mirrored client-side). */

interface FieldErrors {
  next?: string;
  confirm?: string;
}

export function ChangePasswordPage() {
  const pushToast = useUiStore((state) => state.pushToast);
  const navigate = useNavigate();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [apiError, setApiError] = useState<unknown>(null);
  const mutation = useChangePassword({ bestEffortRefresh: true });

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setFieldErrors({});
    setApiError(null);

    // Client-side guards run before any network call (defense-in-depth over the
    // backend's own min-length + the fact it has no confirm field).
    const validation = validatePasswordChange(next, confirm);
    if (Object.keys(validation).length) { setFieldErrors(validation); return; }
    try {
      await mutation.mutateAsync({ current, next });
    } catch (err) {
      setApiError(err);
      return;
    }
    pushToast("success", "Password changed.");
    navigate("/", { replace: true });
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
          <FormField label="Current password" required>
            {(controlProps) => (
              <input
                {...controlProps}
                type="password"
                name="current_password"
                autoComplete="current-password"
                required
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
              />
            )}
          </FormField>

          <FormField label="New password" required error={fieldErrors.next}>
            {(controlProps) => (
              <input
                {...controlProps}
                type="password"
                name="new_password"
                autoComplete="new-password"
                required
                value={next}
                onChange={(e) => setNext(e.target.value)}
                className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
              />
            )}
          </FormField>

          <FormField label="Confirm new password" required error={fieldErrors.confirm}>
            {(controlProps) => (
              <input
                {...controlProps}
                type="password"
                name="confirm_password"
                autoComplete="new-password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
              />
            )}
          </FormField>

          {apiError !== null && <ErrorBanner error={apiError} data-testid="change-password-error" />}

          <button
            type="submit"
            disabled={mutation.isPending}
            className="mt-2 flex items-center justify-center gap-2 rounded bg-accent px-3 py-2 text-sm font-medium text-carbon-950 transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {mutation.isPending && <Spinner aria-label="Changing password" />}
            {mutation.isPending ? "Changing…" : "Change password"}
          </button>
        </form>
      </section>
    </main>
  );
}
