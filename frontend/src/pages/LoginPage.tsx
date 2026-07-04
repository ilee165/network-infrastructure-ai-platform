/**
 * LoginPage (Auth & Account UI, F3): public credential entry.
 *
 * Flow: submit ``username`` + ``password`` → ``login()`` (sets the refresh
 * cookie + returns the access token) → cache the token, then ``getMe()`` to
 * populate the store and flip status to "authed" → navigate to the path the
 * user was originally trying to reach (``location.state.from``, planted by
 * ``ProtectedRoute``) or "/".
 *
 * A failed login renders the backend ``ApiError`` detail (a single generic
 * "invalid username or password" — the backend never reveals which field was
 * wrong) via the shared ``ErrorBanner``, and leaves the store anonymous; the
 * submit button shows a ``Spinner`` and is disabled while the request is in
 * flight. An already-authenticated visitor is bounced away from /login
 * immediately.
 *
 * Both fields are wrapped in ``FormField`` for real label/control association
 * (audit UI_UX #5 — this page previously had zero aria attributes). The
 * credential error is a panel-level outcome, not per-field validation, so it
 * renders via ``ErrorBanner`` rather than a FormField error slot; login stays
 * inline-only (no toast) since it is a form-validation-shaped outcome, not a
 * background mutation the user could navigate away from.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { getMe, login } from "../api/auth";
import { ErrorBanner } from "../components/ErrorBanner";
import { FormField } from "../components/FormField";
import { Spinner } from "../components/Skeleton";
import { useAuthStore } from "../stores/auth";

/** Shape of the redirect origin ProtectedRoute stores in ``location.state``. */
interface FromState {
  from?: { pathname?: string };
}

export function LoginPage() {
  const status = useAuthStore((state) => state.status);
  const setAuth = useAuthStore((state) => state.setAuth);
  const setToken = useAuthStore((state) => state.setToken);
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);

  // Already signed in: never show the login form — return to the app.
  if (status === "authed") {
    const target = (location.state as FromState | null)?.from?.pathname ?? "/";
    return <Navigate to={target} replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      const { access_token } = await login(username, password);
      // Cache the token first so the immediate getMe() carries the Bearer header.
      setToken(access_token);
      const user = await getMe();
      setAuth(access_token, user);
      const target = (location.state as FromState | null)?.from?.pathname ?? "/";
      navigate(target, { replace: true });
    } catch (err) {
      setError(err);
      setPending(false);
    }
  }

  return (
    <main className="flex h-screen items-center justify-center bg-carbon-950 px-4 text-zinc-300">
      <section
        data-testid="login-page"
        className="w-full max-w-sm rounded border border-carbon-700 bg-carbon-900 p-6"
      >
        <h1 className="text-lg font-semibold text-zinc-100">Sign in</h1>
        <p className="mt-1 text-xs text-zinc-500">NetOps Console</p>

        <form className="mt-6 flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
          <FormField label="Username" required>
            {(controlProps) => (
              <input
                {...controlProps}
                type="text"
                name="username"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
              />
            )}
          </FormField>

          <FormField label="Password" required>
            {(controlProps) => (
              <input
                {...controlProps}
                type="password"
                name="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="rounded border border-carbon-700 bg-carbon-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-accent"
              />
            )}
          </FormField>

          {error !== null && <ErrorBanner error={error} data-testid="login-error" />}

          <button
            type="submit"
            disabled={pending}
            className="mt-2 flex items-center justify-center gap-2 rounded bg-accent px-3 py-2 text-sm font-medium text-carbon-950 transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending && <Spinner aria-label="Signing in" />}
            {pending ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}
