/**
 * ProtectedRoute (Auth & Account UI, F2): the app-wide authentication gate.
 *
 * Wraps the entire protected route tree. Behaviour by auth ``status``:
 *  - ``loading`` — the boot refresh has not resolved yet; render a neutral
 *    loader. Never redirect (we do not yet know whether the user is signed in)
 *    and never flash the protected tree.
 *  - ``anon`` — redirect to ``/login``, preserving the path the user was trying
 *    to reach (in ``location.state.from``) so the login flow can return them.
 *  - ``authed`` with ``user.must_change_password`` — force ``/change-password``
 *    before anything else is reachable (unless already there).
 *  - otherwise — render the nested ``<Outlet/>``.
 *
 * The redirect uses ``replace`` so the gate never pollutes the history stack.
 */

import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuthStore } from "../stores/auth";

/** Path that hosts the (also forced) password-change flow. */
const CHANGE_PASSWORD_PATH = "/change-password";

/** Neutral full-screen loader shown while the boot refresh is in flight. */
function AuthLoading() {
  return (
    <div
      data-testid="auth-loading"
      role="status"
      aria-live="polite"
      className="flex h-screen items-center justify-center bg-carbon-950 text-zinc-400"
    >
      <span className="font-mono text-xs uppercase tracking-widest">Loading…</span>
    </div>
  );
}

export function ProtectedRoute() {
  const status = useAuthStore((state) => state.status);
  const mustChangePassword = useAuthStore((state) => state.user?.must_change_password ?? false);
  const location = useLocation();

  if (status === "loading") {
    return <AuthLoading />;
  }

  if (status === "anon") {
    // Preserve the intended destination so login can return the user to it.
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // Authed: a user who still owes a password change is pinned to the change
  // flow until it clears — nothing else in the app is reachable first.
  if (mustChangePassword && location.pathname !== CHANGE_PASSWORD_PATH) {
    return <Navigate to={CHANGE_PASSWORD_PATH} replace />;
  }

  return <Outlet />;
}
