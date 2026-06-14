/**
 * RoleRoute (Auth & Account UI, F2): a minimum-role gate over a nested route tree.
 *
 * Defense-in-depth ONLY. The backend ``require_role`` (see
 * ``backend/app/api/deps.py``) is the source of truth for every protected
 * endpoint; this guard merely hides admin surfaces in the UI so a lower-rank
 * user never sees a control they cannot use. It never grants access on its own.
 *
 * Rank order mirrors ADR-0010: ``viewer < operator < engineer < admin``. A user
 * at or above the *minimum* sees the nested ``<Outlet/>``; below it (or with an
 * unknown role, which ranks below everything) they get a forbidden view.
 *
 * This guard assumes it sits *inside* ``ProtectedRoute`` — by the time it
 * renders, ``status`` is ``authed`` and ``user`` is non-null.
 */

import { Outlet } from "react-router-dom";
import { useAuthStore } from "../stores/auth";
import { hasMinimumRole } from "../stores/roles";
import type { Role } from "../stores/roles";

interface RoleRouteProps {
  /** Lowest role permitted to see the nested routes. */
  minimum: Role;
}

/** Forbidden view shown when the current user is below the required rank. */
function Forbidden() {
  return (
    <div
      data-testid="forbidden"
      role="alert"
      className="flex flex-col items-center justify-center gap-2 py-24 text-center"
    >
      <p className="font-mono text-xs uppercase tracking-widest text-accent">403</p>
      <h2 className="text-lg font-semibold text-zinc-100">Forbidden</h2>
      <p className="max-w-sm text-sm text-zinc-500">
        You do not have permission to view this area. Ask an administrator if you need access.
      </p>
    </div>
  );
}

export function RoleRoute({ minimum }: RoleRouteProps) {
  const role = useAuthStore((state) => state.user?.role);
  if (!hasMinimumRole(role, minimum)) {
    return <Forbidden />;
  }
  return <Outlet />;
}
