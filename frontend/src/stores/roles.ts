/**
 * RBAC role ranking (Auth & Account UI, F2): the frontend mirror of the
 * ADR-0010 rank order ``viewer < operator < engineer < admin``.
 *
 * Pure, React-free helpers so they can be shared by route guards
 * (``RoleRoute``) and the shell (``Layout``) without dragging in component
 * concerns. These power *defense-in-depth* UI gating only — the backend
 * ``require_role`` (``backend/app/api/deps.py``) remains the source of truth.
 */

/** The four RBAC roles, narrowest to widest. */
export type Role = "viewer" | "operator" | "engineer" | "admin";

/** ADR-0010 rank order; higher rank passes every check at or below its own. */
const ROLE_RANKS: Record<Role, number> = {
  viewer: 0,
  operator: 1,
  engineer: 2,
  admin: 3,
};

/** Rank of a role *name*; unknown / missing names rank below the lowest role. */
export function rankOf(role: string | null | undefined): number {
  if (role === null || role === undefined) {
    return -1;
  }
  return role in ROLE_RANKS ? ROLE_RANKS[role as Role] : -1;
}

/** Whether *role* meets or exceeds the *minimum* required rank. */
export function hasMinimumRole(role: string | null | undefined, minimum: Role): boolean {
  return rankOf(role) >= ROLE_RANKS[minimum];
}
