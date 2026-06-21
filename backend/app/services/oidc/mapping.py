"""IdP group → RBAC role mapping with deny-default (ADR-0028 §4).

The single security property here is **deny-default**: a federated user gets a
platform role only if at least one of their IdP groups is in the configured
``group → role`` map. A user with no groups, or whose groups map to nothing,
gets **no role** (``None``) — which the caller turns into "no session minted",
never a silent ``viewer`` fallback. When several groups map, the union collapses
to the **highest** matching role (the ``viewer < operator < engineer < admin``
total order). ``admin`` via OIDC is only honoured when explicitly opted in;
otherwise it is capped at ``engineer`` so production admin stays break-glass-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from app.core.errors import NetOpsError
from app.core.security import Role


class RoleMappingError(NetOpsError):
    """A ``group → role`` map references a name that is not an RBAC role.

    A misconfigured map is a deployment fault, surfaced as a 500 rather than
    silently dropping the entry (which could quietly under- or over-privilege).
    """

    status_code = 500
    title = "OIDC Role Map Misconfigured"
    slug = "oidc-role-map"


def map_groups_to_role(
    groups: Iterable[str] | None,
    group_role_map: Mapping[str, str],
    *,
    allow_admin: bool,
) -> Role | None:
    """Resolve IdP *groups* to the highest mapped platform :class:`Role`, or ``None``.

    Returns ``None`` (deny) when *groups* is absent/empty or none of them are in
    *group_role_map* — the caller must mint no session in that case (ADR-0028
    §4 deny-default). When ``allow_admin`` is false an ``admin`` mapping is
    capped at ``engineer`` so OIDC cannot grant production admin unless opted in.

    Raises:
        RoleMappingError: If the map points a group at a non-RBAC role name.
    """
    if not groups:
        return None
    group_set = set(groups)
    best: Role | None = None
    for group, role_name in group_role_map.items():
        if group not in group_set:
            continue
        role = Role.from_name(role_name)
        if role is None:
            raise RoleMappingError(f"unknown role {role_name!r} in OIDC group map")
        if role is Role.ADMIN and not allow_admin:
            role = Role.ENGINEER  # break-glass-only admin: cap OIDC at engineer.
        if best is None or role.rank > best.rank:
            best = role
    return best
