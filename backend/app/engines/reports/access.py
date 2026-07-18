"""Per-kind RBAC role floors for report generation AND artifact download.

ADR-0053 §3 (PROPOSED, refinable by the Consultant role-floor item): change +
compliance-posture reports are **engineer+** (matching the existing on-demand
compliance endpoint floor); access-review + audit-integrity are **admin**
(user/PII surface; integrity-root attestation). The SAME floor is enforced at
the generation trigger and at the artifact download endpoint — a role change
between generation and download is honored at download time (no stale-authz
caching), and the Documentation-Agent tools enforce it against the invoking
user's bound role.
"""

from __future__ import annotations

from typing import Final

from app.core.security import Role
from app.models.reports import ReportKind

__all__ = ["ROLE_FLOORS", "kinds_visible_to", "required_role", "role_meets_floor"]

#: The pinned per-kind minimum role (ADR-0053 §3).
ROLE_FLOORS: Final[dict[ReportKind, Role]] = {
    ReportKind.CHANGE: Role.ENGINEER,
    ReportKind.COMPLIANCE_POSTURE: Role.ENGINEER,
    ReportKind.ACCESS_REVIEW: Role.ADMIN,
    ReportKind.AUDIT_INTEGRITY: Role.ADMIN,
}


def required_role(kind: ReportKind) -> Role:
    """The minimum role for *kind* (KeyError-free: every kind is pinned above)."""
    return ROLE_FLOORS[kind]


def role_meets_floor(role: Role | None, kind: ReportKind) -> bool:
    """True iff *role* satisfies the floor for *kind* (``None`` never does)."""
    if role is None:
        return False
    return role.can_act_as(ROLE_FLOORS[kind])


def kinds_visible_to(role: Role | None) -> frozenset[ReportKind]:
    """The report kinds whose floor *role* meets (deny-by-default on ``None``)."""
    return frozenset(kind for kind in ReportKind if role_meets_floor(role, kind))
