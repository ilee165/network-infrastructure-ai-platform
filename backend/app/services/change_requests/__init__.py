"""ChangeRequest lifecycle service package (M5 task #3, ADR-0020).

Exposes :class:`ChangeRequestService`, the single server-side owner of the
ChangeRequest state machine: guarded transitions, the **primary** four-eyes
guard (approver != requester), engineer+ RBAC, post-submit immutability of
``requester_id`` / ``four_eyes_required``, and an audited entry for every
transition. Agents reach this service only through the typed tool wrappers in
``agents/framework`` (REPO-STRUCTURE §5) — never directly.

    from app.services.change_requests import ChangeRequestService
"""

from app.services.change_requests.service import ChangeRequestService

__all__ = ["ChangeRequestService"]
