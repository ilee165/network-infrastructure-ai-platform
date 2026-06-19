"""ChangeRequest lifecycle service package (M5 task #3, ADR-0020).

Exposes :class:`ChangeRequestService`, the single server-side owner of the
ChangeRequest state machine: guarded transitions, the **primary** four-eyes
guard (approver != requester), engineer+ RBAC, admin-only four-eyes waiver,
post-submit immutability of ``requester_id`` / ``four_eyes_required``, and an
audited entry for every transition. Agents reach this service only through the
typed tool wrappers in ``agents/framework`` (REPO-STRUCTURE §5) — never
directly.

The post-approval ``mark_*`` handoffs require the verified
:data:`AUTOMATION_PRINCIPAL` (ADR-0020 §1/§2); the Automation Agent service
(M5 Wave 4) is the only caller that holds it.

    from app.services.change_requests import ChangeRequestService
"""

from app.services.change_requests.service import (
    AUTOMATION_PRINCIPAL,
    AutomationPrincipal,
    ChangeRequestService,
)

__all__ = ["AUTOMATION_PRINCIPAL", "AutomationPrincipal", "ChangeRequestService"]
