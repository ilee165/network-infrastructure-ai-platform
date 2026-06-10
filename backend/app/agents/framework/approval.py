"""Approval gate for state-changing agent tools (ADR-0003, ADR-0011).

Brief section 5: any state-changing tool call creates a ``ChangeRequest`` and
blocks until human approval — no exceptions. M0 ships the *gate contract*
only: :class:`ApprovalGate` is the seam, and :class:`DenyAllGate` is the
secure-by-default implementation that denies everything. M5 wires the real
ChangeRequest-backed gate (``services/change_mgmt.py``); until then a
STATE_CHANGING tool can only execute if a test (or future milestone code)
explicitly injects an approving gate.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import NetOpsError


class ApprovalRequiredError(NetOpsError):
    """A state-changing tool was invoked without an approved ChangeRequest.

    Extends the :class:`~app.core.errors.NetOpsError` hierarchy so the FastAPI
    handlers render it as an RFC 7807 problem (403: the caller is
    authenticated but the action is forbidden until a human approves it).
    """

    status_code = 403
    title = "Approval Required"
    slug = "approval-required"


class ApprovalRequest(BaseModel):
    """What an agent is asking permission to do.

    M5 extends this into a full ChangeRequest payload (target devices,
    rendered diff, rollback plan — brief section 7); M0 carries the minimum
    needed for an auditable gate decision.
    """

    model_config = ConfigDict(frozen=True)

    #: Registered tool name (matches the audit event's ``tool_name``).
    tool_name: str
    #: Validated tool arguments as they would be executed.
    arguments: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    """The gate's verdict for one :class:`ApprovalRequest`."""

    model_config = ConfigDict(frozen=True)

    #: ``True`` only when a human approved the change (M5: via ChangeRequest).
    approved: bool
    #: Human-readable explanation, surfaced in errors and audit events.
    reason: str | None = None
    #: M5: the ChangeRequest this decision came from; always ``None`` at M0.
    change_request_id: str | None = None


@runtime_checkable
class ApprovalGate(Protocol):
    """Decides whether a state-changing tool call may proceed.

    Implementations must be side-effect-safe to call repeatedly: the M5
    ChangeRequest gate blocks (graph interrupt) until a human acts, while the
    M0 :class:`DenyAllGate` returns immediately.
    """

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return the decision for *request*; never raise for a plain denial."""
        ...


class DenyAllGate:
    """Secure-by-default gate: every request is denied.

    This is the only gate shipped at M0 — there is deliberately no
    "allow all" counterpart in production code (CLAUDE.md: human approval
    for changes). M5 replaces injection sites with the ChangeRequest gate.
    """

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Deny *request* with an explanation pointing at the M5 workflow."""
        return ApprovalDecision(
            approved=False,
            reason=(
                f"tool '{request.tool_name}' is state-changing and requires an approved "
                "ChangeRequest; the approval workflow ships in M5"
            ),
        )
