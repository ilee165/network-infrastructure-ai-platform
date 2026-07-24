"""ChangeRequest spine + approval history (M5; ADR-0020, brief §7, D11).

The persistent ChangeRequest is the single spine for every state-changing
action (config restore/deploy, DDI record add/modify/delete). M5 makes
CLAUDE.md's "Human approval for changes" + "Audit everything" durable.

Aggregates:

- :class:`ChangeRequest` — one proposed change and its lifecycle state
  (``draft → pending_approval → approved → executing → completed | failed →
  rolled_back``, ADR-0020 §1). The execution inputs an approver reviews and that
  run verbatim — ``payload`` (the exact diff/API calls), ``target_refs`` (device
  ids / DDI object refs) and ``rollback_plan`` (ADR-0021 baseline/inverse spec) —
  ride in JSONB, frozen at submit so what executes is what was approved (no
  approve-then-swap TOCTOU, ADR-0020 §2). ``before_state`` / ``after_state`` JSONB
  ride alongside as the audited diff (ADR-0020 §4) — what changed, distinct from
  the applied ``payload``. ``four_eyes_required`` defaults to **true** (secure by
  default); ``requester_id`` is a real FK to ``users``; ``generating_session_id``
  is a real FK to ``agent_sessions`` (non-partitioned, nullable for human-authored
  CRs); ``reasoning_trace_id`` links the agent run that authored the CR.
- :class:`Approval` — one append-only approve/reject *decision* per row (full
  history with comments, not a mutable column — ADR-0020 alt #2). ``actor_id``
  is a real FK to ``users``; ``change_request_id`` a real FK to the CR.

Four-eyes (approver != requester) is enforced server-side in the ChangeRequest
service transition guard (M5 task #3) and — defense-in-depth — by a PostgreSQL
*constraint trigger* declared in migration 0007 (it spans two tables, so a
single-row CHECK cannot express it). That trigger is **conditional on
``four_eyes_required``**: it raises only when the CR has ``four_eyes_required =
true``, so the documented disabled-mode self-approval stays reachable (and is
still recorded as a distinct, audited row). The model intentionally carries no
DB CHECK for this; the trigger is migration DDL (PostgreSQL-only) covered by the
``integration``-marked migration test in both the enabled and disabled paths.

Design decision (fixed): ``requester_id`` / ``actor_id`` target the
non-partitioned ``users`` table and so keep real DB-level FKs.
``reasoning_trace_id`` is a plain indexed UUID with **no FK** — ``reasoning_traces``
is range-partitioned and a PostgreSQL FK to it must include the partition key
(``created_at``); the same posture as ``audit_log.reasoning_trace_id`` and the
``raw_artifact_id`` pattern. Linkage integrity is enforced by the service +
tests, not a DB constraint.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Enum as SaEnum
from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin, utcnow

__all__ = [
    "Approval",
    "ApprovalDecision",
    "ChangeRequest",
    "ChangeRequestKind",
    "ChangeRequestState",
]


class ChangeRequestState(StrEnum):
    """Lifecycle of a ChangeRequest (ADR-0020 §1).

    Terminal: ``completed``, ``rolled_back``. ``failed`` is non-terminal — it
    transitions to ``rolled_back`` once the structured rollback (ADR-0021)
    completes; a failed CR whose rollback also fails stays ``failed`` and raises
    an operator alert (never silently closed).
    """

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ChangeRequestKind(StrEnum):
    """What class of state-changing action a CR proposes (ADR-0020 §2).

    Persisted as VARCHAR(32) via :func:`_wire_enum` (``native_enum=False``, no
    CHECK constraint — migration 0007), so adding a new member is a code-only
    change: no Alembic migration is required as long as the value fits in 32
    chars. ``security_remediation`` (P2 W3-T1, ADR-0037 §4) is such an addition —
    a Security-Agent remediation draft, gate-routed exactly like ``ddi_record``.
    """

    CONFIG = "config"
    DDI_RECORD = "ddi_record"
    REPORT_GENERATION = "report_generation"
    SECURITY_REMEDIATION = "security_remediation"


class ApprovalDecision(StrEnum):
    """One human decision on a CR — an append-only row, not a mutable column."""

    APPROVE = "approve"
    REJECT = "reject"


def _wire_enum(enum_cls: type[StrEnum], *, length: int = 32) -> SaEnum:
    """Portable enum column persisting StrEnum *values* as VARCHAR.

    ``native_enum=False`` keeps SQLite/Postgres DDL identical and avoids Postgres
    ``CREATE TYPE`` churn; values (not member names) go on the wire. Mirrors
    ``app.models.agents._wire_enum``.
    """
    return SaEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda enum_type: [member.value for member in enum_type],
    )


class ChangeRequest(UuidPkMixin, TimestampMixin, Base):
    """A proposed state-changing action and its guarded lifecycle (ADR-0020).

    ``payload`` (the exact diff/API calls to apply), ``target_refs`` (device ids /
    DDI object refs) and ``rollback_plan`` (ADR-0021 baseline/inverse spec) carry
    the change an approver reviews and the executor applies verbatim; they are
    frozen at submit and immutable through approval/execution (re-editing requires
    ``reject → draft`` + a fresh submit) so what executes is what was approved.
    ``before_state`` / ``after_state`` are the audited diff (ADR-0020 §4) — what
    changed — kept alongside the applied ``payload``. ``four_eyes_required``
    defaults to ``True`` — the secure default that keeps the DB four-eyes
    constraint trigger in force. ``generating_session_id`` is a real FK to the
    ``agent_sessions`` row that authored the CR (nullable for human-authored CRs).
    """

    __tablename__ = "change_requests"

    state: Mapped[ChangeRequestState] = mapped_column(
        _wire_enum(ChangeRequestState), nullable=False, default=ChangeRequestState.DRAFT, index=True
    )
    kind: Mapped[ChangeRequestKind] = mapped_column(_wire_enum(ChangeRequestKind), nullable=False)
    requester_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    # Real FK → agent_sessions (non-partitioned, so a real DB FK); nullable for
    # human-authored CRs that did not originate from an agent run (ADR-0020 §2).
    generating_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_sessions.id"), index=True
    )
    # Frozen-at-submit execution inputs (ADR-0020 §2, ADR-0021 §2/§3): the payload
    # the approver reviewed and the executor renders verbatim, the target device /
    # DDI refs, and the rollback plan the Automation Agent executor reads.
    target_refs: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    rollback_plan: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    # Audited diff (ADR-0020 §4): what changed, distinct from the applied payload.
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    four_eyes_required: Mapped[bool] = mapped_column(nullable=False, default=True)
    # Plain indexed UUID, NO FK: reasoning_traces is range-partitioned (see the
    # module docstring / audit_log.reasoning_trace_id precedent). Nullable for
    # human-authored CRs that did not originate from an agent run.
    reasoning_trace_id: Mapped[uuid.UUID | None] = mapped_column(index=True)


class Approval(UuidPkMixin, Base):
    """One append-only approve/reject decision on a :class:`ChangeRequest`.

    A history table (not a mutable column on the CR) so every decision — including
    rejections — and its comment survive (ADR-0020 alt #2). The four-eyes rule
    (no ``approve`` row where ``actor_id == change_requests.requester_id`` when
    that CR's ``four_eyes_required`` is true) is enforced by the service guard
    and the DB constraint trigger in migration 0007 — not a column constraint
    here. ``created_at`` is the decision timestamp; there is no ``updated_at``
    because a decision is immutable (mirrors ``RefreshSession``).
    """

    __tablename__ = "approvals"

    change_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("change_requests.id"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    decision: Mapped[ApprovalDecision] = mapped_column(_wire_enum(ApprovalDecision), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
