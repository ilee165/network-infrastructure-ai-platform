"""Compliance evaluation history (P4 W3-T1; ADR-0053 §7.2).

The M4 compliance engine (ADR-0018) evaluates on demand and persists nothing —
so the PRODUCTION.md §7 "trend over time" requirement is unimplementable without
run history. These two tables persist that history, populated by the daily
``reports.compliance_sweep`` beat task (ADR-0053 §2).

**Secret-free by construction (ADR-0053 §6 layer 3):** findings persist
status/severity ONLY — deliberately NO evidence-excerpt column, because excerpts
can quote config text and config text is secret-bearing (ADR-0017). Live
drill-down to an excerpt stays on the existing on-demand engineer+ endpoint
(``GET /config-snapshots/{device_id}/compliance``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin


class ComplianceSweepTrigger(StrEnum):
    """How a persisted compliance evaluation run was triggered (ADR-0053 §7.2)."""

    SWEEP = "sweep"
    ON_DEMAND = "on_demand"


class ComplianceRun(UuidPkMixin, TimestampMixin, Base):
    """One persisted compliance evaluation run (ADR-0053 §7.2)."""

    __tablename__ = "compliance_runs"
    __table_args__ = (Index("ix_compliance_runs_executed_at", "executed_at"),)

    executed_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer(), nullable=False)
    #: Device ids in scope for this run (JSON list of UUID strings) — scope
    #: metadata only, never device config content.
    device_scope: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)

    findings: Mapped[list[ComplianceRunFinding]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ComplianceRunFinding(UuidPkMixin, Base):
    """One per-device-per-rule outcome of a compliance run (ADR-0053 §7.2).

    Status/severity ONLY — no evidence excerpt column exists, by design
    (ADR-0053 §6 layer 3); the trend report aggregates these rows.
    """

    __tablename__ = "compliance_run_findings"
    __table_args__ = (Index("ix_compliance_run_findings_device_id", "device_id"),)

    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: ``pass`` | ``violation`` | ``skipped`` (ADR-0018 §5 vocabulary).
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)

    run: Mapped[ComplianceRun] = relationship(back_populates="findings")
