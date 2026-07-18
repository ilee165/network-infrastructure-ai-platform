"""Deterministic run identity + scheduled-period computation (ADR-0053 §2).

Generation is idempotent per ``(kind, period)``: the run's PRIMARY KEY is a
UUID derived from those coordinates (the ``config.nightly_backup`` slot-UUID
precedent), so a beat delivery, a Celery redelivery, and an on-demand request
for the same period all collide on the same row — the claim-row guard in
``app.workers.tasks.reports`` classifies the conflict instead of
double-generating.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.models.reports import ReportKind

__all__ = ["deterministic_run_id", "scheduled_period"]


def deterministic_run_id(
    kind: ReportKind | str, period_start: datetime, period_end: datetime
) -> UUID:
    """Derive the stable run UUID for ``(kind, period)`` (ADR-0053 §2).

    SHA-256 over the canonical token; first 16 bytes as an opaque UUID (not
    RFC-4122 — a name-derived claim token, same as the backup slot UUID).
    """
    kind_value = kind.value if isinstance(kind, ReportKind) else kind
    token = (
        f"reports.generate:{kind_value}:"
        f"{period_start.astimezone(UTC).isoformat()}:{period_end.astimezone(UTC).isoformat()}"
    )
    return UUID(bytes=hashlib.sha256(token.encode()).digest()[:16])


def scheduled_period(cadence: str, now: datetime) -> tuple[datetime, datetime]:
    """The PRECEDING full period for a scheduled run firing at *now* (UTC).

    * ``daily``   → the previous UTC calendar day;
    * ``weekly``  → the 7 UTC days ending at today's UTC midnight;
    * ``monthly`` → the previous UTC calendar month.

    Deterministic per fire-date so every redelivery of the same beat tick maps
    to the same ``(period_start, period_end)`` — and therefore the same claim
    row (ADR-0053 §2).

    Raises:
        ValueError: on an unknown cadence token (settings are ``Literal``-typed,
            so this only trips on a programming error).
    """
    at = now.astimezone(UTC)
    midnight = at.replace(hour=0, minute=0, second=0, microsecond=0)
    if cadence == "daily":
        return midnight - timedelta(days=1), midnight
    if cadence == "weekly":
        return midnight - timedelta(days=7), midnight
    if cadence == "monthly":
        first_of_this_month = midnight.replace(day=1)
        last_month_end = first_of_this_month
        prev_last_day = first_of_this_month - timedelta(days=1)
        return prev_last_day.replace(day=1), last_month_end
    raise ValueError(f"unknown report cadence {cadence!r}; expected daily|weekly|monthly")
