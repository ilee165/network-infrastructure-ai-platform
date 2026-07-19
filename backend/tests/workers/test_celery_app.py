"""Celery app config: beat-DISPATCH-time report period computation (PR #166 F2).

Beat messages for the four cadence-scheduled reports used to carry only the
report ``kind``; the worker recomputed ``scheduled_period(cadence, now())`` at
EXECUTION time, so a redelivered or delayed-past-UTC-midnight tick could
target an entirely different period than the one beat actually meant to fire
(the period would then never be regenerated for real). The fix computes the
period bounds via ``celery.beat.BeatLazyFunc`` in ``beat_schedule`` — Celery's
own supported mechanism for evaluating task args/kwargs at DISPATCH time
(``Scheduler.apply_async``), not at worker execution time — and threads them
through as explicit message kwargs. The worker-side "a redelivered/delayed
tick still honors the dispatch-computed bounds" proof lives in
``tests/workers/test_report_tasks.py`` (the message, once dispatched, carries
fixed values no matter how late the worker executes it).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from celery.beat import BeatLazyFunc, _evaluate_entry_kwargs

from app.core.config import get_settings
from app.engines.reports.idempotency import scheduled_period
from app.workers import celery_app as celery_app_module
from app.workers.celery_app import celery_app

_REPORT_BEAT_ENTRIES: tuple[tuple[str, str], ...] = (
    ("report-generate-change", "report_change_cadence"),
    ("report-generate-compliance-posture", "report_compliance_posture_cadence"),
    ("report-generate-access-review", "report_access_review_cadence"),
    ("report-generate-audit-integrity", "report_audit_integrity_cadence"),
)


def _clock_at(instant: datetime) -> type:
    """A stand-in for the ``datetime`` class exposing only ``.now()``."""

    class _Clock:
        @staticmethod
        def now(tz: object = None) -> datetime:
            return instant

    return _Clock


def test_report_beat_entries_carry_lazy_period_bounds() -> None:
    """Every report beat entry's period kwargs are ``BeatLazyFunc`` — resolved
    by Celery beat's ``Scheduler.apply_async`` AT DISPATCH TIME on every tick,
    never a static tuple frozen at process-startup evaluation."""
    for name, _cadence_field in _REPORT_BEAT_ENTRIES:
        entry = celery_app.conf.beat_schedule[name]
        assert isinstance(entry["kwargs"]["period_start"], BeatLazyFunc)
        assert isinstance(entry["kwargs"]["period_end"], BeatLazyFunc)
        # The task's own positional kind arg is untouched (static, harmless).
        assert entry["args"]


def test_beat_dispatch_evaluates_the_period_at_the_dispatch_instant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Evaluating the entry's kwargs — exactly what ``Scheduler.apply_async``
    does on every tick via ``_evaluate_entry_kwargs`` — computes the period
    from the DISPATCH clock, never a later execution-time clock the worker
    might read instead."""
    dispatch_instant = datetime(2026, 7, 12, 23, 59, tzinfo=UTC)  # a Sunday
    monkeypatch.setattr(celery_app_module, "datetime", _clock_at(dispatch_instant))
    settings = get_settings()

    for name, cadence_field in _REPORT_BEAT_ENTRIES:
        entry = celery_app.conf.beat_schedule[name]
        resolved = _evaluate_entry_kwargs(entry["kwargs"])

        cadence = getattr(settings, cadence_field)
        expected_start, expected_end = scheduled_period(cadence, dispatch_instant)
        assert resolved["period_start"] == expected_start.isoformat()
        assert resolved["period_end"] == expected_end.isoformat()


def test_lazy_bounds_track_each_dispatch_instant_not_a_frozen_startup_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unlike a static tuple (evaluated once when the schedule dict is built
    at process start), the lazy bounds reflect whatever instant beat is
    ACTUALLY dispatching at on THIS tick — proven by resolving the same entry
    across two different simulated dispatch instants a week apart and getting
    two different periods, each matching that instant's own computation."""
    entry = celery_app.conf.beat_schedule["report-generate-change"]
    cadence = get_settings().report_change_cadence

    first_instant = datetime(2026, 7, 12, 23, 59, tzinfo=UTC)
    monkeypatch.setattr(celery_app_module, "datetime", _clock_at(first_instant))
    first = _evaluate_entry_kwargs(entry["kwargs"])

    second_instant = datetime(2026, 7, 20, 23, 59, tzinfo=UTC)
    monkeypatch.setattr(celery_app_module, "datetime", _clock_at(second_instant))
    second = _evaluate_entry_kwargs(entry["kwargs"])

    assert first != second
    assert first["period_end"] == scheduled_period(cadence, first_instant)[1].isoformat()
    assert second["period_end"] == scheduled_period(cadence, second_instant)[1].isoformat()
