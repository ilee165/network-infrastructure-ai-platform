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
from pathlib import Path
from typing import Any

import pytest
from celery.beat import BeatLazyFunc, _evaluate_entry_kwargs
from prometheus_client import CollectorRegistry
from prometheus_client.multiprocess import MultiProcessCollector

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


# ---------------------------------------------------------------------------
# Worker metrics-server multiprocess mode (PR #166 F4)
# ---------------------------------------------------------------------------


def test_multiprocess_registry_is_none_without_the_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No ``PROMETHEUS_MULTIPROC_DIR`` -> the caller falls back to the default
    ``REGISTRY`` (the existing single-process dev/test behavior)."""
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    assert celery_app_module._multiprocess_registry() is None


def test_multiprocess_registry_builds_a_multiprocess_collector_when_dir_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #166 F4 minimum test: the metrics-server registry uses
    ``MultiProcessCollector`` (never the default single-process ``REGISTRY``)
    when ``PROMETHEUS_MULTIPROC_DIR`` is set — this is what makes prefork
    CHILD-process metric mutations visible to the parent's ``/metrics`` server."""
    directory = tmp_path / "multiproc"
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(directory))

    registry = celery_app_module._multiprocess_registry()

    assert isinstance(registry, CollectorRegistry)
    assert directory.is_dir()  # created eagerly so a scrape never 404s on it
    collectors = list(registry._collector_to_names)
    assert len(collectors) == 1
    assert isinstance(collectors[0], MultiProcessCollector)


def test_start_worker_metrics_server_passes_the_multiprocess_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the dir is set, ``start_http_server`` is called WITH the
    multiprocess registry — not the implicit default ``REGISTRY``."""
    directory = tmp_path / "multiproc"
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(directory))
    calls: list[dict[str, Any]] = []

    def _fake_start_http_server(port: int, registry: Any = None, **kwargs: Any) -> None:
        calls.append({"port": port, "registry": registry})

    monkeypatch.setattr("prometheus_client.start_http_server", _fake_start_http_server)

    result = celery_app_module.start_worker_metrics_server(9999)

    assert result is True
    assert len(calls) == 1
    assert calls[0]["port"] == 9999
    assert isinstance(calls[0]["registry"], CollectorRegistry)


def test_start_worker_metrics_server_uses_default_registry_without_the_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the env var, ``start_http_server`` is called with NO registry
    kwarg — the existing single-process default-``REGISTRY`` behavior."""
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    calls: list[dict[str, Any]] = []

    def _fake_start_http_server(port: int, **kwargs: Any) -> None:
        calls.append({"port": port, "kwargs": kwargs})

    monkeypatch.setattr("prometheus_client.start_http_server", _fake_start_http_server)

    result = celery_app_module.start_worker_metrics_server(9998)

    assert result is True
    assert len(calls) == 1
    assert calls[0]["kwargs"] == {}


def test_worker_init_seeds_last_success_gauges(monkeypatch: pytest.MonkeyPatch) -> None:
    """``worker_init`` also re-hydrates the report-engine staleness gauges
    (PR #166 F6) — the worker boots BOTH the metrics server AND the seed."""
    monkeypatch.setattr(celery_app_module, "start_worker_metrics_server", lambda port: True)
    calls: list[bool] = []

    import app.workers.tasks.reports as tasks_reports_module

    monkeypatch.setattr(
        tasks_reports_module, "seed_last_success_gauges", lambda: calls.append(True)
    )

    celery_app_module._start_metrics_on_worker_init()

    assert calls == [True]


# ---------------------------------------------------------------------------
# Prefork-child mmap cleanup on exit (PR #166 F4)
# ---------------------------------------------------------------------------


def test_mark_prefork_child_dead_calls_multiprocess_cleanup_when_dir_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "multiproc"
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(directory))
    calls: list[int] = []
    monkeypatch.setattr(
        "prometheus_client.multiprocess.mark_process_dead", lambda pid: calls.append(pid)
    )

    celery_app_module._mark_prefork_child_dead(pid=1234)

    assert calls == [1234]


def test_mark_prefork_child_dead_is_a_noop_without_the_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    # Must not raise even though no multiprocess cleanup is possible.
    celery_app_module._mark_prefork_child_dead(pid=1234)
