"""Deterministic run-id timezone semantics (P4 W3-T1 fix; ADR-0053 §2).

Regression for the naive-datetime divergence: ``deterministic_run_id`` MUST pin
a naive datetime as UTC (mirroring the worker's ``_parse_utc``), never interpret
it as host-local time — otherwise the API/agent-tool run id and the worker's
claim-row id diverge on any non-UTC host and clients poll a phantom run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from app.engines.reports import coerce_utc, deterministic_run_id, scheduled_period
from app.models.reports import ReportKind

_NAIVE_START = datetime(2026, 7, 1)
_NAIVE_END = datetime(2026, 7, 8)


class _NonUtcHostNaive(datetime):
    """Naive datetime whose ``astimezone`` simulates a UTC-5 host.

    Guarantees the regression bites even when the test host itself runs UTC
    (CI): any implementation that reaches ``astimezone`` on a NAIVE value gets
    the shifted host-local interpretation instead of the pinned-UTC one.
    """

    def astimezone(self, tz: timezone | None = None) -> datetime:  # type: ignore[override]
        if self.tzinfo is not None:
            return datetime.astimezone(self, tz)
        simulated = datetime(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.microsecond,
            tzinfo=timezone(timedelta(hours=-5)),
        )
        return simulated.astimezone(tz)


def test_naive_period_matches_aware_utc_period() -> None:
    """A naive period and the same wall clock with tzinfo=UTC share one run id."""
    naive_id = deterministic_run_id(ReportKind.CHANGE, _NAIVE_START, _NAIVE_END)
    aware_id = deterministic_run_id(
        ReportKind.CHANGE,
        _NAIVE_START.replace(tzinfo=UTC),
        _NAIVE_END.replace(tzinfo=UTC),
    )
    assert naive_id == aware_id


def test_naive_period_is_pinned_utc_not_host_local() -> None:
    """Naive input is pinned as UTC even on a simulated non-UTC host."""
    host_local_start = _NonUtcHostNaive(2026, 7, 1)
    host_local_end = _NonUtcHostNaive(2026, 7, 8)
    assert deterministic_run_id(
        ReportKind.CHANGE, host_local_start, host_local_end
    ) == deterministic_run_id(
        ReportKind.CHANGE,
        _NAIVE_START.replace(tzinfo=UTC),
        _NAIVE_END.replace(tzinfo=UTC),
    )


def test_aware_non_utc_period_is_converted_to_utc() -> None:
    """An aware non-UTC period maps to the id of its UTC equivalent."""
    plus_two = timezone(timedelta(hours=2))
    assert deterministic_run_id(
        ReportKind.CHANGE,
        datetime(2026, 7, 1, 2, tzinfo=plus_two),
        datetime(2026, 7, 8, 2, tzinfo=plus_two),
    ) == deterministic_run_id(
        ReportKind.CHANGE,
        datetime(2026, 7, 1, 0, tzinfo=UTC),
        datetime(2026, 7, 8, 0, tzinfo=UTC),
    )


def test_coerce_utc_pins_naive_and_converts_aware() -> None:
    assert coerce_utc(_NAIVE_START) == _NAIVE_START.replace(tzinfo=UTC)
    assert coerce_utc(datetime(2026, 7, 1, 2, tzinfo=timezone(timedelta(hours=2)))) == datetime(
        2026, 7, 1, 0, tzinfo=UTC
    )


def test_scheduled_period_pins_naive_now_as_utc() -> None:
    """Class sweep: ``scheduled_period`` shares the pinned-UTC naive semantics."""
    # 20:30 naive: a UTC-5 host-local interpretation crosses into the next UTC
    # day (01:30Z on the 16th), flipping the derived daily period — the pinned
    # -UTC semantics keep it on the 15th.
    naive_now = _NonUtcHostNaive(2026, 7, 15, 20, 30)
    aware_now = datetime(2026, 7, 15, 20, 30, tzinfo=UTC)
    assert scheduled_period("daily", naive_now) == scheduled_period("daily", aware_now)
