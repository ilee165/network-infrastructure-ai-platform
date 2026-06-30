"""The audit→SIEM export pipeline loop (ADR-0045 §2/§3).

One :func:`export_cycle` is the testable unit: it reads a bounded batch of committed
``audit_log`` rows after the durable cursor (``seq`` order, NULL-``seq`` excluded),
formats each with the selected transport, delivers the batch to the sink, and — ONLY
on a clean sink ACK — advances the durable cursor and recomputes the export-lag
gauge. A sink failure leaves the cursor un-advanced (the rows stay committed in
``audit_log``, the backlog + lag grow, nothing is dropped — ADR-0045 §3) and is
re-tried on the next cycle.

:func:`run_export_loop` is the long-running driver (a Deployment, not a CronJob —
the export is continuous near-real-time streaming): cycle, then either continue
immediately (a full batch ⇒ more backlog to drain) or sleep the poll interval (caught
up), with capped backoff after a sink failure. It is strictly DOWNSTREAM of the audit
DB commit (ADR-0045 §3): it opens its OWN sessions and never touches the action
transaction that wrote the audit row, so a SIEM outage can never block or fail an
audited action's commit.

The lag SLI (ADR-0045 §3, the §6 p95 < 60 s SLO): ``now − commit_ts of the last
exported row``. When the cursor has a ``last_exported_commit_at`` the gauge is
``now − that``; with nothing exported yet (or fully caught up to head) the lag is
~0. A held-down sink freezes the cursor, so the gauge climbs with wall-clock — the
operator-visible "export stalled, no audit loss" signal W3-T3 alerts on.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.metrics import set_audit_export_lag
from app.models.mixins import utcnow
from app.services.audit.export.cursor import (
    advance_cursor,
    current_exported_seq,
    load_cursor,
    read_unexported,
)
from app.services.audit.export.formatters import format_cef, format_https_json, format_syslog
from app.services.audit.export.record import ExportRecord
from app.services.audit.export.sinks import Sink, SinkDeliveryError

_logger = get_logger(__name__)

#: Map the configured format token → the pure formatter (ADR-0045 §1). ``syslog`` and
#: ``cef`` both ride the TLS syslog sink; ``https-json`` the HTTPS sink.
_FORMATTERS: dict[str, Callable[[ExportRecord], str]] = {
    "syslog": format_syslog,
    "cef": format_cef,
    "https-json": format_https_json,
}


@dataclass(frozen=True, slots=True)
class CycleResult:
    """Outcome of one :func:`export_cycle` (the test asserts on this).

    ``delivered`` is the count ACKed + cursor-advanced this cycle. ``batch_full`` is
    True when the read returned a full batch (more backlog likely → drive the next
    cycle immediately). ``lag_seconds`` is the export-lag SLI after this cycle.
    ``failed`` is True when the sink raised (cursor NOT advanced, rows re-tried next
    cycle — never dropped).
    """

    delivered: int
    batch_full: bool
    lag_seconds: float
    failed: bool


def _format_batch(records: list[ExportRecord], *, fmt: str) -> list[str]:
    """Serialize *records* with the selected transport formatter (ADR-0045 §1)."""
    formatter = _FORMATTERS[fmt]
    return [formatter(record) for record in records]


async def _compute_lag_seconds(session: AsyncSession) -> float:
    """Return ``now − last_exported_commit_ts`` (0 when nothing exported, ADR-0045 §3)."""
    cursor = await load_cursor(session)
    if cursor is None or cursor.last_exported_commit_at is None:
        return 0.0
    delta = (utcnow() - cursor.last_exported_commit_at).total_seconds()
    # Lag is never negative (clock skew / a just-committed row): floor at 0.
    return max(delta, 0.0)


async def export_cycle(
    session: AsyncSession,
    *,
    sink: Sink,
    fmt: str,
    batch_size: int,
) -> CycleResult:
    """Run ONE export cycle: read → deliver → advance-on-ACK → recompute lag.

    Reads up to *batch_size* committed rows after the durable cursor (``seq`` order,
    NULL-``seq`` excluded), delivers them via *sink*, and advances the cursor +
    commits ONLY on a clean ACK (at-least-once, ADR-0045 §2). On a
    :class:`SinkDeliveryError` the cursor is left un-advanced (rolled back), the lag
    is still recomputed/published from the un-advanced cursor (so a stall shows up on
    the gauge), and ``failed=True`` is returned so the loop backs off and re-tries the
    SAME rows next cycle — never dropping a row (ADR-0045 §3).
    """
    after_seq = await current_exported_seq(session)
    records = await read_unexported(session, after_seq=after_seq, limit=batch_size)

    if not records:
        lag = await _compute_lag_seconds(session)
        set_audit_export_lag(lag_seconds=lag)
        return CycleResult(delivered=0, batch_full=False, lag_seconds=lag, failed=False)

    payloads = _format_batch(records, fmt=fmt)
    try:
        await sink.deliver(payloads)
    except SinkDeliveryError:
        # Buffer-in-the-durable-table + retry (ADR-0045 §3): do NOT advance the
        # cursor; the rows stay committed and are re-read next cycle. Publish the lag
        # from the (un-advanced) cursor so the held-down sink drives the gauge up.
        await session.rollback()
        lag = await _compute_lag_seconds(session)
        set_audit_export_lag(lag_seconds=lag)
        _logger.warning(
            "audit.export.sink_failure",
            after_seq=after_seq,
            batch=len(records),
            lag_seconds=round(lag, 3),
        )
        return CycleResult(delivered=0, batch_full=False, lag_seconds=lag, failed=True)

    # Sink ACKed the whole batch — advance the durable cursor to the last (max) seq,
    # which is records[-1] because read_unexported returns ORDER BY seq ASC.
    last = records[-1]
    await advance_cursor(session, last=last)
    await session.commit()

    lag = await _compute_lag_seconds(session)
    set_audit_export_lag(lag_seconds=lag)
    _logger.info(
        "audit.export.delivered",
        fmt=fmt,
        delivered=len(records),
        exported_seq=last.seq,
        lag_seconds=round(lag, 3),
    )
    return CycleResult(
        delivered=len(records),
        batch_full=len(records) == batch_size,
        lag_seconds=lag,
        failed=False,
    )


async def run_export_loop(
    *,
    sessionmaker: Callable[[], AsyncSession] | async_sessionmaker[AsyncSession],
    sink: Sink,
    settings: Settings,
    stop: asyncio.Event | None = None,
    max_cycles: int | None = None,
) -> int:
    """Drive :func:`export_cycle` continuously until *stop* is set (or *max_cycles*).

    Each iteration opens its OWN session (strictly downstream of the audit write —
    never the action transaction, ADR-0045 §3). Pacing: drain immediately while
    batches come back full (backlog), sleep ``audit_export_poll_seconds`` when caught
    up, and wait ``audit_export_retry_backoff_seconds`` (capped) after a sink failure
    before re-trying the SAME un-advanced rows. *max_cycles* bounds the loop for the
    test harness; production passes *stop* (a signal-driven event) and leaves
    *max_cycles* None. Returns the number of cycles run.
    """
    assert settings.audit_export_format is not None, "run_export_loop requires a configured format"
    fmt = settings.audit_export_format
    cycles = 0
    while True:
        if stop is not None and stop.is_set():
            break
        if max_cycles is not None and cycles >= max_cycles:
            break
        async with sessionmaker() as session:
            result = await export_cycle(
                session, sink=sink, fmt=fmt, batch_size=settings.audit_export_batch_size
            )
        cycles += 1
        if result.failed:
            await _sleep(settings.audit_export_retry_backoff_seconds, stop)
        elif result.batch_full:
            # More backlog to drain — loop again immediately (near-real-time, §6).
            continue
        else:
            await _sleep(settings.audit_export_poll_seconds, stop)
    return cycles


async def _sleep(seconds: float, stop: asyncio.Event | None) -> None:
    """Sleep *seconds*, but wake early if *stop* is set (responsive shutdown)."""
    if stop is None:
        await asyncio.sleep(seconds)
        return
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)
