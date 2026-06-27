"""Daily audit-chain verification CronJob entrypoint (ADR-0038 §4, ADR-0015).

The Helm-rendered ``audit-chain-verify-cronjob.yaml`` invokes this module daily:

    python -m app.services.audit.verify_job

It recomputes the ``audit_log`` hash chain from the verified-clean checkpoint to
the current head (:func:`app.services.audit.verify.verify_chain`), then:

  * emits a Prometheus metric via the node_exporter TEXTFILE collector
    (``audit_chain_verified`` 1/0 + last-verified position + entries checked) so a
    scraped value — not just a log line — records the chain's health (ADR-0015).
    A CronJob pod is not itself scrapable, so it writes a ``.prom`` file to the
    node_exporter textfile dir (the established no-pushgateway pattern); the metric
    survives the pod;
  * prints one structured ``AUDIT_CHAIN_VERIFY ...`` line for log-based alerting
    and the W5 evidence collector;
  * on ANY break: it does NOT advance the checkpoint, RAISES the alert (the
    non-zero exit + the ``audit_chain_verified 0`` metric ARE the alert signal —
    ADR-0015), and **exits non-zero** so the Job is marked Failed (it never
    silently passes — ADR-0038 §4). On a clean pass it advances the checkpoint and
    exits zero.

The DB session factory and the metric sink are injected into :func:`run` so the
tamper-detection test drives the EXACT job path against an in-memory engine —
what the test asserts is what the Job runs (no drift).

Secure by default: the metric and the log line carry only 0/1 health, counts,
positions, and hex digest PREFIXES (ADR-0038 §1) — never secret material (audit
rows are secret-free by construction, ADR-0032 §5).
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import create_engine, create_sessionmaker
from app.services.audit.verify import VerifyResult, verify_chain

_logger = get_logger(__name__)

#: The node_exporter textfile collector dir the metric is written under. The
#: CronJob mounts an emptyDir/hostPath here; overridable via env for tests + the
#: chart. (The collector scrapes ``*.prom`` files from this dir.)
_TEXTFILE_DIR_ENV = "AUDIT_CHAIN_METRICS_DIR"

#: Metric file name within the textfile dir (one file per job, atomically renamed).
_METRIC_FILENAME = "audit_chain_verify.prom"

#: When this env var is truthy the job runs a FULL scan (walk from genesis,
#: ignoring the checkpoint) instead of the daily incremental walk (A3). The weekly
#: full-scan CronJob sets it; the daily CronJob leaves it unset. Truthy = a case-
#: insensitive ``1``/``true``/``yes``/``on``.
_FULL_SCAN_ENV = "AUDIT_CHAIN_VERIFY_FULL"


def _env_full_scan() -> bool:
    """Return True when ``AUDIT_CHAIN_VERIFY_FULL`` requests a full (genesis) scan."""
    return os.environ.get(_FULL_SCAN_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def render_metrics(result: VerifyResult) -> str:
    """Render *result* as node_exporter textfile-format Prometheus metrics.

    Three series, each with HELP/TYPE headers (ADR-0015): ``audit_chain_verified``
    (1 clean / 0 break — the gate signal), ``audit_chain_last_verified_position``
    (the verified head index), and ``audit_chain_checked_total`` (entries walked
    this pass). Values only — no labels carry secret/digest material.
    """
    verified = 1 if result.ok else 0
    help_verified = (
        "# HELP audit_chain_verified 1 when the audit_log hash chain verified "
        "clean on the last run, 0 on a detected break (ADR-0038 4)."
    )
    help_position = (
        "# HELP audit_chain_last_verified_position 1-based index of the last "
        "verified-clean audit entry (ADR-0038 4)."
    )
    help_checked = (
        "# HELP audit_chain_checked_total Audit entries recomputed in the last verification pass."
    )
    lines = [
        help_verified,
        "# TYPE audit_chain_verified gauge",
        f"audit_chain_verified {verified}",
        help_position,
        "# TYPE audit_chain_last_verified_position gauge",
        f"audit_chain_last_verified_position {result.head_position}",
        help_checked,
        "# TYPE audit_chain_checked_total gauge",
        f"audit_chain_checked_total {result.checked}",
    ]
    return "\n".join(lines) + "\n"


def write_metrics(result: VerifyResult, *, textfile_dir: Path) -> Path:
    """Atomically write the textfile metric to *textfile_dir* and return its path.

    Writes to a temp file in the same dir then ``os.replace`` to the final name so
    a scrape can never observe a half-written file (the node_exporter textfile
    collector convention). Creates the dir if absent.
    """
    textfile_dir.mkdir(parents=True, exist_ok=True)
    target = textfile_dir / _METRIC_FILENAME
    body = render_metrics(result)
    fd, tmp_name = tempfile.mkstemp(dir=textfile_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp_name, target)
    except BaseException:
        # Never leave a stray temp file behind on a write failure.
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


def _emit_log(result: VerifyResult) -> None:
    """Print one structured ``AUDIT_CHAIN_VERIFY ...`` line for log-based alerting."""
    outcome = "PASS" if result.ok else "FAIL"
    fields = [
        f"OUTCOME={outcome}",
        f"checked={result.checked}",
        f"head_position={result.head_position}",
        f"head_entry_id={result.head_entry_id or '-'}",
    ]
    if result.break_ is not None:
        b = result.break_
        fields.extend(
            [
                f"break_position={b.position}",
                f"break_entry_id={b.entry_id}",
                f"break_reason={b.reason}",
                f"expected={b.expected or '-'}",
                f"found={b.found or '-'}",
            ]
        )
    print("AUDIT_CHAIN_VERIFY " + " ".join(fields), flush=True)


async def run(
    *,
    sessionmaker: Callable[[], AsyncSession] | async_sessionmaker[AsyncSession],
    textfile_dir: Path,
    full: bool = False,
) -> int:
    """Run one verification pass; emit the metric + log line; return an exit code.

    On a CLEAN pass: advances the checkpoint over the verified-clean segment,
    commits, writes ``audit_chain_verified 1``, and returns ``0``. On a BREAK: rolls
    back (the checkpoint is NOT advanced), writes ``audit_chain_verified 0`` + the
    break details, and returns ``1`` so the Job is marked Failed — the loud signal
    ADR-0015 requires. A clean pass never masks a break (fail toward false-positive,
    ADR-0038 §4 / W4-T1 spec req 3).

    When *full* is true the verifier ignores the checkpoint and re-walks the whole
    chain from genesis (A3) — the slower-cadence guard that catches tampering of a
    historical row BELOW the watermark, which the daily incremental walk (resuming
    after the checkpoint) never re-visits.

    Alert ordering (A8): the structured ``AUDIT_CHAIN_VERIFY`` log line + the
    structured-logger alert are emitted and the exit code is decided BEFORE the
    metric write. The textfile-metric write is best-effort — a metric-write failure
    must never suppress the alert log or flip the exit code (the alert signal is
    needed exactly when the job is failing).
    """
    async with sessionmaker() as session:
        result = await verify_chain(session, advance_checkpoint=True, full=full)
        if result.ok:
            await session.commit()
        else:
            await session.rollback()

    # A8: emit the alert log line + decide the exit code FIRST, so a metric-write
    # failure below can never swallow the alert signal or the non-zero exit.
    _emit_log(result)
    if result.ok:
        _logger.info(
            "audit.chain.verified",
            checked=result.checked,
            head_position=result.head_position,
            head_entry_id=result.head_entry_id,
            full=full,
        )
        exit_code = 0
    else:
        assert result.break_ is not None  # ok is False ⇒ a break was recorded
        _logger.error(
            "audit.chain.break_detected",
            break_position=result.break_.position,
            break_entry_id=result.break_.entry_id,
            break_reason=result.break_.reason,
            full=full,
        )
        exit_code = 1

    # The metric is a secondary signal (ADR-0015); writing it is best-effort so a
    # textfile-dir failure does not mask the primary log alert / exit code (A8).
    try:
        write_metrics(result, textfile_dir=textfile_dir)
    except OSError:
        _logger.error("audit.chain.metric_write_failed", exc_info=True)

    return exit_code


async def _main() -> int:
    """Build the runtime engine from settings and run one pass (the Job path)."""
    textfile_dir = Path(os.environ.get(_TEXTFILE_DIR_ENV, tempfile.gettempdir()))
    full = _env_full_scan()
    engine = create_engine(get_settings())
    try:
        maker = create_sessionmaker(engine)
        return await run(sessionmaker=maker, textfile_dir=textfile_dir, full=full)
    finally:
        await engine.dispose()


if __name__ == "__main__":  # pragma: no cover - exercised via run() in the test wrapper
    import asyncio

    sys.exit(asyncio.run(_main()))
