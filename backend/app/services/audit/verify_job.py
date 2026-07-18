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
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import create_engine, create_sessionmaker
from app.models.audit import (
    AuditChainCheckpoint,
    AuditChainVerificationRun,
    ChainVerificationOutcome,
    GrantCheckOutcome,
)
from app.models.mixins import utcnow
from app.services.audit.grants import GrantCheckResult, check_audit_log_grants
from app.services.audit.verify import VerifyResult, count_pre_chain_rows, verify_chain

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


def render_metrics(
    result: VerifyResult, *, pre_chain_rows: int = 0, pre_chain_suspicious: int = 0
) -> str:
    """Render *result* as node_exporter textfile-format Prometheus metrics.

    Series, each with HELP/TYPE headers (ADR-0015): ``audit_chain_verified``
    (1 clean / 0 break-or-suspicious — the gate signal), ``audit_chain_last_verified_position``
    (the verified head index), ``audit_chain_checked_total`` (entries walked this
    pass), ``audit_chain_pre_chain_rows`` (NULL-``seq`` pre-chain rows — expected only
    transiently during a rolling deploy) and ``audit_chain_pre_chain_suspicious``
    (pre-chain rows with a non-genesis hash = likely tampering, round-4 #01). Values
    only — no labels carry secret/digest material.

    ``audit_chain_verified`` is 1 ONLY when the chain is clean AND there are no
    suspicious pre-chain rows: a NULL-``seq`` row with a real hash must drag the gate
    to 0 so legacy corruption cannot hide behind the pre-chain classification.
    """
    verified = 1 if (result.ok and pre_chain_suspicious == 0) else 0
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
    help_pre_chain = (
        "# HELP audit_chain_pre_chain_rows NULL-seq pre-chain audit rows (expected "
        "only transiently during a rolling deploy; ADR-0038 4 / round-4 #01)."
    )
    help_pre_chain_suspicious = (
        "# HELP audit_chain_pre_chain_suspicious Pre-chain rows with a non-genesis "
        "entry_hash — likely tampering; drives audit_chain_verified to 0."
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
        help_pre_chain,
        "# TYPE audit_chain_pre_chain_rows gauge",
        f"audit_chain_pre_chain_rows {pre_chain_rows}",
        help_pre_chain_suspicious,
        "# TYPE audit_chain_pre_chain_suspicious gauge",
        f"audit_chain_pre_chain_suspicious {pre_chain_suspicious}",
    ]
    return "\n".join(lines) + "\n"


def write_metrics(
    result: VerifyResult,
    *,
    textfile_dir: Path,
    pre_chain_rows: int = 0,
    pre_chain_suspicious: int = 0,
) -> Path:
    """Atomically write the textfile metric to *textfile_dir* and return its path.

    Writes to a temp file in the same dir then ``os.replace`` to the final name so
    a scrape can never observe a half-written file (the node_exporter textfile
    collector convention). Creates the dir if absent.
    """
    textfile_dir.mkdir(parents=True, exist_ok=True)
    target = textfile_dir / _METRIC_FILENAME
    body = render_metrics(
        result, pre_chain_rows=pre_chain_rows, pre_chain_suspicious=pre_chain_suspicious
    )
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


def _emit_log(result: VerifyResult, *, pre_chain_rows: int, pre_chain_suspicious: int) -> None:
    """Print one structured ``AUDIT_CHAIN_VERIFY ...`` line for log-based alerting.

    OUTCOME is PASS only when the chain is clean AND no pre-chain row is suspicious
    (round-4 #01): a NULL-``seq`` row with a non-genesis hash is surfaced here, never
    hidden. ``pre_chain``/``pre_chain_suspicious`` are always emitted so an operator
    sees the pre-chain count even on an otherwise-clean run.
    """
    healthy = result.ok and pre_chain_suspicious == 0
    outcome = "PASS" if healthy else "FAIL"
    fields = [
        f"OUTCOME={outcome}",
        f"checked={result.checked}",
        f"head_position={result.head_position}",
        f"head_entry_id={result.head_entry_id or '-'}",
        f"pre_chain={pre_chain_rows}",
        f"pre_chain_suspicious={pre_chain_suspicious}",
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


async def _checkpoint_state(session: AsyncSession) -> tuple[uuid.UUID, str] | None:
    """Return ``(entry_id, entry_hash hex)`` of the watermark, or ``None`` if unset.

    The hex digest is a PRESENTATION of the checkpoint entry hash — tamper
    evidence the ADR-0053 §6 redaction contract deliberately permits, never
    secret material.
    """
    checkpoint = (
        await session.execute(
            select(AuditChainCheckpoint).where(
                AuditChainCheckpoint.id == AuditChainCheckpoint.SINGLETON_ID
            )
        )
    ).scalar_one_or_none()
    if checkpoint is None:
        return None
    return checkpoint.entry_id, checkpoint.entry_hash.hex()


async def _persist_verification_run(
    session: AsyncSession,
    *,
    result: VerifyResult,
    healthy: bool,
    full: bool,
    started_at: datetime,
    finished_at: datetime,
    checkpoint_before: tuple[uuid.UUID, str] | None,
) -> None:
    """Persist one ``audit_chain_verification_runs`` row (ADR-0053 §7.4).

    The SMALL ADDITIVE change ADR-0053 names: called AFTER the commit/rollback
    decision so a break run persists its ``break`` row without ever advancing
    the checkpoint (the rollback already happened), and a clean run records
    the advanced watermark. The daily append-only grant attestation runs here
    too (:func:`~app.services.audit.grants.check_audit_log_grants`) and is
    persisted with the row — the historical half of the G-SEC attestation.

    ``outcome`` derives from *healthy* (chain clean AND no suspicious
    pre-chain row), not ``result.ok`` alone: a run the job reports as FAILED
    must never persist as ``clean`` history (fail toward false-positive,
    ADR-0038 §4).
    """
    try:
        grant = await check_audit_log_grants(session)
    except Exception:
        # The attestation must be honest, never silently clean: a failed
        # catalog query persists the explicit ``unavailable`` token.
        _logger.error("audit.chain.grant_check_failed", exc_info=True)
        grant = GrantCheckResult(outcome=GrantCheckOutcome.UNAVAILABLE.value, grants=())
    checkpoint_after = await _checkpoint_state(session)
    outcome = ChainVerificationOutcome.CLEAN if healthy else ChainVerificationOutcome.BREAK
    session.add(
        AuditChainVerificationRun(
            started_at=started_at,
            finished_at=finished_at,
            outcome=outcome.value,
            entries_checked=result.checked,
            # Exclusive lower bound of the walked segment: the checkpoint
            # anchor on an incremental pass; NULL = genesis (first run / full).
            range_from_entry_id=(
                checkpoint_before[0] if (checkpoint_before is not None and not full) else None
            ),
            range_to_entry_id=(
                uuid.UUID(result.head_entry_id) if result.head_entry_id is not None else None
            ),
            checkpoint_before_hash=checkpoint_before[1] if checkpoint_before else None,
            checkpoint_after_hash=checkpoint_after[1] if checkpoint_after else None,
            grant_check_outcome=grant.outcome,
        )
    )
    await session.commit()


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
    started_at = utcnow()
    async with sessionmaker() as session:
        # Watermark state BEFORE the walk — recorded on the ADR-0053 §7.4 history
        # row (checkpoint before/after + the walked range's exclusive lower bound).
        checkpoint_before = await _checkpoint_state(session)
        result = await verify_chain(session, advance_checkpoint=True, full=full)
        # Pre-chain accounting (round-4 #01) — read in-session, BEFORE the commit/
        # rollback decision, so NULL-seq rows are surfaced explicitly and a suspicious
        # one (non-genesis hash = likely tampering) is never hidden by the pre-chain
        # classification.
        pre_chain_rows, pre_chain_suspicious = await count_pre_chain_rows(session)
        # Overall health: the chain must be clean AND no pre-chain row may be suspicious
        # (a NULL-seq row with a real hash is anomalous — fail toward false-positive,
        # ADR-0038 §4). A benign rolling-window old-writer row (genesis hash) is logged
        # but does not fail the gate. Gate the commit on `healthy`, NOT `result.ok`
        # (round-5 #02): a suspicious pre-chain row makes the run FAIL (exit 1), so it
        # must roll back too — otherwise verify_chain's advance_checkpoint would commit
        # an advanced watermark on a run we are reporting as failed.
        healthy = result.ok and pre_chain_suspicious == 0
        if healthy:
            await session.commit()
        else:
            await session.rollback()

        # ADR-0053 §7.4 ADDITIVE history write (P4 W3-T5): persist one outcome row
        # per run (incl. the daily grant attestation) AFTER the commit/rollback
        # decision, so a break run records `break` without the rolled-back
        # checkpoint advance ever landing. Metric + exit-code behavior are
        # UNCHANGED by contract: a row-write failure is logged loudly but never
        # flips the exit code or suppresses the alert path — the missing row then
        # self-surfaces as a verification-gap FINDING in the audit-integrity
        # report (a day with no persisted run is a finding, not a blank).
        try:
            await _persist_verification_run(
                session,
                result=result,
                healthy=healthy,
                full=full,
                started_at=started_at,
                finished_at=utcnow(),
                checkpoint_before=checkpoint_before,
            )
        except Exception:
            _logger.error("audit.chain.verification_run_write_failed", exc_info=True)

    # A8: emit the alert log line + decide the exit code FIRST, so a metric-write
    # failure below can never swallow the alert signal or the non-zero exit.
    _emit_log(result, pre_chain_rows=pre_chain_rows, pre_chain_suspicious=pre_chain_suspicious)
    if result.ok:
        _logger.info(
            "audit.chain.verified",
            checked=result.checked,
            head_position=result.head_position,
            head_entry_id=result.head_entry_id,
            pre_chain_rows=pre_chain_rows,
            pre_chain_suspicious=pre_chain_suspicious,
            full=full,
        )
    else:
        assert result.break_ is not None  # ok is False ⇒ a break was recorded
        _logger.error(
            "audit.chain.break_detected",
            break_position=result.break_.position,
            break_entry_id=result.break_.entry_id,
            break_reason=result.break_.reason,
            pre_chain_rows=pre_chain_rows,
            pre_chain_suspicious=pre_chain_suspicious,
            full=full,
        )
    # Pre-chain rows are EXPLICIT, never silent: a suspicious one is a loud ERROR (it
    # also drags the exit code + the audit_chain_verified metric to failing); a benign
    # transient count is a WARNING so an operator still sees it outside a known window.
    if pre_chain_suspicious > 0:
        _logger.error(
            "audit.chain.pre_chain_suspicious",
            pre_chain_rows=pre_chain_rows,
            pre_chain_suspicious=pre_chain_suspicious,
        )
    elif pre_chain_rows > 0:
        _logger.warning("audit.chain.pre_chain_present", pre_chain_rows=pre_chain_rows)

    exit_code = 0 if healthy else 1

    # The metric is a secondary signal (ADR-0015); writing it is best-effort so a
    # textfile-dir failure does not mask the primary log alert / exit code (A8).
    try:
        write_metrics(
            result,
            textfile_dir=textfile_dir,
            pre_chain_rows=pre_chain_rows,
            pre_chain_suspicious=pre_chain_suspicious,
        )
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
