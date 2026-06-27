"""Daily audit-chain verify CronJob entrypoint (ADR-0038 §4, ADR-0015).

Drives the EXACT job path (:func:`app.services.audit.verify_job.run`) against the
in-memory engine, asserting the loud-on-break contract: a clean chain returns exit
0 with ``audit_chain_verified 1``; a tampered chain returns exit 1 (non-zero, so
the Job is Failed) with ``audit_chain_verified 0`` and the break details — never a
silent pass (ADR-0038 §4). The Prometheus textfile metric is written atomically to
the injected dir (the no-pushgateway pattern, ADR-0015).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.models import AuditChainCheckpoint, AuditLog
from app.services.audit import service as audit_service
from app.services.audit import verify_job
from app.services.audit.verify import VerifyResult


async def _seed(maker: async_sessionmaker, n: int) -> list[AuditLog]:
    async with maker() as session:
        entries = []
        for i in range(n):
            entries.append(
                await audit_service.record(
                    session,
                    actor=f"user:{i}",
                    action=audit_service.DEVICE_UPDATED,
                    target_type="device",
                    target_id=str(i),
                    detail={"step": i},
                )
            )
        await session.commit()
        return entries


async def test_clean_run_exits_zero_and_writes_verified_metric(
    engine: AsyncEngine, tmp_path: Path
) -> None:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _seed(maker, 4)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 0
    metric = (tmp_path / "audit_chain_verify.prom").read_text(encoding="utf-8")
    assert "audit_chain_verified 1" in metric
    assert "audit_chain_checked_total 4" in metric


async def test_clean_run_advances_checkpoint(engine: AsyncEngine, tmp_path: Path) -> None:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _seed(maker, 3)

    await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    async with maker() as session:
        checkpoint = (await session.execute(select(AuditChainCheckpoint))).scalar_one()
    assert checkpoint is not None


async def test_tampered_run_exits_nonzero_and_writes_broken_metric(
    engine: AsyncEngine, tmp_path: Path
) -> None:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    entries = await _seed(maker, 5)

    # Bypass the writer to mutate a hashed field (a privileged DB UPDATE).
    target = entries[2]
    async with maker() as session:
        await session.execute(
            update(AuditLog)
            .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
            .values(action="device.deleted")
        )
        await session.commit()

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 1  # non-zero: the Job is Failed, the loud signal (ADR-0015)
    metric = (tmp_path / "audit_chain_verify.prom").read_text(encoding="utf-8")
    assert "audit_chain_verified 0" in metric


async def test_render_metrics_has_help_and_type_headers() -> None:
    result = VerifyResult(
        ok=True,
        checked=2,
        head_position=2,
        head_entry_id="x",
        head_entry_hash_hex="deadbeef",
        break_=None,
    )
    body = verify_job.render_metrics(result)
    assert "# HELP audit_chain_verified" in body
    assert "# TYPE audit_chain_verified gauge" in body
    assert body.endswith("\n")


async def test_metric_write_is_atomic_replace(engine: AsyncEngine, tmp_path: Path) -> None:
    """The metric write leaves exactly one .prom file and no stray temp files."""
    result = VerifyResult(
        ok=False,
        checked=0,
        head_position=0,
        head_entry_id=None,
        head_entry_hash_hex=None,
        break_=None,
    )
    verify_job.write_metrics(result, textfile_dir=tmp_path)
    files = list(tmp_path.iterdir())
    assert [f.name for f in files] == ["audit_chain_verify.prom"]


async def test_metric_write_failure_does_not_suppress_break_alert(
    engine: AsyncEngine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A metric-write failure must NOT swallow the alert log or the non-zero exit (A8).

    The structured ``AUDIT_CHAIN_VERIFY`` line + the exit code are the PRIMARY alert
    signal (ADR-0015). If the textfile/metric write blows up (e.g. a read-only or
    full disk), the job must still emit the FAIL log line and return non-zero — the
    metric write is best-effort and emitted last, so its failure cannot mask the
    alert exactly when the chain is broken.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    entries = await _seed(maker, 5)
    target = entries[2]
    async with maker() as session:
        await session.execute(
            update(AuditLog)
            .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
            .values(action="device.deleted")
        )
        await session.commit()

    def _boom(*_args: Any, **_kwargs: Any) -> Path:
        raise OSError("metrics textfile dir is read-only")

    monkeypatch.setattr(verify_job, "write_metrics", _boom)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    # The metric write failed, but the alert log line + non-zero exit still fire.
    assert code == 1
    out = capsys.readouterr().out
    assert "AUDIT_CHAIN_VERIFY OUTCOME=FAIL" in out


async def test_full_scan_catches_pre_anchor_tamper_via_job(
    engine: AsyncEngine, tmp_path: Path
) -> None:
    """The job's full=True path re-walks from genesis and catches a historical tamper (A3).

    After the checkpoint is advanced over a clean chain, mutating a PRE-anchor row is
    invisible to the daily incremental job (it resumes after the checkpoint) but the
    weekly full scan (full=True) re-detects it: exit non-zero + ``audit_chain_verified
    0``. This proves the full-scan job mode is the guard for the A3 gap.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    entries = await _seed(maker, 5)

    # Advance the checkpoint over the clean chain (daily incremental run).
    assert await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path) == 0

    # Tamper a pre-anchor historical row (entries[1], well below the watermark).
    pre_anchor = entries[1]
    async with maker() as session:
        await session.execute(
            update(AuditLog)
            .where(AuditLog.id == pre_anchor.id, AuditLog.created_at == pre_anchor.created_at)
            .values(actor="user:evil")
        )
        await session.commit()

    # Daily incremental run does NOT re-detect it (resumes after the checkpoint).
    assert await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path) == 0

    # Weekly full scan re-walks from genesis and catches it: non-zero + broken metric.
    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path, full=True)
    assert code == 1
    metric = (tmp_path / "audit_chain_verify.prom").read_text(encoding="utf-8")
    assert "audit_chain_verified 0" in metric


async def test_main_reads_full_scan_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """``AUDIT_CHAIN_VERIFY_FULL`` selects the full scan; absent/false → incremental (A3)."""
    monkeypatch.delenv(verify_job._FULL_SCAN_ENV, raising=False)
    assert verify_job._env_full_scan() is False
    for truthy in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv(verify_job._FULL_SCAN_ENV, truthy)
        assert verify_job._env_full_scan() is True
    for falsy in ("0", "false", "no", "", "off"):
        monkeypatch.setenv(verify_job._FULL_SCAN_ENV, falsy)
        assert verify_job._env_full_scan() is False
