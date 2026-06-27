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
