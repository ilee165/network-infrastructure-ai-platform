"""Daily audit-chain verify CronJob entrypoint (ADR-0038 §4, ADR-0015).

Drives the EXACT job path (:func:`app.services.audit.verify_job.run`) against the
in-memory engine, asserting the loud-on-break contract: a clean chain returns exit
0 with ``audit_chain_verified 1``; a tampered chain returns exit 1 (non-zero, so
the Job is Failed) with ``audit_chain_verified 0`` and the break details — never a
silent pass (ADR-0038 §4). The Prometheus textfile metric is written atomically to
the injected dir (the no-pushgateway pattern, ADR-0015).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.models import AuditChainCheckpoint, AuditLog
from app.models.mixins import utcnow
from app.services.audit import service as audit_service
from app.services.audit import verify_job
from app.services.audit.chain import GENESIS_HASH, HASH_LEN
from app.services.audit.verify import VerifyResult, count_pre_chain_rows


async def _insert_pre_chain_row(
    maker: async_sessionmaker,
    *,
    entry_hash: bytes,
    prev_hash: bytes = GENESIS_HASH,
) -> None:
    """Core-INSERT a NULL-``seq`` audit row (simulates an old pre-W4 writer).

    Uses a core insert with an explicit ``seq=None`` so the ORM's app-side
    ``_next_seq`` default is bypassed — exactly what an old (pre-``seq``) pod would
    write during a rolling deploy. A benign old-writer row carries the genesis seed in
    BOTH ``entry_hash`` and ``prev_hash``; a non-genesis digest in EITHER is the
    SUSPICIOUS (likely-tampered) case (round-5 #01 — a mutated ``prev_hash`` is just as
    anomalous as a mutated ``entry_hash`` on a row that claims to be pre-chain).
    """
    async with maker() as session:
        await session.execute(
            insert(AuditLog).values(
                id=uuid.uuid4(),
                created_at=utcnow(),
                seq=None,
                actor="legacy:old-writer",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id="legacy",
                detail=None,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
        )
        await session.commit()


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


# ---------------------------------------------------------------------------
# round-4 #01 — NULL-`seq` (pre-chain) handling: no crash, no false break,
# explicit + logged, fail-loud on a suspicious (non-genesis) pre-chain row.
# ---------------------------------------------------------------------------

_NON_GENESIS_HASH = bytes(range(1, HASH_LEN + 1))  # 32 non-zero bytes ≠ GENESIS


async def test_current_chain_head_ignores_lone_null_seq_row(engine: AsyncEngine) -> None:
    """A NULL-`seq` row is never selected as the chain head (round-4 #01 bite).

    With only a NULL-`seq` old-writer row present, the OLD head read
    (``ORDER BY seq DESC LIMIT 1`` with no filter) returns THAT row and then does
    ``int(None) + 1`` — a crash that blocks every new append (and on PostgreSQL the
    NULL sorts FIRST even when real rows exist). The ``seq IS NOT NULL`` filter makes
    the head read seed the chain at ``(GENESIS, 1)`` instead.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _insert_pre_chain_row(maker, entry_hash=GENESIS_HASH)

    async with maker() as session:
        prev_hash, next_seq = await audit_service._current_chain_head(session)

    assert prev_hash == GENESIS_HASH
    assert next_seq == 1


async def test_current_chain_head_uses_greatest_real_seq(engine: AsyncEngine) -> None:
    """The head is the greatest REAL-`seq` row, ignoring any NULL-`seq` pre-chain rows."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    entries = await _seed(maker, 3)  # seq 1,2,3
    await _insert_pre_chain_row(maker, entry_hash=GENESIS_HASH)

    async with maker() as session:
        prev_hash, next_seq = await audit_service._current_chain_head(session)

    assert prev_hash == entries[-1].entry_hash
    assert next_seq == 4


async def test_count_pre_chain_rows_classifies_genesis_vs_suspicious(engine: AsyncEngine) -> None:
    """count_pre_chain_rows: total NULL-`seq` rows + how many are non-genesis (suspicious)."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _seed(maker, 2)  # real chain rows — not counted
    await _insert_pre_chain_row(maker, entry_hash=GENESIS_HASH)  # benign old-writer
    await _insert_pre_chain_row(maker, entry_hash=_NON_GENESIS_HASH)  # suspicious

    async with maker() as session:
        total, suspicious = await count_pre_chain_rows(session)

    assert total == 2
    assert suspicious == 1


async def test_count_pre_chain_rows_flags_tampered_prev_hash(engine: AsyncEngine) -> None:
    """A NULL-`seq` row with genesis entry_hash but a NON-genesis prev_hash is suspicious.

    Round-5 #01: classifying on ``entry_hash`` alone misses a row whose ``prev_hash``
    was mutated to a real predecessor digest — it would pass as a benign old-writer and
    the chain walk (which excludes NULL-seq rows) would never catch it, a false PASS.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _insert_pre_chain_row(maker, entry_hash=GENESIS_HASH, prev_hash=_NON_GENESIS_HASH)

    async with maker() as session:
        total, suspicious = await count_pre_chain_rows(session)

    assert total == 1
    assert suspicious == 1, "tampered prev_hash on a NULL-seq row must be suspicious"


async def test_benign_pre_chain_row_is_logged_but_passes(
    engine: AsyncEngine, tmp_path: Path, capsys: Any
) -> None:
    """A genesis NULL-`seq` old-writer row does NOT false-break and does NOT fail the gate.

    The clean chain still verifies; the pre-chain row is surfaced explicitly (count in
    the log line + metric) but, being a benign genesis-hash old-writer row, keeps
    exit 0 and ``audit_chain_verified 1``.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _seed(maker, 4)
    await _insert_pre_chain_row(maker, entry_hash=GENESIS_HASH)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 0  # benign pre-chain row does not fail the gate
    out = capsys.readouterr().out
    assert "OUTCOME=PASS" in out
    assert "pre_chain=1" in out
    assert "pre_chain_suspicious=0" in out
    metric = (tmp_path / "audit_chain_verify.prom").read_text(encoding="utf-8")
    assert "audit_chain_verified 1" in metric
    assert "audit_chain_pre_chain_rows 1" in metric
    assert "audit_chain_pre_chain_suspicious 0" in metric


async def test_suspicious_pre_chain_row_fails_loud(
    engine: AsyncEngine, tmp_path: Path, capsys: Any
) -> None:
    """A NULL-`seq` row with a non-genesis hash (likely tampering) FAILS the job (round-4 #01).

    Real legacy corruption must never hide behind the pre-chain classification: a
    suspicious pre-chain row drags exit to 1 and ``audit_chain_verified`` to 0 even
    though the real chain itself is clean.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    await _seed(maker, 4)
    await _insert_pre_chain_row(maker, entry_hash=_NON_GENESIS_HASH)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 1  # fail-loud: legacy corruption is not hidden
    out = capsys.readouterr().out
    assert "OUTCOME=FAIL" in out
    assert "pre_chain_suspicious=1" in out
    metric = (tmp_path / "audit_chain_verify.prom").read_text(encoding="utf-8")
    assert "audit_chain_verified 0" in metric
    assert "audit_chain_pre_chain_suspicious 1" in metric
