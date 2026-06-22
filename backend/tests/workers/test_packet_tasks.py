"""M5-T8 Celery packet tasks: capture + sandboxed analysis + retention (eager).

File-backed aiosqlite (each task opens its own ``asyncio.run`` loop, so the
schema must persist across connections), ``task_always_eager``. The capture
subprocess (``_run_tcpdump``), the tshark sandbox (``_analyze_pcap``), and the
file delete (``_delete_file``) are faked through the module seams in
:mod:`app.workers.tasks.packet` — no real subprocess, NIC, tshark, or network.

Asserts the ADR-0023 contract end to end: a worker-side capture content-addresses
a ``pcap_metadata`` row + audit, sandboxed analysis returns normalized findings +
audit (no payload bytes in the result/audit), the retention task deletes the file
and tombstones (never deletes) the row with a ``pcap.purged`` audit entry, and a
hostile filter is rejected by the sandbox and audited as a failure.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.engines.packet import PacketFindings
from app.engines.packet.filters import FilterValidationError
from app.engines.packet.sandbox import SandboxError
from app.models import AuditLog, Base, PcapMetadata
from app.workers.celery_app import celery_app
from app.workers.tasks import packet as tasks


@pytest.fixture()
def eager_celery() -> Iterator[None]:
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = previous


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'packet.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


def _fetch_all(db_url: str, orm_cls: type) -> list[Any]:
    async def _go() -> list[Any]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(orm_cls))).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


def _seed_pcap(
    db_url: str,
    *,
    capture_id: uuid.UUID,
    storage_path: str,
    started_at: datetime,
    retention_days: int,
) -> None:
    async def _go() -> None:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            session.add(
                PcapMetadata(
                    capture_id=capture_id,
                    interface="eth0",
                    requester_id=uuid.uuid4(),
                    started_at=started_at,
                    retention_expires_at=started_at + timedelta(days=retention_days),
                    storage_path=storage_path,
                    sha256="a" * 64,
                    byte_count=1,
                )
            )
            await session.commit()
        await engine.dispose()

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# packet.capture_segment (worker-side tcpdump)
# ---------------------------------------------------------------------------


def test_capture_segment_persists_metadata_and_audits(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    captured_argv: list[Any] = []

    def _fake_tcpdump(argv: list[str]) -> None:
        captured_argv.append(argv)
        # Simulate tcpdump writing the pcap to the -w path.
        out = argv[argv.index("-w") + 1]
        with open(out, "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1pcapbytes")

    monkeypatch.setattr(tasks, "_run_tcpdump", _fake_tcpdump)

    result = tasks.capture_segment(str(uuid.uuid4()), "eth0", "tcp port 443")

    assert result["ok"] is True
    # argv-not-shell: the capture ran from a list.
    assert isinstance(captured_argv[0], list)
    rows = _fetch_all(db_url, PcapMetadata)
    assert len(rows) == 1
    assert rows[0].device_id is None  # segment capture has no device
    assert rows[0].sha256 == result["sha256"]
    actions = {a.action for a in _fetch_all(db_url, AuditLog)}
    assert "packet.capture_completed" in actions


def test_capture_segment_rejects_malicious_interface_and_audits(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    spawned: list[Any] = []
    monkeypatch.setattr(tasks, "_run_tcpdump", lambda argv: spawned.append(argv))

    result = tasks.capture_segment(str(uuid.uuid4()), "eth0; rm -rf /")

    assert result["ok"] is False
    assert spawned == []  # validation rejected before any capture spawn
    assert _fetch_all(db_url, PcapMetadata) == []
    actions = {a.action for a in _fetch_all(db_url, AuditLog)}
    assert "packet.capture_failed" in actions


# ---------------------------------------------------------------------------
# packet.capture_device (eos monitor-session) — dwell ordering
# ---------------------------------------------------------------------------


def test_drive_eos_capture_waits_duration_between_start_and_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The EOS capture must dwell ``duration_seconds`` after ``start`` before it
    sends ``stop``/``copy`` — otherwise it records an empty pcap (ADR-0023 §2)."""
    from app.engines.packet import CaptureSpec, build_eos_capture_commands

    spec = CaptureSpec.create(interface="Ethernet1", duration_seconds=42)
    start_commands = build_eos_capture_commands(spec, "flash:cap.pcap")

    timeline: list[str] = []

    class _FakeTransport:
        def send_command(self, command: str) -> None:
            timeline.append(command)

        def retrieve_file(self, storage_path: str) -> None:
            timeline.append(f"retrieve {storage_path}")

    class _FakeCtx:
        params = object()

        def retrieve(self, transport: Any, storage_path: str) -> None:
            transport.retrieve_file(storage_path)

    from contextlib import contextmanager

    @contextmanager
    def _fake_open_ssh(params: Any) -> Any:
        yield _FakeTransport()

    slept: list[float] = []
    monkeypatch.setattr(tasks, "_open_ssh", _fake_open_ssh)
    monkeypatch.setattr(tasks, "_sleep", lambda seconds: slept.append(seconds))

    async def _fake_ctx(device_id: Any) -> Any:
        return _FakeCtx()

    monkeypatch.setattr(tasks, "_load_ssh_context", _fake_ctx)

    tasks._drive_eos_capture(uuid.uuid4(), spec, "flash:cap.pcap", str(tmp_path / "x.pcap"))

    # Dwell equal to the capture duration happens before stop/copy.
    assert slept == [42]
    stop_idx = timeline.index("monitor capture netops stop")
    start_idx = timeline.index("monitor capture netops start")
    # start precedes stop, and the engine never bundles stop with the start lines.
    assert start_idx < stop_idx
    assert "monitor capture netops stop" not in start_commands
    # copy follows stop; retrieve is last.
    assert timeline.index("copy capture netops flash:cap.pcap") > stop_idx
    assert timeline[-1] == f"retrieve {tmp_path / 'x.pcap'}"


# ---------------------------------------------------------------------------
# packet.analyze_capture (sandboxed tshark)
# ---------------------------------------------------------------------------


def test_analyze_capture_returns_findings_and_audits_no_payload(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    capture_id = uuid.uuid4()

    findings = PacketFindings(packet_count=7, tcp_resets=2)

    def _fake_analyze(path: str, *, display_filter: Any, settings: Any) -> PacketFindings:
        return findings

    monkeypatch.setattr(tasks, "_analyze_pcap", _fake_analyze)
    # The OS-isolation posture is the deployment's job; the eager runner has none
    # of those controls, so the runtime backstop is neutralized here (ADR-0031 §2).
    monkeypatch.setattr(tasks, "_assert_posture", lambda settings: None)

    result = tasks.analyze_capture(str(capture_id))

    assert result["ok"] is True
    assert result["findings"]["packet_count"] == 7
    # The audit detail carries counts only — never raw packet bytes.
    audit_rows = _fetch_all(db_url, AuditLog)
    completed = [a for a in audit_rows if a.action == "packet.analysis_completed"]
    assert completed and completed[0].detail["packet_count"] == 7
    assert "payload" not in completed[0].detail


def test_analyze_capture_sandbox_failure_is_audited(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)

    def _boom(path: str, *, display_filter: Any, settings: Any) -> PacketFindings:
        raise SandboxError("tshark exceeded the timeout")

    monkeypatch.setattr(tasks, "_analyze_pcap", _boom)
    monkeypatch.setattr(tasks, "_assert_posture", lambda settings: None)

    result = tasks.analyze_capture(str(uuid.uuid4()))
    assert result["ok"] is False
    actions = {a.action for a in _fetch_all(db_url, AuditLog)}
    assert "packet.analysis_failed" in actions


def test_analyze_capture_rejected_filter_is_audited(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)

    def _reject(path: str, *, display_filter: Any, settings: Any) -> PacketFindings:
        raise FilterValidationError("filter rejected")

    monkeypatch.setattr(tasks, "_analyze_pcap", _reject)
    monkeypatch.setattr(tasks, "_assert_posture", lambda settings: None)

    result = tasks.analyze_capture(str(uuid.uuid4()), display_filter="tcp; rm -rf /")
    assert result["ok"] is False
    actions = {a.action for a in _fetch_all(db_url, AuditLog)}
    assert "packet.analysis_failed" in actions


def test_analyze_capture_refuses_when_posture_check_fails(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A misconfigured deployment fails closed: posture failure => no tshark, audited.

    The runtime backstop (ADR-0031 §2) refuses to spawn tshark when the worker is
    root / holds CAP_NET_RAW / has a writable rootfs. Here the posture seam raises
    and we assert tshark is never invoked and the failure is audited as ok=False.
    """
    from app.engines.packet import PostureError

    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    spawned: list[Any] = []

    def _should_not_run(path: str, *, display_filter: Any, settings: Any) -> PacketFindings:
        spawned.append(path)
        return PacketFindings(packet_count=0)

    def _bad_posture(settings: Any) -> None:
        raise PostureError("effective UID is 0 (root); the parser must run non-root")

    monkeypatch.setattr(tasks, "_analyze_pcap", _should_not_run)
    monkeypatch.setattr(tasks, "_assert_posture", _bad_posture)

    result = tasks.analyze_capture(str(uuid.uuid4()))

    assert result["ok"] is False
    assert spawned == []  # tshark never spawned — failed closed
    actions = {a.action for a in _fetch_all(db_url, AuditLog)}
    assert "packet.analysis_failed" in actions


# ---------------------------------------------------------------------------
# packet.purge_expired (retention beat)
# ---------------------------------------------------------------------------


def test_purge_expired_deletes_file_tombstones_row_and_audits(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    capture_id = uuid.uuid4()
    pcap_file = tmp_path / "old.pcap"
    pcap_file.write_bytes(b"old pcap bytes")
    _seed_pcap(
        db_url,
        capture_id=capture_id,
        storage_path=str(pcap_file),
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        retention_days=30,
    )

    deleted: list[str] = []
    real_delete = tasks._delete_file

    def _spy_delete(path: str) -> bool:
        deleted.append(path)
        return real_delete(path)

    monkeypatch.setattr(tasks, "_delete_file", _spy_delete)

    result = tasks.purge_expired()

    assert result["purged"] == 1
    assert deleted == [str(pcap_file)]
    assert not pcap_file.exists()  # file removed (sensitive payload gone)
    rows = _fetch_all(db_url, PcapMetadata)
    assert len(rows) == 1  # row NOT deleted — audit fact survives
    assert rows[0].tombstoned_at is not None
    assert rows[0].tombstoned_reason == "retention_expired"
    purge_audits = [a for a in _fetch_all(db_url, AuditLog) if a.action == "pcap.purged"]
    assert purge_audits and purge_audits[0].detail["sha256"] == "a" * 64


def test_purge_expired_skips_fresh_captures(
    eager_celery: None, db_url: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "pcap_dir", tmp_path)
    fresh_file = tmp_path / "fresh.pcap"
    fresh_file.write_bytes(b"fresh")
    _seed_pcap(
        db_url,
        capture_id=uuid.uuid4(),
        storage_path=str(fresh_file),
        started_at=datetime.now(UTC),
        retention_days=30,
    )
    result = tasks.purge_expired()
    assert result["expired"] == 0
    assert fresh_file.exists()
