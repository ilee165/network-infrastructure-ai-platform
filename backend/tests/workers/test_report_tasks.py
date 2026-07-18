"""Report engine Celery tasks (P4 W3-T1; ADR-0053 §2/§4/§6) — eager mode.

No Docker, no network: tasks run against a file-backed aiosqlite database via
the ``_make_engine`` seam (the config-tasks harness pattern). The PDF renderer's
native step is stubbed at ``_render_pdf`` ONLY — the redaction choke point and
the CSV renderer inside the single render path stay REAL, so the fail-closed
proof here exercises the production enforcement, not a fake.

Covers: claim-row semantics (claimed / skipped / resumed / reclaimed),
scheduled-period computation, artifact persistence (sha256 + expiry), the
fail-closed redaction path (typed error class, field-path-only audit, no
partial artifact), the retention purge, and the compliance sweep's secret-free
§7.2 history.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.engines.reports import deterministic_run_id, scheduled_period
from app.engines.reports.payloads import ReportPayload, ReportSection
from app.models import AuditLog, Base, Device, DeviceStatus
from app.models.compliance_history import ComplianceRun, ComplianceRunFinding
from app.models.config_mgmt import ConfigSnapshot, ConfigSource
from app.models.reports import ReportArtifact, ReportKind, ReportRun, ReportRunStatus
from app.workers.celery_app import celery_app
from app.workers.tasks import reports as tasks

_START = "2026-07-01T00:00:00+00:00"
_END = "2026-07-08T00:00:00+00:00"
_START_DT = datetime(2026, 7, 1, tzinfo=UTC)
_END_DT = datetime(2026, 7, 8, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures (config-tasks harness pattern)
# ---------------------------------------------------------------------------


@pytest.fixture()
def eager_celery() -> Iterator[None]:
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = previous


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'reports.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


@pytest.fixture()
def stub_pdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub ONLY the native-lib PDF step; redaction + CSV stay real."""
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")


def _query_all(db_url: str, stmt: Any) -> list[Any]:
    async def _go() -> list[Any]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(stmt)).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


def _seed(db_url: str, *instances: Any) -> None:
    async def _go() -> None:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            session.add_all(instances)
            await session.commit()
        await engine.dispose()

    asyncio.run(_go())


def _audit_actions(db_url: str) -> list[str]:
    return [row.action for row in _query_all(db_url, select(AuditLog))]


_RUN_ID = deterministic_run_id(ReportKind.CHANGE, _START_DT, _END_DT)


# ---------------------------------------------------------------------------
# Generation + claim-row semantics (ADR-0053 §2)
# ---------------------------------------------------------------------------


def test_generate_succeeds_and_persists_artifacts(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    result = tasks.generate.run("change", _START, _END, "on_demand", None)
    assert result["status"] == "succeeded"
    assert result["run_id"] == str(_RUN_ID)

    runs = _query_all(db_url, select(ReportRun))
    assert len(runs) == 1
    run = runs[0]
    assert run.status == ReportRunStatus.SUCCEEDED.value
    assert run.kind == "change"
    assert run.regime_tags == ["soc2:CC8.1"]
    assert run.finished_at is not None

    artifacts = _query_all(db_url, select(ReportArtifact))
    assert sorted(a.format for a in artifacts) == ["csv", "pdf"]
    for artifact in artifacts:
        assert artifact.run_id == _RUN_ID
        assert len(artifact.sha256) == 64
        assert artifact.size_bytes == len(artifact.content)
        # 7-year PROPOSED default retention (ADR-0053 §4).
        assert artifact.expires_at > datetime.now(UTC) + timedelta(days=2500)

    assert _audit_actions(db_url).count("report.generated") == 1


def test_duplicate_delivery_skips_without_second_artifact_or_audit(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    first = tasks.generate.run("change", _START, _END, "on_demand", None)
    assert first["status"] == "succeeded"
    second = tasks.generate.run("change", _START, _END, "scheduled", None)
    assert second["status"] == "skipped"

    assert len(_query_all(db_url, select(ReportArtifact))) == 2  # one csv + one pdf
    assert _audit_actions(db_url).count("report.generated") == 1


def test_stale_running_claim_is_resumed_not_lost(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    """A claim left ``running`` by a dead worker is recovered on redelivery."""
    now = datetime.now(UTC)
    _seed(
        db_url,
        ReportRun(
            id=_RUN_ID,
            kind="change",
            trigger="scheduled",
            requested_by=None,
            period_start=_START_DT,
            period_end=_END_DT,
            status=ReportRunStatus.RUNNING.value,
            regime_tags=["soc2:CC8.1"],
            created_at=now,
            updated_at=now,
        ),
    )
    result = tasks.generate.run("change", _START, _END, "scheduled", None)
    assert result["status"] == "succeeded"
    runs = _query_all(db_url, select(ReportRun))
    assert len(runs) == 1
    assert runs[0].status == ReportRunStatus.SUCCEEDED.value


def test_failed_run_is_reclaimed_for_a_fresh_attempt(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    """Fail-closed redaction must not block a period FOREVER once fixed."""
    now = datetime.now(UTC)
    _seed(
        db_url,
        ReportRun(
            id=_RUN_ID,
            kind="change",
            trigger="on_demand",
            requested_by=None,
            period_start=_START_DT,
            period_end=_END_DT,
            status=ReportRunStatus.FAILED.value,
            error_class="redaction_violation",
            regime_tags=["soc2:CC8.1"],
            finished_at=now,
            created_at=now,
            updated_at=now,
        ),
    )
    result = tasks.generate.run("change", _START, _END, "on_demand", None)
    assert result["status"] == "succeeded"
    run = _query_all(db_url, select(ReportRun))[0]
    assert run.status == ReportRunStatus.SUCCEEDED.value
    assert run.error_class is None


def test_scheduled_periods_are_deterministic() -> None:
    now = datetime(2026, 7, 15, 5, 0, tzinfo=UTC)
    start, end = scheduled_period("weekly", now)
    assert (start, end) == (
        datetime(2026, 7, 8, tzinfo=UTC),
        datetime(2026, 7, 15, tzinfo=UTC),
    )
    start, end = scheduled_period("monthly", now)
    assert (start, end) == (
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 7, 1, tzinfo=UTC),
    )
    start, end = scheduled_period("daily", now)
    assert (start, end) == (
        datetime(2026, 7, 14, tzinfo=UTC),
        datetime(2026, 7, 15, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="unknown report cadence"):
        scheduled_period("hourly", now)


def test_generate_scheduled_uses_settings_cadence(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    result = tasks.generate_scheduled.run("change")
    assert result["status"] == "succeeded"
    run = _query_all(db_url, select(ReportRun))[0]
    assert run.trigger == "scheduled"
    assert run.requested_by is None
    # Default change cadence is weekly: a 7-day period ending at UTC midnight.
    assert run.period_end - run.period_start == timedelta(days=7)


# ---------------------------------------------------------------------------
# Fail-closed redaction (ADR-0053 §6): typed class, field path only, no artifact
# ---------------------------------------------------------------------------

_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"


def _planted_payload_builder(**_kwargs: Any) -> Any:
    async def _build(session: Any, **kwargs: Any) -> ReportPayload:
        return ReportPayload(
            kind=kwargs["kind"].value,
            title="Change Report",
            period_start=kwargs["period_start"],
            period_end=kwargs["period_end"],
            generated_at=kwargs["generated_at"],
            sections=(
                ReportSection(
                    title="Data",
                    columns=("Field", "Value"),
                    rows=(("blob", _PEM),),
                ),
            ),
        )

    return _build


def test_redaction_violation_fails_closed(
    eager_celery: None, db_url: str, stub_pdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks, "build_payload", _planted_payload_builder())

    result = tasks.generate.run("change", _START, _END, "on_demand", None)

    assert result["status"] == "failed"
    assert result["error_class"] == "redaction_violation"
    # No partial artifact was written (fail CLOSED).
    assert _query_all(db_url, select(ReportArtifact)) == []
    run = _query_all(db_url, select(ReportRun))[0]
    assert run.status == ReportRunStatus.FAILED.value
    assert run.error_class == "redaction_violation"

    # The audit entry names the FIELD PATH only — never the value.
    failures = [
        row
        for row in _query_all(db_url, select(AuditLog))
        if row.action == "report.generation_failed"
    ]
    assert len(failures) == 1
    detail = failures[0].detail
    assert detail["error_class"] == "redaction_violation"
    assert detail["field_path"] == "sections[0].rows[0][1]"
    assert "PRIVATE KEY" not in str(detail)


def test_builder_error_is_typed_not_freeform(
    eager_celery: None, db_url: str, stub_pdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(session: Any, **kwargs: Any) -> ReportPayload:
        raise RuntimeError("db exploded with secret-shaped text hunter2")

    monkeypatch.setattr(tasks, "build_payload", _boom)
    result = tasks.generate.run("change", _START, _END, "on_demand", None)
    assert result == {
        "run_id": str(_RUN_ID),
        "status": "failed",
        "error_class": "builder_error",
    }
    run = _query_all(db_url, select(ReportRun))[0]
    assert run.error_class == "builder_error"
    # The typed class — not the exception text — is all that persists.
    failures = [
        row
        for row in _query_all(db_url, select(AuditLog))
        if row.action == "report.generation_failed"
    ]
    assert "hunter2" not in str(failures[0].detail)


# ---------------------------------------------------------------------------
# Retention purge (ADR-0053 §4)
# ---------------------------------------------------------------------------


def test_purge_deletes_only_expired_artifacts_and_audits(
    eager_celery: None, db_url: str, stub_pdf: None
) -> None:
    tasks.generate.run("change", _START, _END, "on_demand", None)
    now = datetime.now(UTC)
    expired = ReportArtifact(
        run_id=_RUN_ID,
        format="csv",
        content=b"old",
        sha256="0" * 64,
        size_bytes=3,
        expires_at=now - timedelta(days=1),
    )
    _seed(db_url, expired)

    result = tasks.purge_expired.run()

    assert result == {"deleted": 1}
    remaining = _query_all(db_url, select(ReportArtifact))
    assert len(remaining) == 2  # the live csv+pdf pair survives
    assert all(a.expires_at > now for a in remaining)
    assert "report.purge_swept" in _audit_actions(db_url)


# ---------------------------------------------------------------------------
# Compliance sweep → §7.2 trend history (secret-free by construction)
# ---------------------------------------------------------------------------


def _seed_device_with_snapshot(db_url: str) -> UUID:
    device = Device(
        id=uuid4(),
        hostname="core-sw-01",
        mgmt_ip="10.0.0.1",
        vendor_id="cisco_ios",
        status=DeviceStatus.REACHABLE,
        site="hq",
    )
    snapshot = ConfigSnapshot(
        device_id=device.id,
        captured_at=datetime.now(UTC),
        source=ConfigSource.ON_DEMAND,
        content="hostname core-sw-01\nno service password-recovery\nend\n",
        content_hash="a" * 64,
    )
    _seed(db_url, device, snapshot)
    return device.id


def test_compliance_sweep_persists_secret_free_history(eager_celery: None, db_url: str) -> None:
    device_id = _seed_device_with_snapshot(db_url)

    result = tasks.compliance_sweep.run()

    assert result["status"] == "succeeded"
    assert result["devices"] == 1
    runs = _query_all(db_url, select(ComplianceRun))
    assert len(runs) == 1
    assert runs[0].trigger == "sweep"
    assert runs[0].device_scope == [str(device_id)]

    findings = _query_all(db_url, select(ComplianceRunFinding))
    assert len(findings) == result["findings"] > 0
    for finding in findings:
        assert finding.status in {"pass", "violation", "skipped"}
        assert finding.severity in {"info", "warn", "violation"}
    # Secret-free BY CONSTRUCTION (ADR-0053 §6 layer 3): the history table has
    # no evidence-excerpt column at all — nothing to redact, nothing to leak.
    assert "evidence" not in ComplianceRunFinding.__table__.columns
    assert "compliance.sweep_completed" in _audit_actions(db_url)


def test_compliance_sweep_redelivery_is_idempotent(eager_celery: None, db_url: str) -> None:
    _seed_device_with_snapshot(db_url)
    first = tasks.compliance_sweep.run()
    assert first["status"] == "succeeded"
    second = tasks.compliance_sweep.run()
    assert second["status"] == "skipped"
    assert len(_query_all(db_url, select(ComplianceRun))) == 1
    assert len(_query_all(db_url, select(ComplianceRunFinding))) == first["findings"]


def test_device_without_snapshot_is_skipped(eager_celery: None, db_url: str) -> None:
    _seed(
        db_url,
        Device(
            hostname="bare-device",
            mgmt_ip="10.0.0.2",
            vendor_id="cisco_ios",
            status=DeviceStatus.REACHABLE,
        ),
    )
    result = tasks.compliance_sweep.run()
    assert result["status"] == "succeeded"
    assert result["devices"] == 0
    assert result["findings"] == 0
