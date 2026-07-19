"""Documentation-Agent report tools (P4 W3-T1; ADR-0053 §1/§3).

The agent TRIGGERS and CITES reports under the INVOKING user's RBAC: the
framework read facade enforces the per-kind role floor against the role bound
by ``agent_run_context``, listing excludes above-floor kinds, artifact CONTENT
is never exposed (metadata + sha256 only), and the generation trigger enqueues
the SAME engine task with the invoking user id recorded.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.db as db
from app.agents.documentation.tools import (
    get_report_run,
    list_report_runs,
    request_report_generation,
)
from app.agents.framework.read_facade import ReportAccessDeniedError
from app.agents.framework.tools import agent_run_context
from app.core.security import Role
from app.engines.reports import deterministic_run_id
from app.models import AuditLog, Base
from app.models.reports import ReportArtifact, ReportKind, ReportRun, ReportRunStatus


async def _generation_audit_rows() -> list[AuditLog]:
    """The committed ``report.generation_requested`` rows in the wired test DB."""
    async with db.get_sessionmaker()() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
    return [row for row in rows if row.action == "report.generation_requested"]


_START = datetime(2026, 7, 1, tzinfo=UTC)
_END = datetime(2026, 7, 8, tzinfo=UTC)


@pytest.fixture()
def seeded_db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """File-backed schema with one run (+artifact) per kind; facade wired to it."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'agent-reports.sqlite'}"
    engine = create_async_engine(url)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as session:
            for kind in ReportKind:
                run = ReportRun(
                    id=deterministic_run_id(kind, _START, _END),
                    kind=kind.value,
                    trigger="scheduled",
                    requested_by=None,
                    period_start=_START,
                    period_end=_END,
                    status=ReportRunStatus.SUCCEEDED.value,
                    regime_tags=["soc2:CC8.1"],
                    finished_at=_END,
                )
                session.add(run)
                session.add(
                    ReportArtifact(
                        run_id=run.id,
                        format="csv",
                        content=b"secret-free,cells\r\n",
                        sha256="d" * 64,
                        size_bytes=19,
                        expires_at=_END,
                    )
                )
            await session.commit()

    import asyncio

    asyncio.run(_setup())
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    yield
    asyncio.run(engine.dispose())


@pytest.fixture()
def engineer_identity() -> Iterator[None]:
    with agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()):
        yield


async def test_list_excludes_kinds_above_the_invoking_role(
    seeded_db: None, engineer_identity: None
) -> None:
    result = json.loads(await list_report_runs.ainvoke({}))
    kinds = {run["kind"] for run in result["runs"]}
    assert kinds == {"change", "compliance_posture"}
    # Metadata only: sha256 for citation, never artifact content bytes.
    artifact = result["runs"][0]["artifacts"][0]
    assert artifact["sha256"] == "d" * 64
    assert "content" not in artifact


async def test_list_shows_all_kinds_to_admin(seeded_db: None) -> None:
    with agent_run_context(role=Role.ADMIN):
        result = json.loads(await list_report_runs.ainvoke({}))
    assert {run["kind"] for run in result["runs"]} == {k.value for k in ReportKind}


async def test_explicit_above_floor_kind_is_denied(
    seeded_db: None, engineer_identity: None
) -> None:
    with pytest.raises(ReportAccessDeniedError):
        await list_report_runs.ainvoke({"kind": "access_review"})


async def test_get_run_above_floor_is_indistinguishable_from_missing(
    seeded_db: None, engineer_identity: None
) -> None:
    """Existence is RBAC-scoped (ADR-0053 §3): run ids are computable OFFLINE
    (``deterministic_run_id``), so an above-floor run must resolve exactly like
    a missing one — a distinct denial would confirm which admin-only report
    periods exist to a sub-floor caller (PR #166 F3)."""
    allowed_id = deterministic_run_id(ReportKind.CHANGE, _START, _END)
    fetched = json.loads(await get_report_run.ainvoke({"run_id": str(allowed_id)}))
    assert fetched["run_id"] == str(allowed_id)

    denied_id = deterministic_run_id(ReportKind.ACCESS_REVIEW, _START, _END)
    missing_id = uuid.uuid4()
    denied = json.loads(await get_report_run.ainvoke({"run_id": str(denied_id)}))
    missing = json.loads(await get_report_run.ainvoke({"run_id": str(missing_id)}))
    assert set(denied) == set(missing) == {"error"}
    # Identical response shape modulo the probed id — nothing to distinguish.
    assert denied["error"].replace(str(denied_id), "<id>") == missing["error"].replace(
        str(missing_id), "<id>"
    )


async def test_get_run_admin_still_sees_above_floor_kinds(seeded_db: None) -> None:
    run_id = deterministic_run_id(ReportKind.ACCESS_REVIEW, _START, _END)
    with agent_run_context(role=Role.ADMIN):
        fetched = json.loads(await get_report_run.ainvoke({"run_id": str(run_id)}))
    assert fetched["run_id"] == str(run_id)


async def test_request_generation_enqueues_under_invoking_user(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.workers import celery_app as celery_module

    calls: list[dict[str, Any]] = []

    def _record(name: str, args: list[Any] | None = None, **kwargs: Any) -> None:
        calls.append({"name": name, "args": list(args or []), **kwargs})

    monkeypatch.setattr(celery_module.celery_app, "send_task", _record)

    user_id = uuid.uuid4()
    with agent_run_context(role=Role.ENGINEER, user_id=user_id):
        result = json.loads(
            await request_report_generation.ainvoke(
                {
                    "kind": "change",
                    "period_start": _START.isoformat(),
                    "period_end": _END.isoformat(),
                }
            )
        )

    assert result == {
        "run_id": str(deterministic_run_id(ReportKind.CHANGE, _START, _END)),
        "status": "queued",
    }
    assert len(calls) == 1
    call = calls[0]
    assert call["name"] == "reports.generate"
    assert call["queue"] == "docs"
    # The SAME engine task vector the API uses, with the invoking user recorded.
    assert call["args"] == [
        "change",
        _START.isoformat(),
        _END.isoformat(),
        "on_demand",
        str(user_id),
    ]
    # Durable-audit parity with POST /api/v1/reports (PR #166 F3): the agent
    # path records the same committed generation_requested event, attributed
    # to the requesting principal.
    rows = await _generation_audit_rows()
    assert len(rows) == 1
    assert rows[0].actor == f"user:{user_id}"
    assert rows[0].target_type == "report_run"
    assert rows[0].target_id == str(deterministic_run_id(ReportKind.CHANGE, _START, _END))
    assert rows[0].detail == {
        "kind": "change",
        "period_start": _START.isoformat(),
        "period_end": _END.isoformat(),
    }


async def test_request_generation_audit_is_committed_before_dispatch(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit row is durable BEFORE the broker call: a dispatch failure can
    never lose the evidence that the generation was requested (PR #166 F3)."""
    from app.workers import celery_app as celery_module

    def _broker_down(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("broker unreachable")

    monkeypatch.setattr(celery_module.celery_app, "send_task", _broker_down)
    user_id = uuid.uuid4()
    with (
        agent_run_context(role=Role.ENGINEER, user_id=user_id),
        pytest.raises(RuntimeError, match="broker unreachable"),
    ):
        await request_report_generation.ainvoke(
            {
                "kind": "change",
                "period_start": _START.isoformat(),
                "period_end": _END.isoformat(),
            }
        )
    rows = await _generation_audit_rows()
    assert len(rows) == 1  # committed despite the failed dispatch
    assert rows[0].actor == f"user:{user_id}"


async def test_request_generation_pins_naive_period_as_utc(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Naive ISO periods are pinned as UTC — the run id matches the worker's.

    Regression: the tool derived the run id via host-local interpretation of
    naive datetimes while the worker pins them as UTC, so the agent cited (and
    polled) a run id the worker never creates on any non-UTC host.
    """
    from app.workers import celery_app as celery_module

    calls: list[dict[str, Any]] = []

    def _record(name: str, args: list[Any] | None = None, **kwargs: Any) -> None:
        calls.append({"name": name, "args": list(args or []), **kwargs})

    monkeypatch.setattr(celery_module.celery_app, "send_task", _record)

    with agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()):
        result = json.loads(
            await request_report_generation.ainvoke(
                {
                    "kind": "change",
                    "period_start": "2026-07-01T00:00:00",  # naive: no offset
                    "period_end": "2026-07-08T00:00:00",
                }
            )
        )

    assert result["run_id"] == str(deterministic_run_id(ReportKind.CHANGE, _START, _END))
    # Serialized aware-UTC, so the worker's _parse_utc derives the SAME id.
    assert calls[0]["args"][1] == _START.isoformat()
    assert calls[0]["args"][2] == _END.isoformat()


async def test_request_generation_rejects_future_period_end(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A not-yet-complete period is refused before anything is enqueued."""
    from datetime import timedelta

    from app.workers import celery_app as celery_module

    calls: list[Any] = []
    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *a, **k: calls.append(1))
    now = datetime.now(UTC)
    with (
        agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()),
        pytest.raises(ValueError, match="future"),
    ):
        await request_report_generation.ainvoke(
            {
                "kind": "change",
                "period_start": (now - timedelta(days=1)).isoformat(),
                "period_end": (now + timedelta(days=1)).isoformat(),
            }
        )
    assert calls == []  # a rejected period never reaches the broker


async def test_request_generation_denied_below_floor(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.workers import celery_app as celery_module

    calls: list[Any] = []
    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *a, **k: calls.append(1))
    with agent_run_context(role=Role.ENGINEER), pytest.raises(ReportAccessDeniedError):
        await request_report_generation.ainvoke(
            {
                "kind": "audit_integrity",
                "period_start": _START.isoformat(),
                "period_end": _END.isoformat(),
            }
        )
    assert calls == []  # a denied request never reaches the broker
    assert await _generation_audit_rows() == []  # ...and is never audited


async def test_request_generation_rejects_over_cap_span(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The facade path enforces the same span cap as the API schema (PR #166
    F3): builders materialize one tuple per period day, so an unbounded span
    is an unbounded-memory vector on the worker."""
    from datetime import timedelta

    from app.workers import celery_app as celery_module

    calls: list[Any] = []
    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *a, **k: calls.append(1))
    with (
        agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()),
        pytest.raises(ValueError, match="span"),
    ):
        await request_report_generation.ainvoke(
            {
                "kind": "change",
                "period_start": (_END - timedelta(days=401)).isoformat(),
                "period_end": _END.isoformat(),
            }
        )
    assert calls == []  # a rejected span never reaches the broker


async def test_request_generation_accepts_at_cap_span(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly 400 days (annual report + slack) is allowed — the cap is a
    boundary, not an off-by-one."""
    from datetime import timedelta

    from app.workers import celery_app as celery_module

    calls: list[Any] = []
    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *a, **k: calls.append(1))
    with agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()):
        result = json.loads(
            await request_report_generation.ainvoke(
                {
                    "kind": "change",
                    "period_start": (_END - timedelta(days=400)).isoformat(),
                    "period_end": _END.isoformat(),
                }
            )
        )
    assert result["status"] == "queued"
    assert calls == [1]


async def test_request_generation_rejects_pre_floor_period_start(
    seeded_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A period_start before the platform-epoch floor is refused."""
    from app.workers import celery_app as celery_module

    calls: list[Any] = []
    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *a, **k: calls.append(1))
    with (
        agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()),
        pytest.raises(ValueError, match="period_start"),
    ):
        await request_report_generation.ainvoke(
            {
                "kind": "change",
                "period_start": "2019-12-31T00:00:00+00:00",
                "period_end": "2020-01-05T00:00:00+00:00",
            }
        )
    assert calls == []


async def test_unbound_identity_is_denied_by_default(seeded_db: None) -> None:
    """No bound identity -> no visible kinds (deny-by-default, brief §7)."""
    result = json.loads(await list_report_runs.ainvoke({}))
    assert result == {"runs": []}
    with pytest.raises(ReportAccessDeniedError):
        await request_report_generation.ainvoke(
            {
                "kind": "change",
                "period_start": _START.isoformat(),
                "period_end": _END.isoformat(),
            }
        )
