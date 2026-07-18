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
from app.models import Base
from app.models.reports import ReportArtifact, ReportKind, ReportRun, ReportRunStatus

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


async def test_get_run_enforces_the_kind_floor(seeded_db: None, engineer_identity: None) -> None:
    allowed_id = deterministic_run_id(ReportKind.CHANGE, _START, _END)
    fetched = json.loads(await get_report_run.ainvoke({"run_id": str(allowed_id)}))
    assert fetched["run_id"] == str(allowed_id)

    denied_id = deterministic_run_id(ReportKind.ACCESS_REVIEW, _START, _END)
    with pytest.raises(ReportAccessDeniedError):
        await get_report_run.ainvoke({"run_id": str(denied_id)})


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
