"""Report API surface (P4 W3-T1; ADR-0053 §2/§3): per-kind RBAC at generation
AND download, audited requests/downloads, RBAC-scoped listing, and the
download-time role-revocation regression (no stale-authz caching).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.reports as reports_module
from app.engines.reports import deterministic_run_id
from app.models import AuditLog, Role, User
from app.models.reports import ReportArtifact, ReportKind, ReportRun, ReportRunStatus

_START = datetime(2026, 7, 1, tzinfo=UTC)
_END = datetime(2026, 7, 8, tzinfo=UTC)


@pytest.fixture()
def sent_tasks(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record Celery dispatches instead of touching a broker."""
    calls: list[dict[str, Any]] = []

    def _record(name: str, args: list[Any] | None = None, **kwargs: Any) -> None:
        calls.append({"name": name, "args": list(args or []), **kwargs})

    monkeypatch.setattr(reports_module.celery_app, "send_task", _record)
    return calls


async def _seed_run(
    session: AsyncSession,
    *,
    kind: ReportKind = ReportKind.CHANGE,
    with_artifact: bool = True,
) -> tuple[ReportRun, ReportArtifact | None]:
    run = ReportRun(
        id=deterministic_run_id(kind, _START, _END),
        kind=kind.value,
        trigger="on_demand",
        requested_by=None,
        period_start=_START,
        period_end=_END,
        status=ReportRunStatus.SUCCEEDED.value,
        regime_tags=["soc2:CC8.1"],
        finished_at=_END,
    )
    session.add(run)
    artifact: ReportArtifact | None = None
    if with_artifact:
        artifact = ReportArtifact(
            run_id=run.id,
            format="csv",
            content=b"report,change\r\n",
            sha256="c" * 64,
            size_bytes=15,
            expires_at=_END + timedelta(days=2557),
        )
        session.add(artifact)
    await session.flush()
    return run, artifact


def _body(kind: str) -> dict[str, str]:
    return {
        "kind": kind,
        "period_start": _START.isoformat(),
        "period_end": _END.isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /reports — per-kind floor at the generation trigger
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "kind", "expected"),
    [
        ("viewer", "change", 403),
        ("operator", "change", 403),
        ("engineer", "change", 202),
        ("admin", "change", 202),
        ("engineer", "compliance_posture", 202),
        ("engineer", "access_review", 403),
        ("admin", "access_review", 202),
        ("engineer", "audit_integrity", 403),
        ("admin", "audit_integrity", 202),
    ],
)
async def test_generation_floor_per_kind(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    sent_tasks: list[dict[str, Any]],
    role: str,
    kind: str,
    expected: int,
) -> None:
    response = await client.post("/api/v1/reports", json=_body(kind), headers=auth_headers(role))
    assert response.status_code == expected
    if expected == 202:
        payload = response.json()
        assert payload["status"] == "queued"
        assert payload["run_id"] == str(deterministic_run_id(ReportKind(kind), _START, _END))
        assert sent_tasks and sent_tasks[-1]["name"] == "reports.generate"
    else:
        assert sent_tasks == []  # a denied request must never enqueue


async def test_generation_request_is_audited(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
    sent_tasks: list[dict[str, Any]],
    users: dict[str, User],
) -> None:
    response = await client.post(
        "/api/v1/reports", json=_body("change"), headers=auth_headers("engineer")
    )
    assert response.status_code == 202
    rows = [
        row
        for row in (await session.execute(select(AuditLog))).scalars()
        if row.action == "report.generation_requested"
    ]
    assert len(rows) == 1
    assert rows[0].actor == f"user:{users['engineer'].username}"
    assert rows[0].detail["kind"] == "change"
    # The enqueued task carries the requesting user id (invoking-user RBAC).
    assert sent_tasks[-1]["args"][-1] == str(users["engineer"].id)


async def test_generation_rejects_inverted_period(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    sent_tasks: list[dict[str, Any]],
) -> None:
    body = {
        "kind": "change",
        "period_start": _END.isoformat(),
        "period_end": _START.isoformat(),
    }
    response = await client.post("/api/v1/reports", json=body, headers=auth_headers("engineer"))
    assert response.status_code == 422
    assert sent_tasks == []


# ---------------------------------------------------------------------------
# Listing + detail — RBAC-scoped visibility
# ---------------------------------------------------------------------------


async def test_listing_is_scoped_to_visible_kinds(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
) -> None:
    for kind in ReportKind:
        await _seed_run(session, kind=kind, with_artifact=False)

    engineer_view = await client.get("/api/v1/reports", headers=auth_headers("engineer"))
    assert engineer_view.status_code == 200
    kinds = {item["kind"] for item in engineer_view.json()["items"]}
    assert kinds == {"change", "compliance_posture"}

    admin_view = await client.get("/api/v1/reports", headers=auth_headers("admin"))
    assert {i["kind"] for i in admin_view.json()["items"]} == {k.value for k in ReportKind}

    # Explicitly requesting an above-floor kind is a 403, not an empty page.
    denied = await client.get(
        "/api/v1/reports", params={"kind": "access_review"}, headers=auth_headers("engineer")
    )
    assert denied.status_code == 403


async def test_run_detail_enforces_kind_floor(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
) -> None:
    run, _ = await _seed_run(session, kind=ReportKind.ACCESS_REVIEW)
    denied = await client.get(f"/api/v1/reports/{run.id}", headers=auth_headers("engineer"))
    assert denied.status_code == 403
    allowed = await client.get(f"/api/v1/reports/{run.id}", headers=auth_headers("admin"))
    assert allowed.status_code == 200
    detail = allowed.json()
    assert detail["kind"] == "access_review"
    assert len(detail["artifacts"]) == 1
    assert detail["artifacts"][0]["sha256"] == "c" * 64


async def test_unknown_run_and_artifact_are_404(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
) -> None:
    missing = uuid.uuid4()
    assert (
        await client.get(f"/api/v1/reports/{missing}", headers=auth_headers("admin"))
    ).status_code == 404
    run, _ = await _seed_run(session)
    assert (
        await client.get(
            f"/api/v1/reports/{run.id}/artifacts/{missing}", headers=auth_headers("engineer")
        )
    ).status_code == 404


# ---------------------------------------------------------------------------
# Download — bytes out, audited, floor re-evaluated at download time
# ---------------------------------------------------------------------------


async def test_download_returns_bytes_and_audits(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
    users: dict[str, User],
) -> None:
    run, artifact = await _seed_run(session)
    assert artifact is not None
    response = await client.get(
        f"/api/v1/reports/{run.id}/artifacts/{artifact.id}", headers=auth_headers("engineer")
    )
    assert response.status_code == 200
    assert response.content == b"report,change\r\n"
    assert response.headers["content-type"].startswith("text/csv")
    assert "change-2026-07-08.csv" in response.headers["content-disposition"]

    downloads = [
        row
        for row in (await session.execute(select(AuditLog))).scalars()
        if row.action == "report.artifact_downloaded"
    ]
    assert len(downloads) == 1
    assert downloads[0].actor == f"user:{users['engineer'].username}"
    assert downloads[0].detail["sha256"] == "c" * 64
    assert downloads[0].detail["kind"] == "change"


async def test_role_revoked_between_generation_and_download_is_denied(
    client: httpx.AsyncClient,
    auth_headers: Callable[[str], dict[str, str]],
    session: AsyncSession,
    users: dict[str, User],
) -> None:
    """ADR-0053 §3: the floor is re-evaluated at download time — no stale authz.

    The SAME bearer token that could download while the user held engineer is
    denied after the role is revoked to viewer: authorization is resolved from
    the database on every request, never cached from generation time.
    """
    run, artifact = await _seed_run(session)
    assert artifact is not None
    url = f"/api/v1/reports/{run.id}/artifacts/{artifact.id}"
    headers = auth_headers("engineer")

    assert (await client.get(url, headers=headers)).status_code == 200

    # Revoke: demote the engineer to viewer (same user id, same token).
    viewer_role = (await session.execute(select(Role).where(Role.name == "viewer"))).scalar_one()
    users["engineer"].role = viewer_role
    await session.flush()

    assert (await client.get(url, headers=headers)).status_code == 403
