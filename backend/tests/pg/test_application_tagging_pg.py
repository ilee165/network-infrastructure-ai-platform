"""Manual application-tagging (W2-T3) semantics re-asserted under REAL PostgreSQL.

The SQLite unit suite (``tests/api/test_applications.py``) is the fast smoke;
this module drives the REAL tagging API (the FastAPI app with ``get_db``
overridden onto the PG harness session) against the migrated schema so the two
PG-bound behaviors the task names are proven on the production backend
(P4-PLAN §0a "SQLite hides PG semantics"):

1. **Cascade delete** — deleting a ``manual`` application removes its
   dependency rows via the migration-created ``ON DELETE CASCADE`` (not the
   SQLite pragma emulation), with the cascade recorded in the
   ``application.delete`` audit entry.
2. **Audit ordering** — the tagging mutations append hash-chained entries whose
   ``seq`` is strictly monotonic in true mutation order under the PG
   advisory-lock writer, the full sequence verifies clean, and a tampered
   tagging entry breaks verification (negative control; the UPDATE is possible
   here only because the harness connects as the table owner, whom the
   ``REVOKE UPDATE`` does not bind — exactly the privileged-tamper case the
   chain exists to catch).

Secret-surface: tag payloads are names/owner strings/row references only; no
fixture or assertion here contains secret material.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.config import Settings
from app.core.security import create_access_token
from app.models import Application, ApplicationDependency, AuditLog, Device, Role, User
from app.services import audit
from app.services.audit.verify import verify_chain

pytestmark = pytest.mark.integration

BASE = "/api/v1/applications"

TAGGING_ACTIONS = (
    audit.APPLICATION_CREATE,
    audit.APPLICATION_DEPENDENCY_CREATE,
    audit.APPLICATION_UPDATE,
    audit.APPLICATION_DEPENDENCY_DELETE,
    audit.APPLICATION_DELETE,
)


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="pg-tagging-harness-secret-key-0000",
        access_token_expire_minutes=5,
    )


@pytest.fixture()
async def engineer(pg_session: AsyncSession) -> User:
    """One engineer user referencing the migration-seeded ``engineer`` role."""
    role = (await pg_session.execute(select(Role).where(Role.name == "engineer"))).scalar_one()
    user = User(
        username=f"pg-tagging-eng-{uuid.uuid4().hex[:8]}",
        password_hash="not-a-real-hash",  # never authenticated with; tokens are minted directly
        role_id=role.id,
    )
    pg_session.add(user)
    await pg_session.commit()
    return user


@pytest.fixture()
async def client(settings: Settings, pg_session: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    """The real app over the PG harness session (``get_db`` overridden)."""
    from app.main import create_app

    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield pg_session

    application.dependency_overrides[deps.get_db] = _override_db
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


def _headers(user: User, settings: Settings, role: str = "engineer") -> dict[str, str]:
    token = create_access_token(
        str(user.id), settings, extra_claims={"type": "access", "roles": [role]}
    )
    return {"Authorization": f"Bearer {token}"}


async def _run_tagging_sequence(
    client: httpx.AsyncClient, headers: dict[str, str], pg_session: AsyncSession
) -> tuple[str, str]:
    """Create app → tag a device → update → untag → delete; return (app_id, dep_id)."""
    device = Device(
        hostname=f"pg-sw-{uuid.uuid4().hex[:8]}",
        mgmt_ip=f"198.51.100.{uuid.uuid4().int % 200 + 10}",
    )
    pg_session.add(device)
    await pg_session.commit()

    created = await client.post(
        BASE,
        json={"name": f"pg-payroll-{uuid.uuid4().hex[:8]}", "owner": "team-hr", "fqdns": []},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    app_id = created.json()["id"]
    # The create ETag is still current: tagging a dependency below does not touch
    # the application row, so it preconditions the PATCH that follows.
    etag = created.json()["updated_at"]

    dep = await client.post(
        f"{BASE}/{app_id}/dependencies",
        json={"target_kind": "device", "target_ref": str(device.id)},
        headers=headers,
    )
    assert dep.status_code == 201, dep.text
    dep_id = dep.json()["id"]

    patched = await client.patch(
        f"{BASE}/{app_id}",
        json={"owner": "team-fin"},
        headers={**headers, "If-Match": f'"{etag}"'},
    )
    assert patched.status_code == 200, patched.text

    removed = await client.delete(f"{BASE}/{app_id}/dependencies/{dep_id}", headers=headers)
    assert removed.status_code == 204, removed.text

    deleted = await client.delete(f"{BASE}/{app_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    return app_id, dep_id


async def test_manual_delete_cascades_on_real_pg_and_audit_seq_is_mutation_ordered(
    client: httpx.AsyncClient,
    pg_session: AsyncSession,
    engineer: User,
    settings: Settings,
) -> None:
    """Real ``ON DELETE CASCADE`` + strictly-``seq``-ordered tagging audit trail."""
    headers = _headers(engineer, settings)

    # A second application whose dependency must SURVIVE the other app's delete
    # (the cascade is scoped to the deleted row, not the table).
    survivor_device = Device(hostname="pg-survivor-sw", mgmt_ip="198.51.100.250")
    pg_session.add(survivor_device)
    await pg_session.commit()
    survivor = await client.post(
        BASE, json={"name": f"pg-survivor-{uuid.uuid4().hex[:8]}", "fqdns": []}, headers=headers
    )
    assert survivor.status_code == 201
    survivor_dep = await client.post(
        f"{BASE}/{survivor.json()['id']}/dependencies",
        json={"target_kind": "device", "target_ref": str(survivor_device.id)},
        headers=headers,
    )
    assert survivor_dep.status_code == 201

    app_id, dep_id = await _run_tagging_sequence(client, headers, pg_session)

    # Cascade: the deleted app is gone; the audited cascade names any rows it took.
    pg_session.expire_all()
    assert await pg_session.get(Application, uuid.UUID(app_id)) is None
    remaining = (await pg_session.execute(select(ApplicationDependency))).scalars().all()
    assert [str(row.id) for row in remaining] == [survivor_dep.json()["id"]]

    # Audit ordering: the tagging entries appear in true mutation order with
    # strictly increasing seq (the PG advisory-lock append path).
    rows = (
        (
            await pg_session.execute(
                select(AuditLog).where(AuditLog.action.in_(TAGGING_ACTIONS)).order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )
    actions = [row.action for row in rows]
    assert actions == [
        audit.APPLICATION_CREATE,  # survivor app
        audit.APPLICATION_DEPENDENCY_CREATE,  # survivor dep
        audit.APPLICATION_CREATE,
        audit.APPLICATION_DEPENDENCY_CREATE,
        audit.APPLICATION_UPDATE,
        audit.APPLICATION_DEPENDENCY_DELETE,
        audit.APPLICATION_DELETE,
    ]
    seqs = [row.seq for row in rows]
    assert all(later > earlier for earlier, later in zip(seqs, seqs[1:], strict=False))

    # The delete entry carries the before-state; its cascade list is empty here
    # because the dependency was explicitly untagged first (its own entry above).
    delete_entry = rows[-1]
    assert delete_entry.target_id == app_id
    assert delete_entry.detail is not None and delete_entry.detail["cascaded_dependencies"] == []

    # Chain membership: the whole tagging sequence verifies clean on real bytea
    # columns + the PG seq keyset walk.
    result = await verify_chain(pg_session)
    assert result.ok, result.break_
    assert result.checked == len(rows)


async def test_tampered_tagging_entry_breaks_chain_verification_on_pg(
    client: httpx.AsyncClient,
    pg_session: AsyncSession,
    engineer: User,
    settings: Settings,
) -> None:
    """Negative control: a privileged UPDATE of a tagging entry is DETECTED.

    The harness connects as the table owner, whom the migration's
    ``REVOKE UPDATE ... FROM PUBLIC`` does not bind — the hash chain is the
    backstop for exactly this actor (ADR-0038).
    """
    headers = _headers(engineer, settings)
    _, dep_id = await _run_tagging_sequence(client, headers, pg_session)

    target = (
        await pg_session.execute(
            select(AuditLog).where(AuditLog.action == audit.APPLICATION_DEPENDENCY_CREATE)
        )
    ).scalar_one()
    await pg_session.execute(
        update(AuditLog)
        .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
        .values(detail={"after": {"target_ref": "attacker-swapped-ref", "dep": dep_id}})
    )
    await pg_session.commit()
    pg_session.expire_all()

    result = await verify_chain(pg_session)
    assert not result.ok
    assert result.break_ is not None
    assert result.break_.reason == "entry_hash_mismatch"
    assert result.break_.entry_id == str(target.id)
