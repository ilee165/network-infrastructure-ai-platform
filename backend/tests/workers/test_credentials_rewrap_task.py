"""Worker shell test for the KEK re-wrap task (P1 W6-T3).

The ``credentials.re_wrap_keys`` Celery task is exercised eagerly with its
module-level seams (``_make_engine`` / ``_key_provider``) pointed at a file-backed
aiosqlite database (each task phase opens its own event loop via ``asyncio.run``,
so the schema must live in a file, not a per-connection in-memory DB) and the
W6-T2 deterministic Vault fake — no Redis, no Postgres, no network. Asserts the
worker drives the service pass end-to-end and returns a JSON-safe versions/counts
summary with no key material.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.crypto import HashiCorpVaultTransitKeyProvider
from app.models import AuditLog, Base
from app.models.inventory import CredentialKind, DeviceCredential
from app.services.credentials import service as vault
from app.workers.tasks import credentials as task
from tests.core.test_kms_providers import _FakeVaultTransitClient

_SECRET = "w0rker-r3wrap-secret!"


def _provider(client: _FakeVaultTransitClient) -> HashiCorpVaultTransitKeyProvider:
    return HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key="netops-kek", client=client
    )


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    """File-backed aiosqlite URL with the schema created; seams point at it."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'rewrap.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(task, "_make_engine", lambda: create_async_engine(url))
    return url


def _seed(db_url: str, provider: HashiCorpVaultTransitKeyProvider, n: int) -> None:
    async def _go() -> None:
        engine = create_async_engine(db_url)
        try:
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as session:
                for i in range(n):
                    await vault.create_credential(
                        session,
                        provider,
                        name=f"c{i}",
                        kind=CredentialKind.SSH,
                        username="netops",
                        secret=f"{_SECRET}-{i}",
                        params=None,
                        actor="user:alice",
                    )
                await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_go())


def test_re_wrap_keys_task_migrates_and_returns_summary(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The task re-wraps the corpus and returns a no-key-material versions summary."""
    client = _FakeVaultTransitClient(current_version=1)
    _seed(db_url, _provider(client), 3)
    client.current_version = 2  # operator/KMS bump
    monkeypatch.setattr(task, "_key_provider", lambda: _provider(client))

    summary = task.re_wrap_keys()
    assert summary == {
        "from_version": "netops-kek:v1",
        "to_version": "netops-kek:v2",
        "row_count": 3,
        "rows_migrated": 3,
    }
    assert _SECRET not in str(summary)

    async def _verify() -> None:
        engine = create_async_engine(db_url)
        try:
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as session:
                rows = (await session.execute(select(DeviceCredential))).scalars().all()
                assert {r.kek_version for r in rows} == {"netops-kek:v2"}
                actions = {
                    r.action for r in (await session.execute(select(AuditLog))).scalars().all()
                }
                assert "kek.rotate.start" in actions
                assert "kek.rotate.complete" in actions
        finally:
            await engine.dispose()

    asyncio.run(_verify())


def test_re_wrap_keys_task_on_migrated_corpus_is_a_no_op(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-running on a fully-migrated corpus migrates zero rows (idempotent)."""
    client = _FakeVaultTransitClient(current_version=1)
    _seed(db_url, _provider(client), 2)
    monkeypatch.setattr(task, "_key_provider", lambda: _provider(client))

    summary = task.re_wrap_keys()
    assert summary["rows_migrated"] == 0
    assert summary["row_count"] == 0
    assert summary["from_version"] is None
    assert summary["to_version"] == "netops-kek:v1"
