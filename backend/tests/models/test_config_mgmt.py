"""Config-management + documentation ORM roundtrips and FK integrity (M4).

Mirrors ``tests/models/test_inventory.py`` / ``test_agents.py``: in-memory
aiosqlite, no Postgres/Docker/network. The pgvector ``VECTOR`` column and its
HNSW/cosine index are PostgreSQL-only DDL exercised by the ``integration``-marked
migration test; here the ``with_variant`` fallback stores the embedding as TEXT.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AgentSession,
    AgentSessionStatus,
    CompliancePolicy,
    ConfigSnapshot,
    ConfigSource,
    Device,
    Document,
    DocumentFormat,
    DocumentKind,
    Embedding,
    Role,
    User,
)


async def test_config_snapshot_roundtrip(session: AsyncSession, device: Device) -> None:
    """A snapshot persists verbatim with its hash, source enum, and baseline flag."""
    captured = datetime(2026, 6, 14, 2, 0, tzinfo=UTC)
    snapshot = ConfigSnapshot(
        device_id=device.id,
        captured_at=captured,
        content_hash="a" * 64,
        content="hostname core-01\nip ssh version 2\n",
        source=ConfigSource.SCHEDULED,
        capture_run_id=uuid.uuid4(),
        baseline=True,
    )
    session.add(snapshot)
    await session.commit()

    reloaded = (
        await session.execute(
            select(ConfigSnapshot)
            .where(ConfigSnapshot.id == snapshot.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.source is ConfigSource.SCHEDULED
    assert reloaded.content == "hostname core-01\nip ssh version 2\n"
    assert reloaded.content_hash == "a" * 64
    assert reloaded.captured_at == captured
    assert reloaded.baseline is True
    assert reloaded.device_id == device.id


async def test_config_snapshot_requires_device_fk(session: AsyncSession) -> None:
    """device_id references devices.id — an unknown device violates the FK."""
    session.add(
        ConfigSnapshot(
            device_id=uuid.uuid4(),
            content_hash="b" * 64,
            content="orphan",
            source=ConfigSource.ON_DEMAND,
            baseline=False,
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_config_snapshot_content_addressed_dedup_constraint(
    session: AsyncSession, device: Device
) -> None:
    """(device_id, content_hash) is unique — a re-capture of the same config conflicts."""
    common = {
        "device_id": device.id,
        "content_hash": "c" * 64,
        "content": "same config",
        "source": ConfigSource.SCHEDULED,
        "baseline": False,
    }
    session.add(ConfigSnapshot(**common))
    await session.flush()
    session.add(ConfigSnapshot(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_compliance_policy_versioning_roundtrip(session: AsyncSession) -> None:
    """A policy persists scope + rules as JSON and reloads them structurally."""
    scope = {"vendors": ["cisco_ios", "eos"], "roles": ["core"], "sites": ["*"]}
    rules = [
        {
            "id": "ssh-v2-only",
            "severity": "violation",
            "assert": {"type": "regex_present", "pattern": "^ip ssh version 2$"},
        }
    ]
    policy = CompliancePolicy(policy_id="baseline-hardening", version=1, scope=scope, rules=rules)
    session.add(policy)
    await session.commit()

    reloaded = (
        await session.execute(
            select(CompliancePolicy)
            .where(CompliancePolicy.id == policy.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.policy_id == "baseline-hardening"
    assert reloaded.version == 1
    assert reloaded.scope == scope
    assert reloaded.rules == rules


async def test_compliance_policy_unique_per_version(session: AsyncSession) -> None:
    """(policy_id, version) is unique; a second v1 of the same policy conflicts."""
    session.add(CompliancePolicy(policy_id="baseline-hardening", version=1))
    await session.flush()
    # A new version of the same policy is allowed...
    session.add(CompliancePolicy(policy_id="baseline-hardening", version=2))
    await session.flush()
    # ...but a duplicate (policy_id, version) is rejected.
    session.add(CompliancePolicy(policy_id="baseline-hardening", version=1))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def _agent_session(session: AsyncSession) -> AgentSession:
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}")
    session.add(role)
    await session.flush()
    user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
    session.add(user)
    await session.flush()
    agent_session = AgentSession(
        user_id=user.id,
        invoking_role="engineer",
        intent="generate inventory",
        status=AgentSessionStatus.RUNNING,
    )
    session.add(agent_session)
    await session.flush()
    return agent_session


async def test_document_roundtrip_with_session_link(session: AsyncSession) -> None:
    """A document persists its kind/format enums, source_refs, and session link."""
    agent_session = await _agent_session(session)
    source_refs = {"device_ids": [str(uuid.uuid4())], "site": "hq"}
    document = Document(
        kind=DocumentKind.RUNBOOK,
        title="Core switch runbook",
        format=DocumentFormat.MD,
        content="# Runbook\n\nSteps...\n",
        source_refs=source_refs,
        generated_by_session_id=agent_session.id,
    )
    session.add(document)
    await session.commit()

    reloaded = (
        await session.execute(
            select(Document)
            .where(Document.id == document.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.kind is DocumentKind.RUNBOOK
    assert reloaded.format is DocumentFormat.MD
    assert reloaded.source_refs == source_refs
    assert reloaded.generated_by_session_id == agent_session.id


async def test_document_session_link_is_optional(session: AsyncSession) -> None:
    """generated_by_session_id is nullable (deterministic docs may have no session)."""
    document = Document(
        kind=DocumentKind.DIAGRAM,
        title="L2 topology",
        format=DocumentFormat.MERMAID,
        content="graph TD; a-->b",
    )
    session.add(document)
    await session.commit()
    assert document.generated_by_session_id is None


async def test_embedding_roundtrip_and_document_fk(session: AsyncSession) -> None:
    """An embedding chunk persists, links to its document, and reloads its text."""
    document = Document(
        kind=DocumentKind.RUNBOOK,
        title="Runbook",
        format=DocumentFormat.MD,
        content="chunk one\nchunk two",
    )
    session.add(document)
    await session.flush()

    session.add_all(
        [
            Embedding(
                document_id=document.id,
                chunk_index=0,
                chunk_text="chunk one",
                embedding="[0.1, 0.2, 0.3]",
            ),
            Embedding(
                document_id=document.id,
                chunk_index=1,
                chunk_text="chunk two",
                embedding="[0.4, 0.5, 0.6]",
            ),
        ]
    )
    await session.commit()

    chunks = (
        (
            await session.execute(
                select(Embedding)
                .where(Embedding.document_id == document.id)
                .order_by(Embedding.chunk_index)
            )
        )
        .scalars()
        .all()
    )
    assert [chunk.chunk_text for chunk in chunks] == ["chunk one", "chunk two"]


async def test_embedding_requires_document_fk(session: AsyncSession) -> None:
    """document_id references documents.id — an orphan embedding is rejected."""
    session.add(
        Embedding(
            document_id=uuid.uuid4(),
            chunk_index=0,
            chunk_text="orphan",
            embedding="[0.0]",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_embedding_unique_per_document_chunk(session: AsyncSession) -> None:
    """(document_id, chunk_index) is unique so re-embedding replaces deterministically."""
    document = Document(
        kind=DocumentKind.INVENTORY,
        title="Inventory",
        format=DocumentFormat.CSV,
        content="a,b\n1,2",
    )
    session.add(document)
    await session.flush()
    session.add(
        Embedding(document_id=document.id, chunk_index=0, chunk_text="x", embedding="[0.1]")
    )
    await session.flush()
    session.add(
        Embedding(document_id=document.id, chunk_index=0, chunk_text="y", embedding="[0.2]")
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
