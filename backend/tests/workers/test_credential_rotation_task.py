"""Credential-rotation worker pass (W4-T2, ADR-0040 §1): the exact Job path.

Drives :func:`app.workers.tasks.credential_rotation.run` against a NullPool SQLite
engine (W6 flaky-concurrency lesson) with INJECTED fakes for the device verifier +
new-secret factory — so what the test asserts is what the Helm CronJob runs. The
plaintext sentinel below must never appear in the run summary or the log stream.
"""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import structlog.testing
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.crypto import KEY_BYTES, EnvKeyProvider, KeyProvider
from app.models import Base
from app.models.inventory import CredentialKind, Device, DeviceCredential, DeviceStatus
from app.services.credentials import service as vault
from app.workers.tasks import credential_rotation
from app.workers.tasks.credential_rotation import RotationPassSummary, render_summary, run

_NEW_SECRET = "rotated-by-the-job-Sup3rS3cret!"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


@pytest.fixture()
async def maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A NullPool, file-backed SQLite sessionmaker (the autonomous-commit Job shape)."""
    db_path = tmp_path / "w4t2_rotation_task.db"
    engine: AsyncEngine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path.as_posix()}", poolclass=NullPool
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _seed(
    maker: async_sessionmaker[AsyncSession],
    provider: KeyProvider,
    *,
    bind_device: bool = True,
    name: str = "job-ssh",
    mgmt_ip: str = "10.0.0.1",
) -> None:
    async with maker() as session:
        credential = await vault.create_credential(
            session,
            provider,
            name=name,
            kind=CredentialKind.SSH,
            username="netops",
            secret="old-secret",
            params=None,
            actor="user:alice",
        )
        await session.flush()
        if bind_device:
            session.add(
                Device(
                    hostname=name,
                    mgmt_ip=mgmt_ip,
                    status=DeviceStatus.NEW,
                    credential_id=credential.id,
                )
            )
        await session.commit()


async def _accept(_device: Device, _secret: vault.DecryptedSecret) -> bool:
    return True


async def _reject(_device: Device, _secret: vault.DecryptedSecret) -> bool:
    return False


# ---------------------------------------------------------------------------
# Happy path: a device-bound credential rotates and the job exits 0
# ---------------------------------------------------------------------------


async def test_run_activates_bound_credential_and_exits_zero(
    maker: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    provider = _provider()
    await _seed(maker, provider)
    summary_dir = tmp_path / "summary"

    with structlog.testing.capture_logs() as captured:
        code = await run(
            sessionmaker=maker,
            provider=provider,
            verify=_accept,
            summary_dir=summary_dir,
            secret_factory=lambda _c: _NEW_SECRET,
        )

    assert code == 0
    # The summary file was written (the L5 `test -s` guard depends on this).
    summary_file = summary_dir / "credential_rotation.prom"
    assert summary_file.exists()
    body = summary_file.read_text(encoding="utf-8")
    assert "credential_rotation_activated_total 1" in body
    assert "credential_rotation_degraded_total 0" in body
    # No plaintext anywhere in the summary or the captured log stream.
    assert _NEW_SECRET not in body
    assert _NEW_SECRET not in str(captured)


# ---------------------------------------------------------------------------
# Fail-closed: a failed verify degrades and the job exits non-zero (the alert)
# ---------------------------------------------------------------------------


async def test_run_degrades_on_failed_verify_and_exits_nonzero(
    maker: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    provider = _provider()
    await _seed(maker, provider)
    summary_dir = tmp_path / "summary"

    code = await run(
        sessionmaker=maker,
        provider=provider,
        verify=_reject,
        summary_dir=summary_dir,
        secret_factory=lambda _c: _NEW_SECRET,
        max_attempts=2,
    )

    # Non-zero exit = the ADR-0015 alert; the prior credential is still usable.
    assert code == 1
    body = (summary_dir / "credential_rotation.prom").read_text(encoding="utf-8")
    assert "credential_rotation_degraded_total 1" in body
    assert "credential_rotation_activated_total 0" in body


# ---------------------------------------------------------------------------
# An unbound credential is not in the worklist (no device to verify against)
# ---------------------------------------------------------------------------


async def test_unbound_credential_is_not_rotated(
    maker: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    provider = _provider()
    await _seed(maker, provider, bind_device=False)
    summary_dir = tmp_path / "summary"

    code = await run(
        sessionmaker=maker,
        provider=provider,
        verify=_accept,
        summary_dir=summary_dir,
        secret_factory=lambda _c: _NEW_SECRET,
    )
    assert code == 0
    body = (summary_dir / "credential_rotation.prom").read_text(encoding="utf-8")
    assert "credential_rotation_considered_total 0" in body


# ---------------------------------------------------------------------------
# The default secret factory is a CSPRNG token (no static/predictable secret)
# ---------------------------------------------------------------------------


def test_default_secret_factory_is_random_and_nonempty() -> None:
    cred = DeviceCredential(name="x", kind=CredentialKind.SSH)  # not persisted
    a = credential_rotation._new_secret(cred)
    b = credential_rotation._new_secret(cred)
    assert a and b and a != b


def test_render_summary_carries_counts_only() -> None:
    body = render_summary(RotationPassSummary(considered=5, activated=4, degraded=1))
    assert "credential_rotation_considered_total 5" in body
    assert "credential_rotation_activated_total 4" in body
    assert "credential_rotation_degraded_total 1" in body
