"""Confirm-then-swap, fail-closed device-secret rotation (ADR-0040 §1/§3).

The exit "bites":

  * NO-LEAK invariant: after a rotation no plaintext (old or new) is in the vault
    row, any audit ``detail`` row, or the captured log stream; the activated DEK is
    a FRESH wrap (wrapped_dek/ciphertext changed).
  * FAIL-CLOSED: a forced verify failure leaves the PRIOR credential usable (the
    row is never mutated), retries, then marks degraded + alerts — never a silent
    lock-out.
  * Disjoint from KEK rotation: this rotates the device secret (payload re-encrypted
    under a fresh DEK), not the envelope key.

Runs entirely on in-memory aiosqlite. A durable-audit determinism test pins to a
NullPool SQLite engine (W6 flaky-concurrency lesson). The plaintext sentinels
below must never appear in any audit ``detail`` row or captured log event.
"""

from __future__ import annotations

import base64
import os
import uuid
from pathlib import Path

import pytest
import structlog.testing
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    EnvKeyProvider,
    KeyProvider,
    KeyProviderUnavailable,
    WrappedDek,
)
from app.core.errors import NotFoundError
from app.models import AuditLog, Base
from app.models.inventory import CredentialKind, Device, DeviceCredential, DeviceStatus
from app.services.credentials import secret_rotation
from app.services.credentials import service as vault
from app.services.credentials.secret_rotation import RotationState, rotate_device_secret

_OLD_SECRET = "0ld-Passw0rd-rot8me!"
_NEW_SECRET = "n3w-Sup3rS3cret-Passw0rd?"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


async def _create(
    session: AsyncSession, provider: KeyProvider, *, name: str = "rot-ssh"
) -> DeviceCredential:
    return await vault.create_credential(
        session,
        provider,
        name=name,
        kind=CredentialKind.SSH,
        username="netops",
        secret=_OLD_SECRET,
        params={"port": 22},
        actor="user:alice",
    )


def _device() -> Device:
    return Device(hostname="core-1", mgmt_ip="10.0.0.1", status=DeviceStatus.NEW)


async def _accept(_device: Device, _secret: vault.DecryptedSecret) -> bool:
    return True


async def _reject(_device: Device, _secret: vault.DecryptedSecret) -> bool:
    return False


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    result = await session.execute(select(AuditLog).where(AuditLog.action == action))
    return list(result.scalars())


# ---------------------------------------------------------------------------
# Confirm-then-swap: success activates a fresh wrap; no leak
# ---------------------------------------------------------------------------


async def test_successful_rotation_activates_fresh_wrap(session: AsyncSession) -> None:
    """A verified rotation swaps to a fresh DEK; the new secret decrypts, old does not."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = bytes(credential.ciphertext)
    old_wrapped_dek = bytes(credential.wrapped_dek)
    device = _device()

    outcome = await rotate_device_secret(
        session,
        provider,
        credential_id=credential.id,
        new_secret=_NEW_SECRET,
        device=device,
        verify=_accept,
        actor="system:rotation",
    )

    assert outcome.state is RotationState.ACTIVATED
    assert outcome.attempts == 1
    assert outcome.kek_version == "v1"

    # A FRESH wrap: both the payload ciphertext and the wrapped DEK changed.
    assert credential.ciphertext != old_ciphertext
    assert credential.wrapped_dek != old_wrapped_dek

    # The NEW secret now decrypts; the old plaintext is gone.
    decrypted = await vault.decrypt(
        session, provider, credential, actor="system:config", reason="check"
    )
    assert decrypted.plaintext == _NEW_SECRET.encode()
    assert decrypted.plaintext != _OLD_SECRET.encode()


async def test_no_leak_invariant_in_row_audit_and_logs(session: AsyncSession) -> None:
    """After rotation, no plaintext in the vault row, any audit detail, or the logs."""
    provider = _provider()
    credential = await _create(session, provider)
    device = _device()

    with structlog.testing.capture_logs() as captured:
        await rotate_device_secret(
            session,
            provider,
            credential_id=credential.id,
            new_secret=_NEW_SECRET,
            device=device,
            verify=_accept,
            actor="system:rotation",
        )

    # The vault row carries ciphertext only — neither plaintext appears verbatim.
    assert _NEW_SECRET.encode() not in credential.ciphertext
    assert _OLD_SECRET.encode() not in credential.ciphertext

    # No audit detail row anywhere carries either plaintext.
    all_rows = (await session.execute(select(AuditLog))).scalars().all()
    assert all_rows  # the rotation produced audit rows
    for row in all_rows:
        assert _NEW_SECRET not in str(row.detail)
        assert _OLD_SECRET not in str(row.detail)

    # The rotation audit carries ids/versions only.
    rotated = await _audit_rows(session, "credential.secret_rotated")
    assert len(rotated) == 1
    assert rotated[0].target_id == str(credential.id)
    assert rotated[0].detail == {
        "rotation": "device_secret",
        "kek_version": "v1",
        "attempts": 1,
    }

    # The captured log stream never carries the plaintext.
    assert _NEW_SECRET not in str(captured)
    assert _OLD_SECRET not in str(captured)


# ---------------------------------------------------------------------------
# Fail-closed: a failed verify leaves the prior credential usable, never locks out
# ---------------------------------------------------------------------------


async def test_failed_rotation_leaves_prior_credential_usable(session: AsyncSession) -> None:
    """A forced verify failure discards the staged secret; the OLD secret still works."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = bytes(credential.ciphertext)
    old_wrapped_dek = bytes(credential.wrapped_dek)
    device = _device()

    outcome = await rotate_device_secret(
        session,
        provider,
        credential_id=credential.id,
        new_secret=_NEW_SECRET,
        device=device,
        verify=_reject,
        actor="system:rotation",
        max_attempts=3,
    )

    # Degraded after exhausting retries; the prior credential is UNCHANGED + usable.
    assert outcome.state is RotationState.DEGRADED
    assert outcome.attempts == 3
    assert outcome.kek_version is None
    assert credential.ciphertext == old_ciphertext
    assert credential.wrapped_dek == old_wrapped_dek

    # The device is NOT locked out: the prior secret still decrypts.
    decrypted = await vault.decrypt(
        session, provider, credential, actor="system:config", reason="fallback"
    )
    assert decrypted.plaintext == _OLD_SECRET.encode()


async def test_failed_rotation_audits_failures_then_degraded_alert(session: AsyncSession) -> None:
    """Each failed attempt audits a failure; repeated failure degrades + alerts (ADR-0015)."""
    provider = _provider()
    credential = await _create(session, provider)
    device = _device()

    with structlog.testing.capture_logs() as captured:
        await rotate_device_secret(
            session,
            provider,
            credential_id=credential.id,
            new_secret=_NEW_SECRET,
            device=device,
            verify=_reject,
            actor="system:rotation",
            max_attempts=2,
        )

    failed = await _audit_rows(session, "credential.secret_rotation_failed")
    assert len(failed) == 2  # one per attempt
    degraded = await _audit_rows(session, "credential.secret_rotation_degraded")
    assert len(degraded) == 1
    assert degraded[0].detail == {"rotation": "device_secret", "attempts": 2}

    # No activation row was written on the failure path.
    assert await _audit_rows(session, "credential.secret_rotated") == []

    # The degraded alert is emitted to the log stream (the ADR-0015 signal).
    assert any(evt.get("event") == "credentials.secret_rotation_degraded" for evt in captured)
    assert _NEW_SECRET not in str(captured)


async def test_recovers_on_later_attempt_when_verify_eventually_succeeds(
    session: AsyncSession,
) -> None:
    """A flaky verify that succeeds on the 2nd attempt activates without degrading."""
    provider = _provider()
    credential = await _create(session, provider)
    device = _device()
    calls = {"n": 0}

    async def _flaky(_device: Device, _secret: vault.DecryptedSecret) -> bool:
        calls["n"] += 1
        return calls["n"] >= 2

    outcome = await rotate_device_secret(
        session,
        provider,
        credential_id=credential.id,
        new_secret=_NEW_SECRET,
        device=device,
        verify=_flaky,
        actor="system:rotation",
        max_attempts=3,
    )
    assert outcome.state is RotationState.ACTIVATED
    assert outcome.attempts == 2
    assert len(await _audit_rows(session, "credential.secret_rotation_failed")) == 1


# ---------------------------------------------------------------------------
# Fail-closed against a down KMS provider; bad inputs
# ---------------------------------------------------------------------------


class _DownProvider:
    """An unreachable provider; every wrap fails closed (ADR-0032 §4)."""

    @property
    def kek_version(self) -> str:
        return "v1"

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        raise KeyProviderUnavailable("TimeoutError")

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        raise KeyProviderUnavailable("TimeoutError")


async def test_provider_unavailable_leaves_row_unchanged(session: AsyncSession) -> None:
    """A KMS outage during staging fails closed: prior credential intact, no mutation."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = bytes(credential.ciphertext)
    device = _device()

    with pytest.raises(KeyProviderUnavailable):
        await rotate_device_secret(
            session,
            _DownProvider(),
            credential_id=credential.id,
            new_secret=_NEW_SECRET,
            device=device,
            verify=_accept,
            actor="system:rotation",
        )
    assert credential.ciphertext == old_ciphertext
    # The fail-closed gate was audited (reason class only, no secret).
    assert len(await _audit_rows(session, "kek.provider.unavailable")) == 1


async def test_missing_credential_raises_not_found(session: AsyncSession) -> None:
    with pytest.raises(NotFoundError):
        await rotate_device_secret(
            session,
            _provider(),
            credential_id=uuid.uuid4(),
            new_secret=_NEW_SECRET,
            device=_device(),
            verify=_accept,
            actor="system:rotation",
        )


async def test_non_positive_max_attempts_rejected(session: AsyncSession) -> None:
    provider = _provider()
    credential = await _create(session, provider)
    with pytest.raises(ValueError, match="max_attempts must be positive"):
        await rotate_device_secret(
            session,
            provider,
            credential_id=credential.id,
            new_secret=_NEW_SECRET,
            device=_device(),
            verify=_accept,
            actor="system:rotation",
            max_attempts=0,
        )


# ---------------------------------------------------------------------------
# Determinism: NullPool SQLite (W6 flaky-concurrency lesson)
# ---------------------------------------------------------------------------


async def test_rotation_round_trip_on_nullpool_sqlite(tmp_path: Path) -> None:
    """The full stage->verify->activate path on a NullPool engine is deterministic."""
    # NullPool opens a fresh connection per op, so a file-backed DB (not :memory:,
    # which is per-connection) is the shared store the round-trip needs.
    db_path = tmp_path / "w4t2_rotation.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}", poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        provider = _provider()
        async with maker() as session:
            credential = await _create(session, provider)
            await session.commit()
            outcome = await rotate_device_secret(
                session,
                provider,
                credential_id=credential.id,
                new_secret=_NEW_SECRET,
                device=_device(),
                verify=_accept,
                actor="system:rotation",
            )
            await session.commit()
            assert outcome.state is RotationState.ACTIVATED
        async with maker() as session:
            reloaded = await session.get(DeviceCredential, credential.id)
            assert reloaded is not None
            decrypted = await vault.decrypt(
                session, provider, reloaded, actor="system:config", reason="check"
            )
            assert decrypted.plaintext == _NEW_SECRET.encode()
    finally:
        await engine.dispose()


def test_module_exposes_default_max_attempts() -> None:
    """The retry budget constant is exported for the worker / call sites."""
    assert secret_rotation.DEFAULT_MAX_ATTEMPTS >= 1
