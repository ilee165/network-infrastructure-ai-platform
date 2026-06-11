"""Credential-vault service tests (ADR-0011): lifecycle, AAD binding, audits, redaction.

Runs entirely on in-memory aiosqlite — no Docker, no network, no Postgres.
The plaintext sentinel strings below must never appear in any audit ``detail``
row or captured structlog event.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
import structlog.testing
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    DecryptionError,
    EnvKeyProvider,
    KeyProvider,
    UnknownKekVersionError,
)
from app.core.errors import NotFoundError
from app.models import AuditLog
from app.models.inventory import CredentialKind, DeviceCredential
from app.services.credentials import service as vault

_SECRET = "sw0rdf1sh-Sup3rS3cret!"
_ROTATED_SECRET = "n3w-r0tated-Passw0rd?"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


class _RotatingProvider:
    """Multi-version KeyProvider double (stands in for a future KMS provider)."""

    def __init__(self, keys: dict[str, bytes], current: str) -> None:
        self._keys = keys
        self._current = current

    def current_version(self) -> str:
        return self._current

    def key(self, version: str) -> bytes:
        try:
            return self._keys[version]
        except KeyError:
            raise UnknownKekVersionError(f"KEK version {version!r} is not available") from None


async def _create(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    name: str = "lab-ssh",
    secret: str = _SECRET,
) -> DeviceCredential:
    return await vault.create_credential(
        session,
        provider,
        name=name,
        kind=CredentialKind.SSH,
        username="netops",
        secret=secret,
        params={"port": 22},
        actor="user:alice",
    )


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    result = await session.execute(select(AuditLog).where(AuditLog.action == action))
    return list(result.scalars())


# ---------------------------------------------------------------------------
# create_credential
# ---------------------------------------------------------------------------


async def test_create_persists_envelope_and_decrypt_roundtrips(session: AsyncSession) -> None:
    """create_credential stores ciphertext only; decrypt returns the plaintext."""
    provider = _provider()
    credential = await _create(session, provider)

    reloaded = (
        await session.execute(
            select(DeviceCredential)
            .where(DeviceCredential.id == credential.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.name == "lab-ssh"
    assert reloaded.kind == CredentialKind.SSH
    assert reloaded.username == "netops"
    assert reloaded.params == {"port": 22}
    assert reloaded.kek_version == "v1"
    assert _SECRET.encode() not in reloaded.ciphertext

    decrypted = await vault.decrypt(
        session, provider, reloaded, actor="system:discovery", reason="ssh session"
    )
    assert decrypted.plaintext == _SECRET.encode()


async def test_create_uses_row_id_as_aad_binding_ciphertext_to_row(session: AsyncSession) -> None:
    """Ciphertext copied onto another row fails decryption: AAD is the row id."""
    provider = _provider()
    cred_a = await _create(session, provider, name="cred-a")
    cred_b = await _create(session, provider, name="cred-b", secret="other-secret")

    cred_b.ciphertext = cred_a.ciphertext
    cred_b.nonce = cred_a.nonce
    cred_b.wrapped_dek = cred_a.wrapped_dek
    cred_b.dek_nonce = cred_a.dek_nonce
    cred_b.kek_version = cred_a.kek_version
    await session.flush()

    with pytest.raises(DecryptionError) as excinfo:
        await vault.decrypt(session, provider, cred_b, actor="user:mallory", reason="copied")
    assert _SECRET not in str(excinfo.value)

    # The legitimate row still decrypts.
    decrypted = await vault.decrypt(session, provider, cred_a, actor="user:alice", reason="check")
    assert decrypted.plaintext == _SECRET.encode()


async def test_create_audits_credential_created_without_secret(session: AsyncSession) -> None:
    """One credential.created audit row; no plaintext in detail or log stream."""
    provider = _provider()
    with structlog.testing.capture_logs() as captured:
        credential = await _create(session, provider)

    rows = await _audit_rows(session, "credential.created")
    assert len(rows) == 1
    entry = rows[0]
    assert entry.actor == "user:alice"
    assert entry.target_type == "credential"
    assert entry.target_id == str(credential.id)
    assert entry.detail is not None
    assert _SECRET not in str(entry.detail)
    assert _SECRET not in str(captured)


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------


async def test_rotate_secret_reencrypts_with_fresh_dek_same_aad(session: AsyncSession) -> None:
    """Rotation swaps ciphertext and DEK; the new secret decrypts under the row AAD."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = credential.ciphertext
    old_wrapped_dek = credential.wrapped_dek

    rotated = await vault.rotate_secret(
        session,
        provider,
        credential_id=credential.id,
        new_secret=_ROTATED_SECRET,
        actor="user:carol",
    )

    assert rotated.id == credential.id
    assert credential.ciphertext != old_ciphertext
    assert credential.wrapped_dek != old_wrapped_dek
    decrypted = await vault.decrypt(
        session, provider, credential, actor="user:carol", reason="post-rotation check"
    )
    assert decrypted.plaintext == _ROTATED_SECRET.encode()

    rows = await _audit_rows(session, "credential.rotated")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)
    assert rows[0].actor == "user:carol"
    assert _ROTATED_SECRET not in str(rows[0].detail)
    assert _SECRET not in str(rows[0].detail)


async def test_rotate_secret_unknown_credential_raises_not_found(session: AsyncSession) -> None:
    """Rotating a nonexistent credential raises NotFoundError without leaking the secret."""
    provider = _provider()
    missing = uuid.uuid4()
    with pytest.raises(NotFoundError) as excinfo:
        await vault.rotate_secret(
            session, provider, credential_id=missing, new_secret=_SECRET, actor="user:carol"
        )
    assert _SECRET not in str(excinfo.value)


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


async def test_decrypt_audits_credential_decrypted_with_reason(session: AsyncSession) -> None:
    """Every decrypt writes a credential.decrypted audit row carrying the reason."""
    provider = _provider()
    credential = await _create(session, provider)

    await vault.decrypt(
        session, provider, credential, actor="system:discovery", reason="discovery run 7"
    )

    rows = await _audit_rows(session, "credential.decrypted")
    assert len(rows) == 1
    entry = rows[0]
    assert entry.actor == "system:discovery"
    assert entry.target_type == "credential"
    assert entry.target_id == str(credential.id)
    assert entry.detail == {"reason": "discovery run 7"}


# ---------------------------------------------------------------------------
# rotate_kek
# ---------------------------------------------------------------------------


async def test_rotate_kek_rewraps_every_credential_and_audits_each(session: AsyncSession) -> None:
    """KEK rotation rewraps all DEKs to the current version; payloads untouched."""
    old_kek, new_kek = os.urandom(KEY_BYTES), os.urandom(KEY_BYTES)
    v1_provider = _RotatingProvider({"v1": old_kek}, current="v1")
    credentials = [
        await _create(session, v1_provider, name=f"cred-{i}", secret=f"{_SECRET}-{i}")
        for i in range(3)
    ]
    snapshots = {c.id: (c.ciphertext, c.nonce, c.wrapped_dek) for c in credentials}

    rotated_provider = _RotatingProvider({"v1": old_kek, "v2": new_kek}, current="v2")
    count = await vault.rotate_kek(session, rotated_provider, actor="user:admin")

    assert count == 3
    for i, credential in enumerate(credentials):
        ciphertext, nonce, wrapped_dek = snapshots[credential.id]
        assert credential.kek_version == "v2"
        assert credential.ciphertext == ciphertext  # payload never re-encrypted
        assert credential.nonce == nonce
        assert credential.wrapped_dek != wrapped_dek
        decrypted = await vault.decrypt(
            session, rotated_provider, credential, actor="user:admin", reason="verify"
        )
        assert decrypted.plaintext == f"{_SECRET}-{i}".encode()

    rows = await _audit_rows(session, "credential.rotated")
    assert len(rows) == 3
    assert {r.target_id for r in rows} == {str(c.id) for c in credentials}


async def test_rotate_kek_with_no_credentials_returns_zero(session: AsyncSession) -> None:
    """An empty vault rotates trivially: zero rewrapped, zero audit rows."""
    count = await vault.rotate_kek(session, _provider(), actor="user:admin")
    assert count == 0
    assert await _audit_rows(session, "credential.rotated") == []


# ---------------------------------------------------------------------------
# DecryptedSecret redaction + log hygiene
# ---------------------------------------------------------------------------


def test_decrypted_secret_repr_and_str_redacted() -> None:
    """repr/str/format never render the plaintext bytes."""
    secret = vault.DecryptedSecret(b"hunter2")
    assert repr(secret) == "DecryptedSecret(****)"
    assert str(secret) == "DecryptedSecret(****)"
    assert "hunter2" not in f"{secret}"
    assert "hunter2" not in f"{secret!r}"
    assert secret.plaintext == b"hunter2"


async def test_no_plaintext_in_structlog_capture_across_lifecycle(session: AsyncSession) -> None:
    """create + rotate + decrypt + rotate_kek emit no plaintext to the log stream."""
    provider = _provider()
    with structlog.testing.capture_logs() as captured:
        credential = await _create(session, provider)
        await vault.rotate_secret(
            session,
            provider,
            credential_id=credential.id,
            new_secret=_ROTATED_SECRET,
            actor="user:alice",
        )
        await vault.decrypt(session, provider, credential, actor="user:alice", reason="lifecycle")
        await vault.rotate_kek(session, provider, actor="user:alice")

    blob = str(captured)
    assert len(captured) >= 4  # one audit event per operation
    assert _SECRET not in blob
    assert _ROTATED_SECRET not in blob
    assert "DecryptedSecret(b" not in blob
