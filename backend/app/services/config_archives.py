"""Config-archive persistence: double-envelope encryption at rest (ADR-0050 §7.3).

A UCS archive arrives already **passphrase-encrypted on-box** (the per-backup
passphrase lives in the credential vault, referenced by ``passphrase_ref``). This
service envelope-encrypts that ciphertext a **second** time with the D11/ADR-0032
machinery (:mod:`app.core.crypto`): a fresh per-archive DEK wrapped by the KEK,
with the AAD bound to the archive **row id**. Reading the DB alone yields
double-encrypted bytes; the vault passphrase row AND the KEK are both required to
reconstruct a usable UCS.

Every persisted/log surface is metadata-only (ADR-0050 §7.3): archive id, device
id, size, sha256, KEK version — never the archive bytes, the passphrase, or the
wrapped DEK. There is NO download endpoint in P4; the only consumer of archive
bytes is the CR-gated restore path, which materializes them via
:func:`build_archive_ref`.

Fail closed (ADR-0032 §4): a :class:`KeyProviderUnavailable` from wrap/unwrap is
audited and re-raised — on a write no row is stored unwrapped. Like every service
here, functions flush but never commit — the caller owns the transaction.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from pydantic import SecretBytes
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.crypto import (
    EncryptedSecret,
    KeyProvider,
    KeyProviderUnavailable,
    envelope_decrypt,
    envelope_encrypt,
)
from app.core.errors import NetOpsError
from app.models.config_mgmt import ConfigArchive as ConfigArchiveRow
from app.plugins.base import ConfigArchive as ConfigArchivePayload
from app.plugins.base import ConfigArchiveRef
from app.services import audit

__all__ = [
    "ArchiveIntegrityError",
    "PersistedArchiveRef",
    "build_archive_ref",
    "load_archive_bytes",
    "store_archive",
]

_TARGET_TYPE = "config_archive"


class ArchiveIntegrityError(NetOpsError):
    """A loaded archive's bytes do not hash to the recorded ``sha256`` (tampered/corrupt)."""

    status_code = 500
    title = "Config Archive Integrity Failure"
    slug = "config-archive-integrity"


def _aad(archive_id: uuid.UUID) -> bytes:
    """Row-binding associated data: the archive id as UTF-8 (parity with ADR-0011)."""
    return str(archive_id).encode()


def _envelope(row: ConfigArchiveRow) -> EncryptedSecret:
    return EncryptedSecret(
        ciphertext=row.ciphertext,
        nonce=row.nonce,
        wrapped_dek=row.wrapped_dek,
        dek_nonce=row.dek_nonce,
        kek_version=row.kek_version,
    )


@dataclass(frozen=True, slots=True, repr=False)
class PersistedArchiveRef:
    """A :class:`~app.plugins.base.ConfigArchiveRef` over a persisted archive row.

    Carries the passphrase-encrypted archive bytes (already stripped of the
    platform envelope) as :class:`~pydantic.SecretBytes` plus the log-safe
    metadata the restore path needs. ``repr`` never renders the bytes.
    """

    archive_id: uuid.UUID
    device_id: uuid.UUID
    archive_format: str
    sha256: str
    passphrase_ref: str
    content: SecretBytes = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"PersistedArchiveRef(archive_id={self.archive_id!r}, "
            f"device_id={self.device_id!r}, format={self.archive_format!r}, "
            f"sha256={self.sha256!r})"
        )


async def store_archive(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    device_id: uuid.UUID,
    archive: ConfigArchivePayload,
    actor: str,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> ConfigArchiveRow:
    """Double-envelope-encrypt *archive* and persist a ``config_archives`` row.

    The row id is generated first (it is the AAD), then the already
    passphrase-encrypted archive bytes are envelope-encrypted a second time under
    a fresh DEK wrapped by the KEK. Audits ``config_archive.created`` + ``kek.wrap``
    with metadata/versions only — never the bytes, the passphrase, or the DEK.

    Raises:
        KeyProviderUnavailable: If the provider is unreachable — audited durably
            and re-raised; **no row is written**.
    """
    archive_id = uuid.uuid4()
    plaintext = archive.content.get_secret_value()
    try:
        envelope = envelope_encrypt(plaintext, _aad(archive_id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_unavailable(
            session, exc, actor=actor, target_id=str(archive_id), maker=sessionmaker
        )
        raise
    row = ConfigArchiveRow(
        id=archive_id,
        device_id=device_id,
        archive_format=archive.format,
        size_bytes=archive.size_bytes,
        sha256=archive.sha256,
        passphrase_ref=archive.passphrase_ref,
        ciphertext=envelope.ciphertext,
        nonce=envelope.nonce,
        wrapped_dek=envelope.wrapped_dek,
        dek_nonce=envelope.dek_nonce,
        kek_version=envelope.kek_version,
    )
    session.add(row)
    await audit.record(
        session,
        actor=actor,
        action=audit.CONFIG_ARCHIVE_CREATED,
        target_type=_TARGET_TYPE,
        target_id=str(archive_id),
        detail={
            "device_id": str(device_id),
            "format": archive.format,
            "size_bytes": archive.size_bytes,
            "sha256": archive.sha256,
            "kek_version": envelope.kek_version,
        },
    )
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_WRAP,
        target_type=_TARGET_TYPE,
        target_id=str(archive_id),
        detail={"kek_version": envelope.kek_version},
    )
    return row


async def load_archive_bytes(
    session: AsyncSession,
    provider: KeyProvider,
    row: ConfigArchiveRow,
    *,
    actor: str,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> bytes:
    """Decrypt the platform envelope, verify integrity, and return the archive bytes.

    Returns the passphrase-encrypted UCS bytes (the platform envelope removed; the
    passphrase envelope is intact — a usable UCS still needs the vault passphrase).
    Verifies the decrypted bytes hash to the recorded ``sha256``. Audits
    ``kek.unwrap``.

    Raises:
        ArchiveIntegrityError: If the decrypted bytes do not match ``sha256``.
        KeyProviderUnavailable: If the provider is unreachable (fail closed).
    """
    try:
        plaintext = envelope_decrypt(_envelope(row), _aad(row.id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_unavailable(
            session, exc, actor=actor, target_id=str(row.id), maker=sessionmaker
        )
        raise
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_UNWRAP,
        target_type=_TARGET_TYPE,
        target_id=str(row.id),
        detail={"kek_version": row.kek_version, "reason": "archive_restore"},
    )
    if hashlib.sha256(plaintext).hexdigest() != row.sha256:
        raise ArchiveIntegrityError(
            f"config archive {row.id} failed integrity check (sha256 mismatch)"
        )
    return plaintext


def build_archive_ref(row: ConfigArchiveRow, content: bytes) -> PersistedArchiveRef:
    """Build a :class:`ConfigArchiveRef` from a row + its decrypted (passphrase-encrypted) bytes."""
    ref = PersistedArchiveRef(
        archive_id=row.id,
        device_id=row.device_id,
        archive_format=row.archive_format,
        sha256=row.sha256,
        passphrase_ref=row.passphrase_ref,
        content=SecretBytes(content),
    )
    # Structural guarantee: the adapter satisfies the base protocol.
    assert isinstance(ref, ConfigArchiveRef)  # noqa: S101
    return ref


async def _audit_unavailable(
    session: AsyncSession,
    exc: KeyProviderUnavailable,
    *,
    actor: str,
    target_id: str,
    maker: async_sessionmaker[AsyncSession] | None,
) -> None:
    """Durably audit a tripped fail-closed gate (reason class only, ADR-0032 §4)."""
    try:
        if maker is not None:
            async with maker() as audit_session:
                await audit.record(
                    audit_session,
                    actor=actor,
                    action=audit.KEK_PROVIDER_UNAVAILABLE,
                    target_type=_TARGET_TYPE,
                    target_id=target_id,
                    detail={"reason_class": exc.reason_class},
                )
                await audit_session.commit()
            return
        await audit.record(
            session,
            actor=actor,
            action=audit.KEK_PROVIDER_UNAVAILABLE,
            target_type=_TARGET_TYPE,
            target_id=target_id,
            detail={"reason_class": exc.reason_class},
        )
    except Exception:  # noqa: BLE001 — never mask the original fail-closed error
        pass
