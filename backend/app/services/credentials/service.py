"""Credential-vault service: envelope-encrypted device secrets + rotation (ADR-0011).

Composes :mod:`app.core.crypto` (AES-256-GCM envelope encryption), the
:class:`~app.models.inventory.DeviceCredential` model, and the append-only
audit writer (:mod:`app.services.audit`). Per ADR-0011 the AAD authenticated
with every payload is the credential **row id** (``str(id).encode()``) —
:func:`create_credential` therefore generates the id app-side *before*
encrypting, and ciphertext copied onto any other row fails decryption.

Secure by default: plaintext exists in memory only inside
:class:`DecryptedSecret` (redacted ``repr``/``str``) and is never placed in
audit ``detail``, log lines, or exception messages. Like every service in
this package, functions flush but never commit — the caller owns the
transaction, so the audit row and the mutation it describes commit or roll
back atomically.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import (
    EncryptedSecret,
    KeyProvider,
    envelope_decrypt,
    envelope_encrypt,
    rewrap,
)
from app.core.errors import NotFoundError
from app.models.inventory import CredentialKind, DeviceCredential
from app.services import audit

_TARGET_TYPE = "credential"

_REDACTED = "DecryptedSecret(****)"


@dataclass(frozen=True, slots=True, repr=False)
class DecryptedSecret:
    """Plaintext secret bytes confined to a redaction-safe container.

    ``repr``/``str`` always render ``DecryptedSecret(****)`` so accidental
    logging or interpolation can never disclose the payload. Intended
    consumers are the device transports / discovery engine only; never log
    this object or its ``plaintext`` attribute.
    """

    plaintext: bytes

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED


def _aad(credential_id: uuid.UUID) -> bytes:
    """Row-binding associated data: the credential id as UTF-8 (ADR-0011)."""
    return str(credential_id).encode()


def _envelope(credential: DeviceCredential) -> EncryptedSecret:
    """Reassemble the stored envelope columns into an :class:`EncryptedSecret`."""
    return EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        wrapped_dek=credential.wrapped_dek,
        dek_nonce=credential.dek_nonce,
        kek_version=credential.kek_version,
    )


def _store(credential: DeviceCredential, envelope: EncryptedSecret) -> None:
    """Write an envelope back onto the credential's ciphertext columns."""
    credential.ciphertext = envelope.ciphertext
    credential.nonce = envelope.nonce
    credential.wrapped_dek = envelope.wrapped_dek
    credential.dek_nonce = envelope.dek_nonce
    credential.kek_version = envelope.kek_version


async def create_credential(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    name: str,
    kind: CredentialKind,
    username: str | None,
    secret: str,
    params: dict[str, Any] | None,
    actor: str,
) -> DeviceCredential:
    """Encrypt *secret* under a fresh DEK and persist a new credential row.

    The row id is generated first (app-side UUIDv4) because it is the AAD —
    the ciphertext is cryptographically bound to this row before it exists.
    Audits ``credential.created``; the detail carries metadata only, never
    the secret.
    """
    credential_id = uuid.uuid4()
    envelope = envelope_encrypt(secret.encode("utf-8"), _aad(credential_id), provider)
    credential = DeviceCredential(
        id=credential_id,
        name=name,
        kind=kind,
        username=username,
        params=params,
    )
    _store(credential, envelope)
    session.add(credential)
    await audit.record(
        session,
        actor=actor,
        action=audit.CREDENTIAL_CREATED,
        target_type=_TARGET_TYPE,
        target_id=str(credential_id),
        detail={"name": name, "kind": kind.value, "kek_version": envelope.kek_version},
    )
    return credential


async def rotate_secret(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    credential_id: uuid.UUID,
    new_secret: str,
    actor: str,
) -> DeviceCredential:
    """Replace the secret payload: fresh DEK, fresh nonces, same row-id AAD.

    Audits ``credential.rotated``.

    Raises:
        NotFoundError: If *credential_id* does not exist.
    """
    credential = await session.get(DeviceCredential, credential_id)
    if credential is None:
        raise NotFoundError(f"credential {credential_id} does not exist")
    envelope = envelope_encrypt(new_secret.encode("utf-8"), _aad(credential.id), provider)
    _store(credential, envelope)
    await audit.record(
        session,
        actor=actor,
        action=audit.CREDENTIAL_ROTATED,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"rotation": "secret", "kek_version": envelope.kek_version},
    )
    return credential


async def decrypt(
    session: AsyncSession,
    provider: KeyProvider,
    credential: DeviceCredential,
    *,
    actor: str,
    reason: str,
) -> DecryptedSecret:
    """Decrypt *credential*'s payload, auditing ``credential.decrypted`` with *reason*.

    Intended callers are the device transports / discovery engine only — every
    plaintext access leaves an audit row saying who needed it and why.

    Raises:
        DecryptionError: If authentication fails (ciphertext moved to another
            row, tampered data, or wrong key).
        UnknownKekVersionError: If the provider cannot supply the KEK version
            the stored DEK is wrapped under.
    """
    plaintext = envelope_decrypt(_envelope(credential), _aad(credential.id), provider)
    await audit.record(
        session,
        actor=actor,
        action=audit.CREDENTIAL_DECRYPTED,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"reason": reason},
    )
    return DecryptedSecret(plaintext)


async def rotate_kek(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    actor: str,
) -> int:
    """Rewrap every credential's DEK under the provider's current KEK version.

    Cheap rotation per ADR-0011: only the wrapped DEK changes; payload
    ciphertext is never re-encrypted. Credentials already wrapped under the
    provider's current KEK version are skipped (no rewrap, no audit row).
    Audits ``credential.rotated`` per rewrapped credential and returns the
    number of credentials rewrapped.

    Raises:
        UnknownKekVersionError: If any stored ``kek_version`` cannot be
            supplied by *provider* (the old KEK is needed to unwrap).
    """
    current_version = provider.current_version()
    credentials = (await session.execute(select(DeviceCredential))).scalars().all()
    rewrapped_count = 0
    for credential in credentials:
        old_version = credential.kek_version
        if old_version == current_version:
            continue
        rewrapped = rewrap(_envelope(credential), provider)
        _store(credential, rewrapped)
        rewrapped_count += 1
        await audit.record(
            session,
            actor=actor,
            action=audit.CREDENTIAL_ROTATED,
            target_type=_TARGET_TYPE,
            target_id=str(credential.id),
            detail={
                "rotation": "kek",
                "from_kek_version": old_version,
                "to_kek_version": rewrapped.kek_version,
            },
        )
    return rewrapped_count
