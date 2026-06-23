"""Credential-vault service: envelope-encrypted device secrets + rotation (ADR-0011, ADR-0032).

Composes :mod:`app.core.crypto` (AES-256-GCM envelope encryption behind the
wrap/unwrap :class:`~app.core.crypto.KeyProvider`), the
:class:`~app.models.inventory.DeviceCredential` model, and the append-only
audit writer (:mod:`app.services.audit`). Per ADR-0011 the AAD authenticated
with every payload is the credential **row id** (``str(id).encode()``) —
:func:`create_credential` therefore generates the id app-side *before*
encrypting, and ciphertext copied onto any other row fails decryption. Per
ADR-0032 §1 the same row-id AAD is bound at the KEK->DEK wrap layer too.

Fail closed (ADR-0032 §4): a :class:`~app.core.crypto.KeyProviderUnavailable`
from wrap/unwrap is audited (``kek.provider.unavailable``) and re-raised — on a
write no row is stored unwrapped, and on a read the dependent task fails and
retries so a ChangeRequest that cannot unwrap goes to ``failed``, never
``completed``. Every wrap/unwrap on this core path is audited (``kek.wrap`` /
``kek.unwrap``) with identifiers and KEK versions only — never key bytes
(ADR-0032 §5/§6).

Secure by default: plaintext exists in memory only inside
:class:`DecryptedSecret` (redacted ``repr``/``str``) and is never placed in
audit ``detail``, log lines, or exception messages. Like every service in this
package, functions flush but never commit — the caller owns the transaction, so
the audit row and the mutation it describes commit or roll back atomically.
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
    KeyProviderUnavailable,
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


async def _audit_provider_unavailable(
    session: AsyncSession,
    exc: KeyProviderUnavailable,
    *,
    actor: str,
    target_id: str | None,
) -> None:
    """Audit a tripped fail-closed gate (ADR-0032 §4/§5): reason class only.

    ``detail`` carries the coarse machine ``reason_class`` and nothing else —
    never key bytes, the wrapped blob, or a ``credential_ref`` value.
    """
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_PROVIDER_UNAVAILABLE,
        target_type=_TARGET_TYPE,
        target_id=target_id,
        detail={"reason_class": exc.reason_class},
    )


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
    Audits ``credential.created`` and ``kek.wrap``; the detail carries metadata
    and the KEK version only, never the secret.

    Raises:
        KeyProviderUnavailable: If the provider is unreachable — audited as
            ``kek.provider.unavailable`` and re-raised; **no row is written**.
    """
    credential_id = uuid.uuid4()
    try:
        envelope = envelope_encrypt(secret.encode("utf-8"), _aad(credential_id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(session, exc, actor=actor, target_id=str(credential_id))
        raise
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
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_WRAP,
        target_type=_TARGET_TYPE,
        target_id=str(credential_id),
        detail={"kek_version": envelope.kek_version},
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

    Audits ``credential.rotated`` and ``kek.wrap``.

    Raises:
        NotFoundError: If *credential_id* does not exist.
        KeyProviderUnavailable: If the provider is unreachable — audited as
            ``kek.provider.unavailable`` and re-raised; the payload is unchanged.
    """
    credential = await session.get(DeviceCredential, credential_id)
    if credential is None:
        raise NotFoundError(f"credential {credential_id} does not exist")
    try:
        envelope = envelope_encrypt(new_secret.encode("utf-8"), _aad(credential.id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(session, exc, actor=actor, target_id=str(credential.id))
        raise
    _store(credential, envelope)
    await audit.record(
        session,
        actor=actor,
        action=audit.CREDENTIAL_ROTATED,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"rotation": "secret", "kek_version": envelope.kek_version},
    )
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_WRAP,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"kek_version": envelope.kek_version},
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
    """Decrypt *credential*'s payload, auditing ``kek.unwrap`` + ``credential.decrypted``.

    Intended callers are the device transports / discovery engine only — every
    plaintext access leaves an audit row saying who needed it and why.

    Raises:
        DecryptionError: If authentication fails (ciphertext moved to another
            row, tampered data, or wrong key).
        UnknownKekVersionError: If the provider cannot supply the KEK version
            the stored DEK is wrapped under.
        KeyProviderUnavailable: If the provider is unreachable — audited as
            ``kek.provider.unavailable`` and re-raised so the dependent task
            fails and retries (Celery ``acks_late``); no plaintext is returned.
    """
    try:
        plaintext = envelope_decrypt(_envelope(credential), _aad(credential.id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(session, exc, actor=actor, target_id=str(credential.id))
        raise
    await audit.record(
        session,
        actor=actor,
        action=audit.KEK_UNWRAP,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"kek_version": credential.kek_version, "reason": reason},
    )
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
    """Rewrap every credential's DEK under the provider's active KEK version.

    Cheap rotation per ADR-0011/ADR-0032 §3: only the wrapped DEK changes;
    payload ciphertext is never re-encrypted. Credentials already wrapped under
    the provider's active KEK version are skipped (no rewrap, no audit row).
    Audits ``credential.rotated`` and ``kek.wrap`` per rewrapped credential and
    returns the number of credentials rewrapped.

    Raises:
        UnknownKekVersionError: If any stored ``kek_version`` cannot be supplied
            by *provider* (the old KEK is needed to unwrap).
        KeyProviderUnavailable: If the provider is unreachable — audited as
            ``kek.provider.unavailable`` and re-raised; no rows are mutated.
    """
    active_version = provider.kek_version
    credentials = (await session.execute(select(DeviceCredential))).scalars().all()
    rewrapped_count = 0
    for credential in credentials:
        old_version = credential.kek_version
        if old_version == active_version:
            continue
        try:
            rewrapped = rewrap(_envelope(credential), _aad(credential.id), provider)
        except KeyProviderUnavailable as exc:
            await _audit_provider_unavailable(
                session, exc, actor=actor, target_id=str(credential.id)
            )
            raise
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
        await audit.record(
            session,
            actor=actor,
            action=audit.KEK_WRAP,
            target_type=_TARGET_TYPE,
            target_id=str(credential.id),
            detail={"kek_version": rewrapped.kek_version},
        )
    return rewrapped_count
