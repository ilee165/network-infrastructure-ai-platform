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
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.crypto import (
    EncryptedSecret,
    KeyProvider,
    KeyProviderUnavailable,
    envelope_decrypt,
    envelope_encrypt,
    is_production_grade,
    rewrap,
)
from app.core.errors import NotFoundError
from app.models.inventory import CredentialKind, DeviceCredential
from app.services import audit

_TARGET_TYPE = "credential"

#: Audit ``target_type`` for the provider-level (non-row) KEK events.
_PROVIDER_TARGET_TYPE = "key_provider"

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


def autonomous_sessionmaker(session: AsyncSession) -> async_sessionmaker[AsyncSession]:
    """Derive an autonomous sessionmaker bound to *session*'s engine (ADR-0032 §4/§5).

    Production callers that own an :class:`AsyncSession` but no separate
    sessionmaker (notably the worker decrypt sites, whose session is created
    inside a private context manager) use this to obtain the independent
    transaction the durable fail-closed audit needs. It reuses the same
    :class:`~sqlalchemy.ext.asyncio.AsyncEngine` (``session.bind``), so the
    ``kek.provider.unavailable`` row commits on its own short-lived session while
    the caller's doomed transaction rolls back — never lost on the one path that
    rolls the caller back.
    """
    bind = session.bind
    if not isinstance(bind, AsyncEngine):  # pragma: no cover - all prod sessions bind an engine
        raise RuntimeError("credential session is not bound to an AsyncEngine")
    return async_sessionmaker(bind, expire_on_commit=False)


async def _audit_provider_unavailable(
    session: AsyncSession,
    exc: KeyProviderUnavailable,
    *,
    actor: str,
    target_id: str | None,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """Durably audit a tripped fail-closed gate (ADR-0032 §4/§5): reason class only.

    ``detail`` carries the coarse machine ``reason_class`` and nothing else —
    never key bytes, the wrapped blob, or a ``credential_ref`` value.

    The fail-closed gate is the one path where the caller's transaction is
    *rolled back* (no row was written, the exception propagates to a route that
    never commits). The required append-only ``audit_log`` row must therefore be
    persisted **independently** of that doomed transaction: when *sessionmaker*
    is supplied, the row is written in a separate short-lived session that
    commits before the gate exception re-raises (``audit_log`` is append-only, so
    an autonomous commit is sound — there is no sibling write to be atomic with
    on the failure path). When *sessionmaker* is ``None`` (unit tests asserting
    on the same session, callers with no autonomous boundary), the row is flushed
    on the caller's session as before — non-durable, but behaviourally correct.
    """
    if sessionmaker is not None:
        async with sessionmaker() as audit_session:
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


async def audit_provider_select(
    sessionmaker: async_sessionmaker[AsyncSession],
    provider: KeyProvider,
    *,
    actor: str,
) -> None:
    """Durably audit the active KEK provider/backend selection (ADR-0032 §5).

    Emitted when the platform chooses its active provider at startup. ``detail``
    (the ADR-0032 §5 ``after`` shape) carries identifiers/versions only —
    ``{provider: <class name>, kek_version, is_production_grade}`` — never key
    bytes, the wrapped blob, or a ``credential_ref`` value.

    Written in its own short-lived session that commits immediately so the row
    survives independent of any request transaction (it is emitted at startup
    where there is no caller-owned transaction boundary).
    """
    async with sessionmaker() as session:
        await audit.record(
            session,
            actor=actor,
            action=audit.KEK_PROVIDER_SELECT,
            target_type=_PROVIDER_TARGET_TYPE,
            target_id=type(provider).__name__,
            detail={
                "provider": type(provider).__name__,
                "kek_version": provider.kek_version,
                "is_production_grade": is_production_grade(provider),
            },
        )
        await session.commit()


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
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> DeviceCredential:
    """Encrypt *secret* under a fresh DEK and persist a new credential row.

    The row id is generated first (app-side UUIDv4) because it is the AAD —
    the ciphertext is cryptographically bound to this row before it exists.
    Audits ``credential.created`` and ``kek.wrap``; the detail carries metadata
    and the KEK version only, never the secret.

    *sessionmaker* lets the fail-closed ``kek.provider.unavailable`` audit row be
    persisted durably in its own transaction (the caller's transaction rolls back
    on this path — ADR-0032 §4/§5); routes pass it, unit tests may omit it.

    Raises:
        KeyProviderUnavailable: If the provider is unreachable — audited durably
            as ``kek.provider.unavailable`` and re-raised; **no row is written**.
    """
    credential_id = uuid.uuid4()
    try:
        envelope = envelope_encrypt(secret.encode("utf-8"), _aad(credential_id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(
            session, exc, actor=actor, target_id=str(credential_id), sessionmaker=sessionmaker
        )
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
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> DeviceCredential:
    """Replace the secret payload: fresh DEK, fresh nonces, same row-id AAD.

    Audits ``credential.rotated`` and ``kek.wrap``. *sessionmaker* makes the
    fail-closed ``kek.provider.unavailable`` audit row durable (ADR-0032 §4/§5).

    Raises:
        NotFoundError: If *credential_id* does not exist.
        KeyProviderUnavailable: If the provider is unreachable — audited durably
            as ``kek.provider.unavailable`` and re-raised; the payload is unchanged.
    """
    credential = await session.get(DeviceCredential, credential_id)
    if credential is None:
        raise NotFoundError(f"credential {credential_id} does not exist")
    try:
        envelope = envelope_encrypt(new_secret.encode("utf-8"), _aad(credential.id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(
            session, exc, actor=actor, target_id=str(credential.id), sessionmaker=sessionmaker
        )
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
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> DecryptedSecret:
    """Decrypt *credential*'s payload, auditing ``kek.unwrap`` + ``credential.decrypted``.

    Intended callers are the device transports / discovery engine only — every
    plaintext access leaves an audit row saying who needed it and why.
    *sessionmaker* makes the fail-closed ``kek.provider.unavailable`` audit row
    durable (ADR-0032 §4/§5).

    Raises:
        DecryptionError: If authentication fails (ciphertext moved to another
            row, tampered data, or wrong key).
        UnknownKekVersionError: If the provider cannot supply the KEK version
            the stored DEK is wrapped under.
        KeyProviderUnavailable: If the provider is unreachable — audited durably
            as ``kek.provider.unavailable`` and re-raised so the dependent task
            fails and retries (Celery ``acks_late``); no plaintext is returned.
    """
    try:
        plaintext = envelope_decrypt(_envelope(credential), _aad(credential.id), provider)
    except KeyProviderUnavailable as exc:
        await _audit_provider_unavailable(
            session, exc, actor=actor, target_id=str(credential.id), sessionmaker=sessionmaker
        )
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
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> int:
    """Rewrap every credential's DEK under the provider's active KEK version.

    Cheap rotation per ADR-0011/ADR-0032 §3: only the wrapped DEK changes;
    payload ciphertext is never re-encrypted. Credentials already wrapped under
    the provider's active KEK version are skipped (no rewrap, no audit row).
    Audits ``credential.rotated`` and ``kek.wrap`` per rewrapped credential and
    returns the number of credentials rewrapped. *sessionmaker* makes the
    fail-closed ``kek.provider.unavailable`` audit row durable (ADR-0032 §4/§5).

    Raises:
        UnknownKekVersionError: If any stored ``kek_version`` cannot be supplied
            by *provider* (the old KEK is needed to unwrap).
        KeyProviderUnavailable: If the provider is unreachable — audited durably
            as ``kek.provider.unavailable`` and re-raised; no rows are mutated.
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
                session,
                exc,
                actor=actor,
                target_id=str(credential.id),
                sessionmaker=sessionmaker,
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
