"""Device-secret rotation: confirm-then-swap, fail-closed (ADR-0040 §1/§3).

Rotates the platform's STORED copy of a device login secret. The new secret is
wrapped as a freshly KMS-wrapped DEK via the EXISTING ADR-0032 envelope provider
(:func:`app.core.crypto.envelope_encrypt`) — there is NO new crypto here and this
path is disjoint from KEK/master-key rotation (ADR-0032 / W6-T3, which rotates the
envelope key, not the device secret).

Confirm-then-swap, never overwrite the only working secret in place (ADR-0040 §1):

  1. STAGE  — wrap the new secret into a fresh envelope IN MEMORY; the credential
     row's ciphertext columns are NOT touched yet, so the prior secret stays the
     credential of record.
  2. VERIFY — authenticate the new secret against the target device via an injected
     :data:`DeviceVerifier`. (The verifier is injected so the rotation logic is
     deterministically testable; the real transport-backed verifier lives at the
     call site / worker and is host-limited — it cannot run on the build host.)
  3. ACTIVATE — only on a successful verify is the new envelope stored onto the row
     (the swap). The prior credential is replaced ONLY after the new one is proven.

Fail-closed (ADR-0040 §3): a failed verify DISCARDS the unconfirmed staged
envelope — the row is never mutated, so the prior credential stays valid and the
device is never locked out. The rotation is retried up to ``max_attempts``; on
repeated failure the credential is marked DEGRADED and an alert is raised
(ADR-0015) — a device is never left silently unreachable. (Chosen over
invalidate-then-replace, which risks locking out the only working credential.)

Secure by default (ADR-0040 §1 / ADR-0032 §6): the transient new-secret plaintext
is held only in a local ``bytearray`` and ZEROIZED in a ``finally`` (success or
failure); it never reaches a log line, audit ``detail``, queue, cache, exception
message, or the return value. Audit events carry ids/versions/outcome ONLY.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.crypto import (
    EncryptedSecret,
    KeyProvider,
    KeyProviderUnavailable,
    envelope_encrypt,
)
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.models.inventory import Device, DeviceCredential
from app.services import audit
from app.services.credentials.service import (
    DecryptedSecret,
    _aad,
    _audit_provider_unavailable,
    _store,
)

_logger = get_logger(__name__)

_TARGET_TYPE = "credential"

#: Default retry budget before a credential is marked degraded (ADR-0040 §3).
DEFAULT_MAX_ATTEMPTS = 3

#: A device-side verification of a staged secret: authenticate *secret* against
#: *device* and return ``True`` iff the new secret is confirmed working. The
#: plaintext is passed inside :class:`DecryptedSecret` so it stays redaction-safe;
#: the verifier MUST NOT log/persist it. Injected so the rotation logic is
#: deterministically testable; the real transport-backed verifier is host-limited.
DeviceVerifier = Callable[[Device, DecryptedSecret], Awaitable[bool]]


class RotationState(StrEnum):
    """Terminal state of a confirm-then-swap rotation (no secret material)."""

    #: The new secret verified and was activated as the credential of record.
    ACTIVATED = "activated"
    #: Every attempt's verify failed; the credential was marked degraded + alerted.
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class RotationOutcome:
    """Versions/counts-only result of a rotation — carries NO secret material.

    ``state`` is the terminal :class:`RotationState`; ``attempts`` is how many
    stage+verify cycles ran; ``kek_version`` is the KEK version the new (activated)
    envelope was wrapped under on success, or ``None`` when the rotation degraded
    (the prior credential — unchanged — remains the credential of record).
    """

    credential_id: uuid.UUID
    state: RotationState
    attempts: int
    kek_version: str | None


def _zeroize_str_secret(buf: bytearray) -> None:
    """Best-effort wipe of the transient new-secret plaintext buffer (ADR-0032 §6)."""
    for i in range(len(buf)):
        buf[i] = 0


async def rotate_device_secret(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    credential_id: uuid.UUID,
    new_secret: str,
    device: Device,
    verify: DeviceVerifier,
    actor: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> RotationOutcome:
    """Confirm-then-swap rotation of a device credential's stored secret (ADR-0040).

    Stages a fresh KMS-wrapped envelope for *new_secret*, verifies it against
    *device* via *verify*, and activates it ONLY on success — never overwriting the
    prior (working) secret until the new one is confirmed. A failed verify discards
    the unconfirmed envelope (the prior credential stays usable); the rotation is
    retried up to *max_attempts*, then the credential is marked degraded + alerted.

    The transient plaintext is zeroized in a ``finally``; audit events
    (``credential.secret_rotated`` / ``...rotation_failed`` / ``...rotation_degraded``)
    carry ids/versions/attempt counts ONLY.

    Args:
        max_attempts: Stage+verify cycles before degrading; MUST be positive.

    Returns:
        A :class:`RotationOutcome` (state + attempts + activated kek_version).

    Raises:
        ValueError: If *max_attempts* is not positive.
        NotFoundError: If *credential_id* does not exist.
        KeyProviderUnavailable: If the provider is unreachable while wrapping —
            audited durably as ``kek.provider.unavailable`` and re-raised; the
            prior credential is unchanged (fail-closed, no row mutated).
    """
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")

    credential = await session.get(DeviceCredential, credential_id)
    if credential is None:
        raise NotFoundError(f"credential {credential_id} does not exist")

    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        secret_buf = bytearray(new_secret.encode("utf-8"))
        try:
            # STAGE: wrap the new secret into a fresh envelope IN MEMORY. The row's
            # ciphertext columns are untouched here, so the prior secret remains the
            # credential of record until the swap is confirmed (ADR-0040 §1).
            #
            # CR C5: pass the zeroizable bytearray straight into envelope_encrypt
            # (AES-GCM consumes a buffer) rather than bytes(secret_buf). An immutable
            # bytes copy would survive the finally-zeroization below — Python cannot
            # wipe an immutable object — so minimizing immutable copies of the
            # plaintext keeps the transient secret wipeable (ADR-0032 §6). The
            # one immutable copy we cannot avoid is the verifier's DecryptedSecret
            # below, whose contract holds plaintext as bytes.
            try:
                staged: EncryptedSecret = envelope_encrypt(
                    secret_buf, _aad(credential.id), provider
                )
            except KeyProviderUnavailable as exc:
                # Fail-closed (ADR-0032 §4): no row mutated, prior credential intact.
                await _audit_provider_unavailable(
                    session,
                    exc,
                    actor=actor,
                    target_id=str(credential.id),
                    sessionmaker=sessionmaker,
                )
                raise
            # VERIFY: authenticate the staged secret against the device. The
            # plaintext is handed over inside a redaction-safe DecryptedSecret. A
            # verifier that RAISES (transport timeout, auth-protocol error, a
            # device-side KeyProviderUnavailable) is a verification *failure*, not a
            # crash: ADR-0040 §3 treats anything that did not confirm as fail-closed
            # (discard the staged envelope, retry, then degrade). Swallowing it here
            # also keeps the rotation worker's run() loop alive so it finishes the
            # pass and writes its summary instead of aborting on one bad device.
            try:
                confirmed = await verify(device, DecryptedSecret(bytes(secret_buf)))
            except Exception:  # noqa: BLE001 — any verify failure is fail-closed (ADR-0040 §3)
                confirmed = False
        finally:
            # Zeroize the transient plaintext on EVERY path (ADR-0032 §6).
            _zeroize_str_secret(secret_buf)

        if confirmed:
            # ACTIVATE: store the staged envelope onto the row — the swap. Only now
            # does the new secret become the credential of record.
            _store(credential, staged)
            await audit.record(
                session,
                actor=actor,
                action=audit.CREDENTIAL_SECRET_ROTATED,
                target_type=_TARGET_TYPE,
                target_id=str(credential.id),
                detail={
                    "rotation": "device_secret",
                    "kek_version": staged.kek_version,
                    "attempts": attempts,
                },
            )
            await audit.record(
                session,
                actor=actor,
                action=audit.KEK_WRAP,
                target_type=_TARGET_TYPE,
                target_id=str(credential.id),
                detail={"kek_version": staged.kek_version},
            )
            return RotationOutcome(
                credential_id=credential.id,
                state=RotationState.ACTIVATED,
                attempts=attempts,
                kek_version=staged.kek_version,
            )

        # DISCARD the unconfirmed staged envelope: the row was never mutated, so the
        # prior credential stays valid and usable (no lock-out — ADR-0040 §3).
        await audit.record(
            session,
            actor=actor,
            action=audit.CREDENTIAL_SECRET_ROTATION_FAILED,
            target_type=_TARGET_TYPE,
            target_id=str(credential.id),
            detail={"rotation": "device_secret", "attempt": attempts},
        )

    # Repeated failure: mark degraded + alert (ADR-0015). The prior credential is
    # unchanged and still usable; the device is never silently unreachable.
    await audit.record(
        session,
        actor=actor,
        action=audit.CREDENTIAL_SECRET_ROTATION_DEGRADED,
        target_type=_TARGET_TYPE,
        target_id=str(credential.id),
        detail={"rotation": "device_secret", "attempts": attempts},
    )
    _logger.error(
        "credentials.secret_rotation_degraded",
        credential_id=str(credential.id),
        attempts=attempts,
    )
    return RotationOutcome(
        credential_id=credential.id,
        state=RotationState.DEGRADED,
        attempts=attempts,
        kek_version=None,
    )
