"""Credential-vault envelope encryption (ADR-0011 §1, ADR-0032 §1/§4/§6).

Every secret gets its own random 256-bit **DEK**; the payload is encrypted
with AES-256-GCM (96-bit random nonce, caller-supplied AAD binding the
ciphertext to its database row). The DEK is **wrapped** by the platform **KEK**
(master key) behind the :class:`KeyProvider` *wrap/unwrap* contract (ADR-0032
§1): the provider exposes only :meth:`~KeyProvider.wrap_dek` /
:meth:`~KeyProvider.unwrap_dek` — never a KEK byte-export — so a real KMS
(AWS / Azure / Vault) can implement it without ever releasing key material into
the process. ``kek_version`` makes rotation cheap — :func:`rewrap` re-wraps the
DEK only and never touches the payload ciphertext.

The credential row-id AAD is bound at **both** envelope layers: DEK->secret
(payload) and KEK->DEK (wrap). Binding it at the wrap layer too means a wrapped
DEK lifted from one row cannot be replayed onto another even with KEK access
(ADR-0032 §1, cross-row replay guard). Local providers bind it in-process; a
provider that can neither pass nor inner-wrap ``aad`` MUST reject a non-empty
``aad`` at construction.

Fail closed (ADR-0032 §4): when the provider is unreachable, wrap/unwrap raise
the typed :class:`KeyProviderUnavailable` (503-class) — never plaintext, never a
cached KEK. The plaintext DEK lives only for the single AESGCM op and is
zeroized after use; it is never cached, serialized, queued, or audited.

Secure by default (ADR-0032 §6): no function, ``__repr__``, or exception in this
module ever places key material (KEK, DEK, wrapped blob) or plaintext in a log
line, repr, or message. :class:`WrappedDek` redacts its bytes; raw backend SDK
errors are wrapped as a typed :class:`KeyProviderError` so they never surface
verbatim.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field, replace
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings
from app.core.errors import NetOpsError

#: AES-256 key size (bytes) for both the KEK and every per-secret DEK.
KEY_BYTES = 32

#: GCM standard 96-bit nonce size (bytes).
NONCE_BYTES = 12


class KekConfigurationError(NetOpsError):
    """The credential-vault KEK is missing or malformed (deployment problem)."""

    status_code = 500
    title = "Credential Vault Misconfigured"
    slug = "kek-misconfigured"


class UnknownKekVersionError(NetOpsError):
    """A stored secret references a KEK version this provider cannot supply."""

    status_code = 500
    title = "Unknown KEK Version"
    slug = "unknown-kek-version"


class DecryptionError(NetOpsError):
    """Authenticated decryption failed (wrong key, wrong AAD, or tampered data)."""

    status_code = 500
    title = "Credential Decryption Failed"
    slug = "decryption-failed"


class KeyProviderError(NetOpsError):
    """A key-provider operation failed.

    Raw backend SDK exceptions (boto3 / azure / hvac) are wrapped in this typed
    error — and only a coarse ``reason_class`` is ever exposed — so a provider's
    request/response context can never surface verbatim in a log, trace, or API
    response (ADR-0032 §6). The originating exception is chained for local
    debugging but is *not* part of any rendered message.
    """

    status_code = 500
    title = "Key Provider Error"
    slug = "key-provider-error"

    def __init__(self, reason_class: str) -> None:
        #: Coarse, non-sensitive machine label for the failure (e.g. the
        #: backend exception's class name) — safe to log/audit.
        self.reason_class = reason_class
        super().__init__(f"key-provider operation failed ({reason_class})")


class KeyProviderUnavailable(KeyProviderError):
    """The key provider is unreachable; the vault fails closed (ADR-0032 §4).

    A 503-class error: on writes no row is stored unwrapped; on reads the
    dependent Celery task fails and retries (``acks_late``) and a ChangeRequest
    that cannot unwrap its credential goes to ``failed``, never ``completed``.
    """

    status_code = 503
    title = "Key Provider Unavailable"
    slug = "key-provider-unavailable"


@dataclass(frozen=True, slots=True)
class WrappedDek:
    """A DEK wrapped under the active KEK (ADR-0032 §1).

    Maps 1:1 onto the existing ``device_credentials`` columns:
    ``ciphertext`` -> ``wrapped_dek`` (with the wrap nonce prepended for local
    providers) and ``kek_version`` -> ``kek_version``. The ciphertext is
    redacted from ``repr`` so an accidental log shows only the KEK version.
    """

    ciphertext: bytes = field(repr=False)
    kek_version: str

    def __repr__(self) -> str:
        return f"<wrapped:{self.kek_version}>"


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Liveness of a :class:`KeyProvider` for the fail-closed readiness gate.

    ``detail`` carries a coarse machine reason only (never key material); the
    readiness-probe / ``/metrics`` wiring lands with the KMS backends in W6-T2.
    """

    available: bool
    kek_version: str
    detail: str | None = None


@runtime_checkable
class KeyProvider(Protocol):
    """KMS-compatible wrap/unwrap source for the platform KEK (ADR-0032 §1).

    The KEK is used *only* through :meth:`wrap_dek` / :meth:`unwrap_dek` — there
    is deliberately **no** ``get_kek()`` / ``export()`` byte method, so a network
    KMS can implement the same contract without ever releasing key material
    (ADR-0032 §1/§6). MVP ships the in-process :class:`EnvKeyProvider` /
    :class:`FileKeyProvider`; AWS / Azure / Vault backends land in W6-T2.
    """

    @property
    def kek_version(self) -> str:
        """Stable id of the *active* wrapping key, stored on each row."""
        ...

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        """Wrap *dek* under the active KEK, binding *aad* (the credential row id).

        Raises:
            KeyProviderUnavailable: If the provider is unreachable (fail closed).
            KeyProviderError: If wrapping fails for any other backend reason.
        """
        ...

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        """Unwrap *wrapped* under its recorded KEK version, verifying *aad*.

        Returns the transient plaintext DEK; the caller zeroizes it after the
        single AESGCM op (ADR-0032 §6 — no DEK cache).

        Raises:
            UnknownKekVersionError: If the provider cannot supply the version.
            DecryptionError: If authentication fails (wrong KEK, wrong AAD, or
                tampered data — the cross-row replay guard).
            KeyProviderUnavailable: If the provider is unreachable (fail closed).
        """
        ...

    def health(self) -> ProviderHealth:
        """Report provider liveness for the fail-closed readiness gate (§4)."""
        ...


def _decode_kek(encoded: str, *, source: str) -> bytes:
    """Decode and validate a urlsafe-base64 KEK; *source* names where it came from.

    Error messages identify the source, never the key material itself.
    """
    try:
        # base64.b64decode with altchars instead of urlsafe_b64decode: only the
        # former supports validate=True (reject garbage instead of skipping it).
        raw = base64.b64decode(encoded.encode("ascii"), altchars=b"-_", validate=True)
    except ValueError as exc:  # binascii.Error and UnicodeEncodeError subclass ValueError
        raise KekConfigurationError(f"KEK from {source} is not valid urlsafe base64") from exc
    if len(raw) != KEY_BYTES:
        raise KekConfigurationError(
            f"KEK from {source} must decode to exactly {KEY_BYTES} bytes (AES-256)"
        )
    return raw


def _zeroize(buf: bytearray) -> None:
    """Best-effort wipe of a mutable plaintext-DEK buffer after the AESGCM op."""
    for i in range(len(buf)):
        buf[i] = 0


class _StaticKeyProvider:
    """In-process wrap/unwrap base for single-version local providers (ADR-0032 §2).

    Holds one KEK in memory (local fallback, non-production) and binds the
    row-id ``aad`` *natively* via the AESGCM wrap layer — so the same
    cross-row-replay guard a KMS gives applies here too.
    """

    def __init__(self, kek: bytes, version: str) -> None:
        self._kek = kek
        self._version = version

    @property
    def kek_version(self) -> str:
        """Return the configured KEK version (``NETOPS_KEK_VERSION``, default ``v1``)."""
        return self._version

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        """AESGCM-wrap *dek* under the in-process KEK, binding *aad*.

        The 96-bit nonce is prepended to the GCM output so the single
        ``WrappedDek.ciphertext`` blob is self-contained.
        """
        nonce = os.urandom(NONCE_BYTES)
        sealed = AESGCM(self._kek).encrypt(nonce, dek, aad)
        return WrappedDek(ciphertext=nonce + sealed, kek_version=self._version)

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        """Unwrap *wrapped* if its version matches and *aad* authenticates.

        Raises:
            UnknownKekVersionError: For any other version — restore the matching
                KEK material to read secrets wrapped under it.
            DecryptionError: If GCM authentication fails (wrong KEK, wrong AAD,
                or tampered wrapped blob).
        """
        if wrapped.kek_version != self._version:
            raise UnknownKekVersionError(
                f"KEK version {wrapped.kek_version!r} is not available "
                f"(provider holds {self._version!r})"
            )
        nonce, sealed = wrapped.ciphertext[:NONCE_BYTES], wrapped.ciphertext[NONCE_BYTES:]
        try:
            return AESGCM(self._kek).decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise DecryptionError(
                "Wrapped DEK failed authenticated decryption (wrong KEK, wrong AAD, "
                "or tampered data)"
            ) from exc

    def health(self) -> ProviderHealth:
        """A local in-process KEK is always reachable."""
        return ProviderHealth(available=True, kek_version=self._version)


class EnvKeyProvider(_StaticKeyProvider):
    """KEK from the environment: ``NETOPS_KEK`` (urlsafe-base64, 32 bytes decoded)."""

    def __init__(self, settings: Settings) -> None:
        if settings.kek is None:
            raise KekConfigurationError("NETOPS_KEK is not set; cannot build EnvKeyProvider")
        super().__init__(
            _decode_kek(settings.kek.get_secret_value(), source="NETOPS_KEK"),
            settings.kek_version,
        )


class FileKeyProvider(_StaticKeyProvider):
    """KEK from a mounted file (Docker/K8s secret): ``NETOPS_KEK_FILE`` path."""

    def __init__(self, settings: Settings) -> None:
        if settings.kek_file is None:
            raise KekConfigurationError("NETOPS_KEK_FILE is not set; cannot build FileKeyProvider")
        try:
            encoded = settings.kek_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KekConfigurationError(f"KEK file {settings.kek_file} could not be read") from exc
        super().__init__(
            _decode_kek(encoded, source=str(settings.kek_file)),
            settings.kek_version,
        )


def get_key_provider(settings: Settings) -> KeyProvider:
    """Build the configured :class:`KeyProvider` (``kek`` wins over ``kek_file``).

    Raises:
        KekConfigurationError: If neither ``NETOPS_KEK`` nor ``NETOPS_KEK_FILE``
            is configured — the credential vault cannot operate without a KEK.
    """
    if settings.kek is not None:
        return EnvKeyProvider(settings)
    if settings.kek_file is not None:
        return FileKeyProvider(settings)
    raise KekConfigurationError(
        "Credential vault KEK is not configured: set NETOPS_KEK (urlsafe-base64, "
        "32 bytes decoded) or NETOPS_KEK_FILE (path to a file containing it)"
    )


@dataclass(frozen=True, slots=True)
class EncryptedSecret:
    """Envelope-encrypted secret as persisted in ``device_credentials``.

    ``wrapped_dek`` / ``dek_nonce`` are the wrap-layer columns; for local
    providers the :class:`WrappedDek` blob is split back into them on store and
    recombined on unwrap. Byte fields are excluded from ``repr`` so accidental
    logging shows only the KEK version, never blob contents.
    """

    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    wrapped_dek: bytes = field(repr=False)
    dek_nonce: bytes = field(repr=False)
    kek_version: str

    def _wrapped(self) -> WrappedDek:
        """Recombine the two wrap-layer columns into a provider :class:`WrappedDek`."""
        return WrappedDek(
            ciphertext=self.dek_nonce + self.wrapped_dek, kek_version=self.kek_version
        )


def _split_wrapped(wrapped: WrappedDek) -> tuple[bytes, bytes]:
    """Split a local-provider blob into ``(dek_nonce, wrapped_dek)`` columns."""
    return wrapped.ciphertext[:NONCE_BYTES], wrapped.ciphertext[NONCE_BYTES:]


def envelope_encrypt(plaintext: bytes, aad: bytes, provider: KeyProvider) -> EncryptedSecret:
    """Encrypt *plaintext* under a fresh random DEK, wrapping the DEK with the KEK.

    Args:
        plaintext: Secret bytes to protect.
        aad: Associated data authenticated with **both** envelope layers — per
            ADR-0011/ADR-0032 the credential row id, binding the payload *and*
            the wrapped DEK to its row.
        provider: Wrap/unwrap source of the active KEK.

    Returns:
        The full envelope; every field is safe to persist.

    Raises:
        KeyProviderUnavailable: If the provider is unreachable (no row written).
    """
    dek = bytearray(AESGCM.generate_key(bit_length=KEY_BYTES * 8))
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
        wrapped = provider.wrap_dek(bytes(dek), aad=aad)
    finally:
        _zeroize(dek)
    dek_nonce, wrapped_dek = _split_wrapped(wrapped)
    return EncryptedSecret(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        dek_nonce=dek_nonce,
        kek_version=wrapped.kek_version,
    )


def envelope_decrypt(secret: EncryptedSecret, aad: bytes, provider: KeyProvider) -> bytes:
    """Decrypt *secret*, verifying *aad*; the inverse of :func:`envelope_encrypt`.

    The plaintext DEK is transient and zeroized after the single AESGCM op
    (ADR-0032 §6 — no DEK cache).

    Raises:
        UnknownKekVersionError: If the provider cannot supply ``secret.kek_version``.
        DecryptionError: If either GCM layer fails authentication (wrong AAD,
            wrong key, or tampered ciphertext).
        KeyProviderUnavailable: If the provider is unreachable (fail closed).
    """
    dek = bytearray(provider.unwrap_dek(secret._wrapped(), aad=aad))
    try:
        return AESGCM(bytes(dek)).decrypt(secret.nonce, secret.ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Secret payload failed authenticated decryption (wrong AAD or tampered data)"
        ) from exc
    finally:
        _zeroize(dek)


def rewrap(secret: EncryptedSecret, aad: bytes, provider: KeyProvider) -> EncryptedSecret:
    """Re-wrap the DEK under the provider's active KEK (cheap rotation, ADR-0032 §3).

    The payload ``ciphertext``/``nonce`` are returned untouched — rotation never
    re-encrypts the payload. *aad* (the credential row id) is bound on both the
    old unwrap and the new wrap, so the row binding survives rotation. The
    provider must still be able to supply the old ``secret.kek_version``.

    Raises:
        UnknownKekVersionError: If the provider cannot supply the old version.
        KeyProviderUnavailable: If the provider is unreachable (fail closed).
    """
    dek = bytearray(provider.unwrap_dek(secret._wrapped(), aad=aad))
    try:
        wrapped = provider.wrap_dek(bytes(dek), aad=aad)
    finally:
        _zeroize(dek)
    dek_nonce, wrapped_dek = _split_wrapped(wrapped)
    return replace(
        secret, wrapped_dek=wrapped_dek, dek_nonce=dek_nonce, kek_version=wrapped.kek_version
    )
