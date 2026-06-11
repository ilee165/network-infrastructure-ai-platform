"""Credential-vault envelope encryption (ADR-0011, Decision 1).

Every secret gets its own random 256-bit **DEK**; the payload is encrypted
with AES-256-GCM (96-bit random nonce, caller-supplied AAD binding the
ciphertext to its database row). The DEK is wrapped by the platform **KEK**
(master key) sourced behind the :class:`KeyProvider` interface, which is
KMS-compatible: AWS KMS / Azure Key Vault providers can implement it later
without schema changes. ``kek_version`` makes rotation cheap — :func:`rewrap`
re-wraps the DEK only and never touches the payload ciphertext.

Secure by default: no function in this module ever places key material or
plaintext in an exception message, repr, or log line.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field, replace
from typing import Protocol

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


class KeyProvider(Protocol):
    """KMS-compatible source of the platform KEK (ADR-0011).

    MVP ships :class:`EnvKeyProvider` and :class:`FileKeyProvider`; cloud KMS
    providers implement this same interface on the production roadmap.
    """

    def current_version(self) -> str:
        """Return the version label new secrets should be wrapped under."""
        ...

    def key(self, version: str) -> bytes:
        """Return the 32-byte KEK for *version*.

        Raises:
            UnknownKekVersionError: If this provider cannot supply *version*.
        """
        ...


@dataclass(frozen=True, slots=True)
class EncryptedSecret:
    """Envelope-encrypted secret as persisted in ``device_credentials``.

    Byte fields are excluded from ``repr`` so accidental logging shows only
    the KEK version, never blob contents.
    """

    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    wrapped_dek: bytes = field(repr=False)
    dek_nonce: bytes = field(repr=False)
    kek_version: str


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


class _StaticKeyProvider:
    """Shared base for single-version providers holding one KEK in memory."""

    def __init__(self, kek: bytes, version: str) -> None:
        self._kek = kek
        self._version = version

    def current_version(self) -> str:
        """Return the configured KEK version (``NETOPS_KEK_VERSION``, default ``v1``)."""
        return self._version

    def key(self, version: str) -> bytes:
        """Return the KEK if *version* matches the configured version.

        Raises:
            UnknownKekVersionError: For any other version — restore the
                matching KEK material to read secrets wrapped under it.
        """
        if version != self._version:
            raise UnknownKekVersionError(
                f"KEK version {version!r} is not available (provider holds {self._version!r})"
            )
        return self._kek


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


def envelope_encrypt(plaintext: bytes, aad: bytes, provider: KeyProvider) -> EncryptedSecret:
    """Encrypt *plaintext* under a fresh random DEK, wrapping the DEK with the KEK.

    Args:
        plaintext: Secret bytes to protect.
        aad: Associated data authenticated with the payload — per ADR-0011 the
            credential row id, binding the ciphertext to its row.
        provider: Source of the current KEK.

    Returns:
        The full envelope; every field is safe to persist.
    """
    kek_version = provider.current_version()
    kek = provider.key(kek_version)
    dek = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    dek_nonce = os.urandom(NONCE_BYTES)
    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, None)
    return EncryptedSecret(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        dek_nonce=dek_nonce,
        kek_version=kek_version,
    )


def _unwrap_dek(secret: EncryptedSecret, provider: KeyProvider) -> bytes:
    """Unwrap the DEK using the KEK version recorded in *secret*."""
    kek = provider.key(secret.kek_version)
    try:
        return AESGCM(kek).decrypt(secret.dek_nonce, secret.wrapped_dek, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Wrapped DEK failed authenticated decryption (wrong KEK or tampered data)"
        ) from exc


def envelope_decrypt(secret: EncryptedSecret, aad: bytes, provider: KeyProvider) -> bytes:
    """Decrypt *secret*, verifying *aad*; the inverse of :func:`envelope_encrypt`.

    Raises:
        UnknownKekVersionError: If the provider cannot supply ``secret.kek_version``.
        DecryptionError: If either GCM layer fails authentication (wrong AAD,
            wrong key, or tampered ciphertext).
    """
    dek = _unwrap_dek(secret, provider)
    try:
        return AESGCM(dek).decrypt(secret.nonce, secret.ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Secret payload failed authenticated decryption (wrong AAD or tampered data)"
        ) from exc


def rewrap(secret: EncryptedSecret, provider: KeyProvider) -> EncryptedSecret:
    """Re-wrap the DEK under the provider's current KEK (cheap rotation, ADR-0011).

    The payload ``ciphertext``/``nonce`` are returned untouched — rotation
    never re-encrypts the payload. The provider must still be able to supply
    the old ``secret.kek_version`` to unwrap.
    """
    dek = _unwrap_dek(secret, provider)
    new_version = provider.current_version()
    new_kek = provider.key(new_version)
    dek_nonce = os.urandom(NONCE_BYTES)
    wrapped_dek = AESGCM(new_kek).encrypt(dek_nonce, dek, None)
    return replace(secret, wrapped_dek=wrapped_dek, dek_nonce=dek_nonce, kek_version=new_version)
