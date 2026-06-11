"""Envelope-encryption tests (ADR-0011 Decision 1): KeyProviders + AES-256-GCM.

Pure unit tests — no Docker, no network, no database. Secret material must
never appear in any exception message raised by ``app.core.crypto``.
"""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    DecryptionError,
    EncryptedSecret,
    EnvKeyProvider,
    FileKeyProvider,
    KekConfigurationError,
    KeyProvider,
    UnknownKekVersionError,
    envelope_decrypt,
    envelope_encrypt,
    get_key_provider,
    rewrap,
)

_PLAINTEXT = b"s3cr3t-device-password"
_AAD = b"device_credentials:42"


def _kek_b64() -> str:
    return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _env_provider(kek_b64: str | None = None, version: str = "v1") -> EnvKeyProvider:
    return EnvKeyProvider(_settings(kek=kek_b64 or _kek_b64(), kek_version=version))


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


# ---------------------------------------------------------------------------
# Settings fields
# ---------------------------------------------------------------------------


def test_settings_vault_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("NETOPS_KEK", "NETOPS_KEK_FILE", "NETOPS_KEK_VERSION"):
        monkeypatch.delenv(var, raising=False)
    settings = _settings()
    assert settings.kek is None
    assert settings.kek_file is None
    assert settings.kek_version == "v1"


def test_settings_kek_is_secret_and_never_in_repr() -> None:
    kek = _kek_b64()
    settings = _settings(kek=kek)
    assert settings.kek is not None
    assert kek not in repr(settings)
    assert kek not in str(settings)
    assert settings.kek.get_secret_value() == kek


# ---------------------------------------------------------------------------
# Envelope roundtrip
# ---------------------------------------------------------------------------


def test_roundtrip_returns_plaintext() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    assert envelope_decrypt(secret, _AAD, provider) == _PLAINTEXT
    assert secret.kek_version == "v1"
    assert secret.ciphertext != _PLAINTEXT
    assert len(secret.nonce) == NONCE_BYTES
    assert len(secret.dek_nonce) == NONCE_BYTES


def test_fresh_dek_and_nonces_per_call() -> None:
    provider = _env_provider()
    first = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    second = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    assert first.ciphertext != second.ciphertext
    assert first.nonce != second.nonce
    assert first.wrapped_dek != second.wrapped_dek
    assert first.dek_nonce != second.dek_nonce


def test_encrypted_secret_repr_hides_blobs() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    rendered = repr(secret)
    assert "kek_version" in rendered
    assert repr(secret.ciphertext) not in rendered
    assert repr(secret.wrapped_dek) not in rendered


# ---------------------------------------------------------------------------
# Authentication failures (AAD binding + tamper detection)
# ---------------------------------------------------------------------------


def test_wrong_aad_fails() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    with pytest.raises(DecryptionError) as excinfo:
        envelope_decrypt(secret, b"device_credentials:43", provider)
    assert _PLAINTEXT.decode() not in str(excinfo.value)


def test_tampered_ciphertext_fails() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    flipped = bytes([secret.ciphertext[0] ^ 0xFF]) + secret.ciphertext[1:]
    tampered = replace(secret, ciphertext=flipped)
    with pytest.raises(DecryptionError):
        envelope_decrypt(tampered, _AAD, provider)


def test_tampered_wrapped_dek_fails() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    flipped = bytes([secret.wrapped_dek[0] ^ 0xFF]) + secret.wrapped_dek[1:]
    tampered = replace(secret, wrapped_dek=flipped)
    with pytest.raises(DecryptionError):
        envelope_decrypt(tampered, _AAD, provider)


def test_decrypt_with_unknown_kek_version_raises() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    orphaned = replace(secret, kek_version="v99")
    with pytest.raises(UnknownKekVersionError):
        envelope_decrypt(orphaned, _AAD, provider)


# ---------------------------------------------------------------------------
# Rewrap (cheap KEK rotation per ADR-0011)
# ---------------------------------------------------------------------------


def test_rewrap_preserves_plaintext_and_changes_kek_version() -> None:
    old_kek, new_kek = os.urandom(KEY_BYTES), os.urandom(KEY_BYTES)
    v1_provider: KeyProvider = _RotatingProvider({"v1": old_kek}, current="v1")
    secret = envelope_encrypt(_PLAINTEXT, _AAD, v1_provider)
    assert secret.kek_version == "v1"

    rotated: KeyProvider = _RotatingProvider({"v1": old_kek, "v2": new_kek}, current="v2")
    rewrapped = rewrap(secret, rotated)

    assert rewrapped.kek_version == "v2"
    assert rewrapped.wrapped_dek != secret.wrapped_dek
    assert rewrapped.dek_nonce != secret.dek_nonce
    # Payload ciphertext untouched — rotation never re-encrypts the payload.
    assert rewrapped.ciphertext == secret.ciphertext
    assert rewrapped.nonce == secret.nonce
    assert envelope_decrypt(rewrapped, _AAD, rotated) == _PLAINTEXT

    # The old single-version provider can no longer unwrap the rewrapped DEK.
    with pytest.raises(UnknownKekVersionError):
        envelope_decrypt(rewrapped, _AAD, v1_provider)


def test_rewrap_under_same_version_still_roundtrips() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    rewrapped = rewrap(secret, provider)
    assert rewrapped.kek_version == "v1"
    assert envelope_decrypt(rewrapped, _AAD, provider) == _PLAINTEXT


# ---------------------------------------------------------------------------
# EnvKeyProvider
# ---------------------------------------------------------------------------


def test_env_provider_loads_key() -> None:
    kek = _kek_b64()
    provider = EnvKeyProvider(_settings(kek=kek, kek_version="v3"))
    assert provider.current_version() == "v3"
    assert provider.key("v3") == base64.urlsafe_b64decode(kek)


def test_env_provider_rejects_unknown_version() -> None:
    provider = _env_provider()
    with pytest.raises(UnknownKekVersionError):
        provider.key("v2")


def test_env_provider_requires_kek() -> None:
    with pytest.raises(KekConfigurationError):
        EnvKeyProvider(_settings(kek=None))


def test_env_provider_rejects_invalid_base64() -> None:
    bad = "not base64 at all!!!"
    with pytest.raises(KekConfigurationError) as excinfo:
        EnvKeyProvider(_settings(kek=bad))
    assert bad not in str(excinfo.value)


def test_env_provider_rejects_wrong_length_key() -> None:
    short = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    with pytest.raises(KekConfigurationError) as excinfo:
        EnvKeyProvider(_settings(kek=short))
    assert short not in str(excinfo.value)


# ---------------------------------------------------------------------------
# FileKeyProvider
# ---------------------------------------------------------------------------


def test_file_provider_loads_key(tmp_path: Path) -> None:
    kek = _kek_b64()
    kek_path = tmp_path / "kek"
    kek_path.write_text(kek + "\n", encoding="utf-8")  # trailing newline is tolerated
    provider = FileKeyProvider(_settings(kek_file=kek_path))
    assert provider.current_version() == "v1"
    assert provider.key("v1") == base64.urlsafe_b64decode(kek)
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    assert envelope_decrypt(secret, _AAD, provider) == _PLAINTEXT


def test_file_provider_requires_path() -> None:
    with pytest.raises(KekConfigurationError):
        FileKeyProvider(_settings(kek_file=None))


def test_file_provider_missing_file(tmp_path: Path) -> None:
    with pytest.raises(KekConfigurationError):
        FileKeyProvider(_settings(kek_file=tmp_path / "absent"))


# ---------------------------------------------------------------------------
# get_key_provider factory
# ---------------------------------------------------------------------------


def test_factory_returns_env_provider_when_kek_set() -> None:
    provider = get_key_provider(_settings(kek=_kek_b64()))
    assert isinstance(provider, EnvKeyProvider)


def test_factory_returns_file_provider_when_only_file_set(tmp_path: Path) -> None:
    kek_path = tmp_path / "kek"
    kek_path.write_text(_kek_b64(), encoding="utf-8")
    provider = get_key_provider(_settings(kek=None, kek_file=kek_path))
    assert isinstance(provider, FileKeyProvider)


def test_factory_prefers_env_over_file(tmp_path: Path) -> None:
    kek_path = tmp_path / "kek"
    kek_path.write_text(_kek_b64(), encoding="utf-8")
    provider = get_key_provider(_settings(kek=_kek_b64(), kek_file=kek_path))
    assert isinstance(provider, EnvKeyProvider)


def test_factory_raises_clear_error_when_unconfigured() -> None:
    with pytest.raises(KekConfigurationError, match="NETOPS_KEK"):
        get_key_provider(_settings(kek=None, kek_file=None))


# ---------------------------------------------------------------------------
# Secrecy of exception messages
# ---------------------------------------------------------------------------


def test_no_secret_material_in_any_exception_message() -> None:
    kek = _kek_b64()
    provider = _env_provider(kek)
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)

    raised: list[BaseException] = []
    with pytest.raises(DecryptionError) as wrong_aad:
        envelope_decrypt(secret, b"other-row", provider)
    raised.append(wrong_aad.value)
    with pytest.raises(UnknownKekVersionError) as unknown:
        provider.key("v404")
    raised.append(unknown.value)
    with pytest.raises(KekConfigurationError) as unconfigured:
        get_key_provider(_settings(kek=None, kek_file=None))
    raised.append(unconfigured.value)

    raw_kek = base64.urlsafe_b64decode(kek)
    for exc in raised:
        message = str(exc) + repr(exc)
        assert _PLAINTEXT.decode() not in message
        assert kek not in message
        assert repr(raw_kek) not in message


def test_encrypted_secret_is_frozen() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    with pytest.raises(AttributeError):
        secret.kek_version = "v2"  # type: ignore[misc]
    assert isinstance(secret, EncryptedSecret)
