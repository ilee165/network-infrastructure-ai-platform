"""Envelope-encryption tests (ADR-0011 §1, ADR-0032 §1/§4/§6).

Wrap/unwrap KeyProviders + AES-256-GCM. Pure unit tests — no Docker, no
network, no database. Secret/key material must never appear in any exception
message, repr, or log line raised by ``app.core.crypto``.
"""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    WRAP_FORMAT_V1,
    DecryptionError,
    EncryptedSecret,
    EnvKeyProvider,
    FileKeyProvider,
    KekConfigurationError,
    KeyProvider,
    KeyProviderError,
    KeyProviderUnavailable,
    ProviderHealth,
    UnknownKekVersionError,
    WrappedDek,
    envelope_decrypt,
    envelope_encrypt,
    get_key_provider,
    is_production_grade,
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
    """Multi-version wrap/unwrap KeyProvider double (stands in for a KMS provider).

    Wraps in-process with AESGCM under the selected version's KEK, binding the
    row-id ``aad`` exactly as the local providers do — so cross-row replay fails.
    """

    def __init__(self, keys: dict[str, bytes], current: str) -> None:
        self._keys = keys
        self._current = current

    @property
    def kek_version(self) -> str:
        return self._current

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        nonce = os.urandom(NONCE_BYTES)
        sealed = AESGCM(self._keys[self._current]).encrypt(nonce, dek, aad)
        return WrappedDek(ciphertext=nonce + sealed, kek_version=self._current)

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        try:
            kek = self._keys[wrapped.kek_version]
        except KeyError:
            raise UnknownKekVersionError(
                f"KEK version {wrapped.kek_version!r} is not available"
            ) from None
        nonce, sealed = wrapped.ciphertext[:NONCE_BYTES], wrapped.ciphertext[NONCE_BYTES:]
        try:
            return AESGCM(kek).decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise DecryptionError("wrapped DEK failed authentication") from exc

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=True, kek_version=self._current)


class _DownProvider:
    """A provider that is unreachable: every wrap/unwrap fails closed (§4)."""

    @property
    def kek_version(self) -> str:
        return "v1"

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        raise KeyProviderUnavailable("TimeoutError")

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        raise KeyProviderUnavailable("TimeoutError")

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=False, kek_version="v1", detail="unreachable")


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
# wrap_dek / unwrap_dek contract (ADR-0032 §1)
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrips_with_matching_aad() -> None:
    provider = _env_provider()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert isinstance(wrapped, WrappedDek)
    assert wrapped.kek_version == "v1"
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek


def test_unwrap_with_wrong_aad_fails_cross_row_replay_guard() -> None:
    provider = _env_provider()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=b"device_credentials:1")
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(wrapped, aad=b"device_credentials:2")


def test_unwrap_unknown_version_raises() -> None:
    provider = _env_provider()
    orphan = WrappedDek(ciphertext=os.urandom(NONCE_BYTES + 48), kek_version="v99")
    with pytest.raises(UnknownKekVersionError):
        provider.unwrap_dek(orphan, aad=_AAD)


def test_wrapped_dek_repr_redacts_ciphertext() -> None:
    wrapped = WrappedDek(ciphertext=b"\xde\xad\xbe\xef" * 8, kek_version="v7")
    assert repr(wrapped) == "<wrapped:v7>"
    assert repr(wrapped.ciphertext) not in repr(wrapped)


def test_provider_health_reports_version() -> None:
    provider = _env_provider(version="v5")
    health = provider.health()
    assert health.available is True
    assert health.kek_version == "v5"


# ---------------------------------------------------------------------------
# Wrap-format discriminator + legacy (pre-W6-T1, aad=None) compatibility
# ---------------------------------------------------------------------------


def test_wrap_blob_carries_version_discriminator() -> None:
    """New local wraps prepend the WRAP_FORMAT_V1 byte so the format is detectable."""
    provider = _env_provider()
    wrapped = provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    assert wrapped.ciphertext[:1] == WRAP_FORMAT_V1


def test_unwrap_reads_legacy_aad_none_wrap_without_version_byte() -> None:
    """A pre-W6-T1 row (no version byte, DEK wrapped with aad=None) still unwraps.

    Persisted KEK->DEK rows written before the AAD-at-wrap-layer change carried
    ``nonce ‖ AESGCM(kek).encrypt(nonce, dek, None)`` with no discriminator. The
    upgraded unwrap path must read them transparently (one-time backward compat),
    otherwise such credentials become permanently unreadable.
    """
    kek_b64 = _kek_b64()
    raw_kek = base64.urlsafe_b64decode(kek_b64)
    provider = _env_provider(kek_b64)
    dek = os.urandom(KEY_BYTES)

    # Forge the exact legacy blob shape: no version byte, aad=None at the wrap.
    nonce = os.urandom(NONCE_BYTES)
    legacy_sealed = AESGCM(raw_kek).encrypt(nonce, dek, None)
    legacy_wrapped = WrappedDek(ciphertext=nonce + legacy_sealed, kek_version="v1")

    assert provider.unwrap_dek(legacy_wrapped, aad=_AAD) == dek


def test_legacy_row_rewraps_to_v1_format() -> None:
    """A legacy aad=None envelope round-trips through decrypt and rewraps to v1."""
    kek_b64 = _kek_b64()
    raw_kek = base64.urlsafe_b64decode(kek_b64)
    provider = _env_provider(kek_b64)

    # Build a full legacy envelope: payload sealed under a DEK (with row-id AAD,
    # unchanged across versions), DEK wrapped with aad=None and no version byte.
    dek = os.urandom(KEY_BYTES)
    payload_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(payload_nonce, _PLAINTEXT, _AAD)
    wrap_nonce = os.urandom(NONCE_BYTES)
    legacy_wrap = AESGCM(raw_kek).encrypt(wrap_nonce, dek, None)
    legacy = EncryptedSecret(
        ciphertext=ciphertext,
        nonce=payload_nonce,
        wrapped_dek=legacy_wrap,
        dek_nonce=wrap_nonce,
        kek_version="v1",
    )

    assert envelope_decrypt(legacy, _AAD, provider) == _PLAINTEXT

    migrated = rewrap(legacy, _AAD, provider)
    # The migrated wrap now carries the v1 discriminator (dek_nonce holds the head).
    assert migrated._wrapped().ciphertext[:1] == WRAP_FORMAT_V1
    assert envelope_decrypt(migrated, _AAD, provider) == _PLAINTEXT


# ---------------------------------------------------------------------------
# Provider production-grade self-report (ADR-0032 §2/§5)
# ---------------------------------------------------------------------------


def test_local_providers_are_not_production_grade() -> None:
    """Env/File local fallbacks self-report is_production_grade = False (ADR-0032 §2)."""
    provider = _env_provider()
    assert provider.is_production_grade is False
    assert is_production_grade(provider) is False


def test_is_production_grade_defaults_false_for_unknown_provider() -> None:
    """An object lacking the attribute is treated as non-production (fail safe)."""

    class _BareProvider:
        pass

    assert is_production_grade(_BareProvider()) is False  # type: ignore[arg-type]


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
# Fail-closed (ADR-0032 §4)
# ---------------------------------------------------------------------------


def test_envelope_encrypt_fails_closed_when_provider_down() -> None:
    with pytest.raises(KeyProviderUnavailable) as excinfo:
        envelope_encrypt(_PLAINTEXT, _AAD, _DownProvider())
    assert _PLAINTEXT.decode() not in str(excinfo.value)
    assert excinfo.value.status_code == 503


def test_envelope_decrypt_fails_closed_when_provider_down() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    with pytest.raises(KeyProviderUnavailable):
        envelope_decrypt(secret, _AAD, _DownProvider())


def test_key_provider_unavailable_is_a_key_provider_error() -> None:
    exc = KeyProviderUnavailable("ConnectTimeout")
    assert isinstance(exc, KeyProviderError)
    assert exc.reason_class == "ConnectTimeout"


# ---------------------------------------------------------------------------
# Rewrap (cheap KEK rotation per ADR-0011/ADR-0032 §3)
# ---------------------------------------------------------------------------


def test_rewrap_preserves_plaintext_and_changes_kek_version() -> None:
    old_kek, new_kek = os.urandom(KEY_BYTES), os.urandom(KEY_BYTES)
    v1_provider: KeyProvider = _RotatingProvider({"v1": old_kek}, current="v1")
    secret = envelope_encrypt(_PLAINTEXT, _AAD, v1_provider)
    assert secret.kek_version == "v1"

    rotated: KeyProvider = _RotatingProvider({"v1": old_kek, "v2": new_kek}, current="v2")
    rewrapped = rewrap(secret, _AAD, rotated)

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
    rewrapped = rewrap(secret, _AAD, provider)
    assert rewrapped.kek_version == "v1"
    assert envelope_decrypt(rewrapped, _AAD, provider) == _PLAINTEXT


# ---------------------------------------------------------------------------
# EnvKeyProvider
# ---------------------------------------------------------------------------


def test_env_provider_loads_key_and_wraps() -> None:
    kek = _kek_b64()
    provider = EnvKeyProvider(_settings(kek=kek, kek_version="v3"))
    assert provider.kek_version == "v3"
    dek = os.urandom(KEY_BYTES)
    assert provider.unwrap_dek(provider.wrap_dek(dek, aad=_AAD), aad=_AAD) == dek


def test_env_provider_rejects_unknown_version() -> None:
    provider = _env_provider()
    orphan = WrappedDek(ciphertext=os.urandom(NONCE_BYTES + 48), kek_version="v2")
    with pytest.raises(UnknownKekVersionError):
        provider.unwrap_dek(orphan, aad=_AAD)


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
    assert provider.kek_version == "v1"
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
# Secrecy of exception messages / no-key-material-leak (ADR-0032 §6 exit gate)
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
        provider.unwrap_dek(WrappedDek(ciphertext=os.urandom(60), kek_version="v404"), aad=_AAD)
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


def test_no_key_material_leak() -> None:
    """ADR-0032 §6 exit gate: no DEK/KEK/wrapped bytes in repr, str, or errors.

    Asserts the structural redactors and typed-error wrapping that keep key
    material off every log/trace/response surface in this module.
    """
    kek_b64 = _kek_b64()
    raw_kek = base64.urlsafe_b64decode(kek_b64)
    provider = _env_provider(kek_b64)

    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)

    # 1. WrappedDek redacts its ciphertext in repr/str.
    for rendered in (repr(wrapped), str(wrapped), f"{wrapped}", f"{wrapped!r}"):
        assert rendered == "<wrapped:v1>"
        assert repr(wrapped.ciphertext) not in rendered
        assert repr(dek) not in rendered

    # 2. EncryptedSecret repr never renders any blob field.
    rendered_secret = repr(secret)
    for blob in (secret.ciphertext, secret.wrapped_dek, secret.dek_nonce, secret.nonce):
        assert repr(blob) not in rendered_secret
    assert repr(raw_kek) not in rendered_secret

    # 3. Provider errors are typed (KeyProviderError) and carry a coarse reason
    #    class only — a raw backend exception never surfaces verbatim.
    err = KeyProviderUnavailable("BotoCoreError")
    assert isinstance(err, KeyProviderError)
    assert err.reason_class == "BotoCoreError"
    assert raw_kek.hex() not in (str(err) + repr(err))

    # 4. No KEK/DEK bytes appear in any exception across the failure paths.
    failures: list[BaseException] = []
    with pytest.raises(DecryptionError) as wrong_aad:
        provider.unwrap_dek(wrapped, aad=b"different-row")
    failures.append(wrong_aad.value)
    with pytest.raises(KeyProviderUnavailable) as down:
        envelope_encrypt(_PLAINTEXT, _AAD, _DownProvider())
    failures.append(down.value)
    for exc in failures:
        blob = str(exc) + repr(exc)
        assert _PLAINTEXT.decode() not in blob
        assert kek_b64 not in blob
        assert repr(raw_kek) not in blob
        assert repr(dek) not in blob


def test_encrypted_secret_is_frozen() -> None:
    provider = _env_provider()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    with pytest.raises(AttributeError):
        secret.kek_version = "v2"  # type: ignore[misc]
    assert isinstance(secret, EncryptedSecret)
