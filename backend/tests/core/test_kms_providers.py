"""KMS-backend KeyProvider tests (P1 W6-T2, ADR-0032 §1/§2/§4).

Pure unit tests — no Docker, no network, no real cloud SDK. boto3 / azure /
hvac are NOT a test dependency: each provider takes an injected low-level KMS
*client*, and these tests inject a deterministic in-memory fake that reproduces
each backend's native semantics (AWS ``EncryptionContext``, Vault ``context``,
Azure ``wrapKey``/``unwrapKey`` with NO native AAD). The providers' real
wrap/unwrap logic — including the Azure inner-AESGCM AAD layer — is exercised at
full coverage against those fakes; LocalStack / Azurite-fake / dev-Vault and the
real clouds are CI-emulator / lab-deferred (ADR-0032 Negative).

Every backend MUST bind the credential row-id AAD so a wrapped DEK lifted from
one row cannot be replayed onto another (cross-row replay guard, ADR-0032 §1) —
asserted identically on all three, including the Azure inner-AESGCM path.
"""

from __future__ import annotations

import base64
import os

import pytest

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    AwsKmsKeyProvider,
    AzureKeyVaultKeyProvider,
    DecryptionError,
    EnvKeyProvider,
    FakeKmsKeyProvider,
    HashiCorpVaultTransitKeyProvider,
    KekConfigurationError,
    KeyProvider,
    KeyProviderError,
    KeyProviderUnavailable,
    LocalKeyProviderInProductionError,
    WrappedDek,
    envelope_decrypt,
    envelope_encrypt,
    get_key_provider,
    require_production_grade,
)

_PLAINTEXT = b"s3cr3t-device-password"
_AAD = b"device_credentials:42"
_OTHER_AAD = b"device_credentials:99"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Deterministic in-memory fake KMS clients (per-backend native semantics)
# ---------------------------------------------------------------------------


class _FakeAwsKmsClient:
    """boto3 ``kms`` shape: Encrypt/Decrypt with native ``EncryptionContext``.

    Reproduces KMS's AAD binding: Decrypt fails when the ``EncryptionContext``
    differs from Encrypt. ``CiphertextBlob`` is opaque; here it is a reversible
    in-memory token carrying the context so a mismatch is detectable without real
    crypto. ``KeyId`` in Decrypt's response echoes the configured ARN.
    """

    def __init__(self, key_arn: str) -> None:
        self._key_arn = key_arn
        self._store: dict[bytes, tuple[bytes, frozenset[tuple[str, str]]]] = {}
        self.down = False

    def encrypt(
        self, *, KeyId: str, Plaintext: bytes, EncryptionContext: dict[str, str]
    ) -> dict[str, object]:
        if self.down:
            raise ConnectionError("kms unreachable")
        token = os.urandom(16)
        self._store[token] = (Plaintext, frozenset(EncryptionContext.items()))
        return {"CiphertextBlob": token, "KeyId": self._key_arn}

    def decrypt(
        self, *, CiphertextBlob: bytes, EncryptionContext: dict[str, str]
    ) -> dict[str, object]:
        if self.down:
            raise ConnectionError("kms unreachable")
        try:
            plaintext, ctx = self._store[CiphertextBlob]
        except KeyError as exc:
            raise ValueError("InvalidCiphertextException") from exc
        if ctx != frozenset(EncryptionContext.items()):
            # KMS raises InvalidCiphertextException on a context mismatch.
            raise ValueError("InvalidCiphertextException: context mismatch")
        return {"Plaintext": plaintext, "KeyId": self._key_arn}


class _FakeVaultTransitClient:
    """hvac ``secrets.transit`` shape: encrypt/decrypt with native ``context``.

    Reproduces Transit versioned keys: ciphertext is ``vault:v<N>:<token>``;
    decrypt accepts any version still present (old versions readable, ADR-0032
    §2). ``context`` (the row-id AAD) is bound natively — decrypt fails on a
    mismatch.
    """

    def __init__(self, current_version: int = 1) -> None:
        self.current_version = current_version
        self._store: dict[str, tuple[bytes, bytes]] = {}
        self.down = False

    def encrypt_data(self, *, name: str, plaintext: bytes, context: bytes) -> dict[str, object]:
        if self.down:
            raise ConnectionError("vault unreachable")
        token = os.urandom(16).hex()
        ref = f"vault:v{self.current_version}:{token}"
        self._store[ref] = (plaintext, context)
        return {"data": {"ciphertext": ref}}

    def decrypt_data(self, *, name: str, ciphertext: str, context: bytes) -> dict[str, object]:
        if self.down:
            raise ConnectionError("vault unreachable")
        try:
            plaintext, bound = self._store[ciphertext]
        except KeyError as exc:
            raise ValueError("invalid ciphertext") from exc
        if bound != context:
            raise ValueError("context mismatch")
        return {"data": {"plaintext": plaintext}}


class _FakeAzureKeyClient:
    """azure-keyvault-keys ``CryptographyClient`` shape: wrapKey/unwrapKey.

    Deliberately has NO ``context``/AAD parameter — Azure ``wrapKey``/``unwrapKey``
    has no native AAD. The provider must bind the row-id via its own AESGCM inner
    layer; this fake only wraps/unwraps the raw inner key with no row binding.
    """

    def __init__(self, key_name: str) -> None:
        self._key_name = key_name
        self._store: dict[bytes, bytes] = {}
        self.down = False

    def wrap_key(self, *, key: bytes) -> bytes:
        if self.down:
            raise ConnectionError("azure unreachable")
        token = os.urandom(16)
        self._store[token] = key
        return token

    def unwrap_key(self, *, encrypted_key: bytes) -> bytes:
        if self.down:
            raise ConnectionError("azure unreachable")
        try:
            return self._store[encrypted_key]
        except KeyError as exc:
            raise ValueError("invalid wrapped key") from exc


def _aws() -> AwsKmsKeyProvider:
    arn = "arn:aws:kms:us-east-1:000000000000:key/test"
    return AwsKmsKeyProvider(key_arn=arn, client=_FakeAwsKmsClient(arn))


def _vault(version: int = 1) -> HashiCorpVaultTransitKeyProvider:
    return HashiCorpVaultTransitKeyProvider(
        transit_mount="transit",
        transit_key="netops-kek",
        client=_FakeVaultTransitClient(current_version=version),
    )


def _azure() -> AzureKeyVaultKeyProvider:
    return AzureKeyVaultKeyProvider(
        vault_uri="https://vault.vault.azure.net/",
        key_name="netops-kek",
        client=_FakeAzureKeyClient("netops-kek"),
    )


_PROVIDERS = {"aws": _aws, "vault": _vault, "azure": _azure}


# ---------------------------------------------------------------------------
# Round-trip + cross-row replay guard (ALL THREE backends)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_wrap_unwrap_roundtrips_with_matching_aad(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert isinstance(wrapped, WrappedDek)
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_wrong_row_id_aad_fails_cross_row_replay_guard(name: str) -> None:
    """A wrapped DEK lifted from row A cannot be unwrapped under row B's AAD.

    Native context (AWS/Vault) and the Azure inner-AESGCM layer must enforce this
    identically — the guarantee holds on every backend.
    """
    provider: KeyProvider = _PROVIDERS[name]()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(wrapped, aad=_OTHER_AAD)


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_envelope_roundtrip_through_provider(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    assert envelope_decrypt(secret, _AAD, provider) == _PLAINTEXT


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_envelope_wrong_aad_fails(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    secret = envelope_encrypt(_PLAINTEXT, _AAD, provider)
    with pytest.raises(DecryptionError):
        envelope_decrypt(secret, _OTHER_AAD, provider)


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_all_backends_are_production_grade(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    assert provider.is_production_grade is True


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_healthy_when_reachable(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    health = provider.health()
    assert health.available is True
    assert health.kek_version == provider.kek_version


# ---------------------------------------------------------------------------
# Azure inner-AESGCM layer specifics (the subtlest correctness point)
# ---------------------------------------------------------------------------


def test_azure_blob_layout_is_nonce_wrapped_inner_ciphertext() -> None:
    """WrappedDek.ciphertext = inner-nonce ‖ wrapped-inner-key ‖ inner-ciphertext.

    The single-blob schema is unchanged (ADR-0032 §1): everything rides in
    ``WrappedDek.ciphertext`` and the fake's wrapped-inner-key is a fixed 16-byte
    token, so the blob is strictly longer than nonce + token alone (it carries the
    inner GCM ciphertext+tag too).
    """
    from app.core.crypto import NONCE_BYTES

    provider = _azure()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    # nonce(12) + wrapped-inner-key(16) + inner GCM(dek + 16-byte tag) > 12 + 16.
    assert len(wrapped.ciphertext) > NONCE_BYTES + 16


def test_azure_tampered_inner_ciphertext_fails() -> None:
    provider = _azure()
    wrapped = provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    blob = bytearray(wrapped.ciphertext)
    blob[-1] ^= 0xFF  # flip a byte in the inner GCM ciphertext/tag
    tampered = WrappedDek(ciphertext=bytes(blob), kek_version=wrapped.kek_version)
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(tampered, aad=_AAD)


# ---------------------------------------------------------------------------
# kek_version shape + old-version decrypt (AWS/Vault)
# ---------------------------------------------------------------------------


def test_aws_kek_version_is_key_arn() -> None:
    provider = _aws()
    assert provider.kek_version.startswith("arn:aws:kms:")


def test_vault_kek_version_shape_is_key_colon_vN() -> None:
    """Vault kek_version = ``<key>:vN`` (ADR-0032 §2 rotation-model column)."""
    provider = _vault(version=3)
    assert provider.kek_version == "netops-kek:v3"


def test_vault_decrypt_accepts_old_versions() -> None:
    """A DEK wrapped under v1 still unwraps after the transit key rotates to v2."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key="netops-kek", client=client
    )
    dek = os.urandom(KEY_BYTES)
    wrapped = v1.wrap_dek(dek, aad=_AAD)
    assert wrapped.kek_version == "netops-kek:v1"

    # Rotate the transit key; the same provider/client now wraps at v2 but must
    # still decrypt the v1 blob (old versions readable).
    client.current_version = 2
    v2 = HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key="netops-kek", client=client
    )
    assert v2.kek_version == "netops-kek:v2"
    assert v2.unwrap_dek(wrapped, aad=_AAD) == dek
    new_wrapped = v2.wrap_dek(dek, aad=_AAD)
    assert new_wrapped.kek_version == "netops-kek:v2"


def test_aws_unwrap_unknown_blob_is_typed_error() -> None:
    """An orphan/invalid ciphertext surfaces as the typed DecryptionError.

    KMS cannot distinguish a tampered blob from a stale one — both fail
    authenticated decryption — so it is the same cross-row/tamper guard, never a
    raw boto3 exception (which is a KeyProviderError subclass tree, ADR-0032 §6).
    """
    provider = _aws()
    orphan = WrappedDek(ciphertext=os.urandom(40), kek_version=provider.kek_version)
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(orphan, aad=_AAD)


# ---------------------------------------------------------------------------
# Fail-closed health + unreachable backend (ADR-0032 §4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_unreachable_backend_health_is_unavailable(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    provider._client.down = True  # type: ignore[attr-defined]
    health = provider.health()
    assert health.available is False
    assert health.detail  # coarse machine reason, never key material


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_unreachable_backend_wrap_fails_closed(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    provider._client.down = True  # type: ignore[attr-defined]
    with pytest.raises(KeyProviderUnavailable):
        provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_unreachable_backend_unwrap_fails_closed(name: str) -> None:
    provider: KeyProvider = _PROVIDERS[name]()
    wrapped = provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    provider._client.down = True  # type: ignore[attr-defined]
    with pytest.raises(KeyProviderUnavailable):
        provider.unwrap_dek(wrapped, aad=_AAD)


# ---------------------------------------------------------------------------
# Deterministic in-memory fake provider (unit-test default)
# ---------------------------------------------------------------------------


def test_fake_provider_roundtrips_and_is_production_grade() -> None:
    provider = FakeKmsKeyProvider()
    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek
    assert provider.is_production_grade is True
    assert provider.health().available is True


def test_fake_provider_wrong_aad_fails() -> None:
    provider = FakeKmsKeyProvider()
    wrapped = provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(wrapped, aad=_OTHER_AAD)


def test_fake_provider_can_simulate_outage() -> None:
    provider = FakeKmsKeyProvider(available=False)
    assert provider.health().available is False
    with pytest.raises(KeyProviderUnavailable):
        provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)


# ---------------------------------------------------------------------------
# Config-only selection (VAULT_KEY_PROVIDER) — service never branches on backend
# ---------------------------------------------------------------------------


def test_factory_selects_aws_by_config() -> None:
    settings = _settings(
        vault_key_provider="aws",
        aws_kms_key_arn="arn:aws:kms:us-east-1:000000000000:key/abc",
    )
    provider = get_key_provider(settings, client=_FakeAwsKmsClient(settings.aws_kms_key_arn))
    assert isinstance(provider, AwsKmsKeyProvider)


def test_factory_selects_vault_by_config() -> None:
    settings = _settings(
        vault_key_provider="vault",
        vault_addr="https://vault.example:8200",
        vault_transit_key="netops-kek",
        vault_credential_ref="netops-kek-role",
    )
    provider = get_key_provider(settings, client=_FakeVaultTransitClient())
    assert isinstance(provider, HashiCorpVaultTransitKeyProvider)


def test_factory_selects_azure_by_config() -> None:
    settings = _settings(
        vault_key_provider="azure",
        azure_key_vault_uri="https://kv.vault.azure.net/",
        azure_key_name="netops-kek",
    )
    provider = get_key_provider(settings, client=_FakeAzureKeyClient("netops-kek"))
    assert isinstance(provider, AzureKeyVaultKeyProvider)


def test_factory_aws_requires_key_arn() -> None:
    settings = _settings(vault_key_provider="aws")
    with pytest.raises(KekConfigurationError):
        get_key_provider(settings, client=_FakeAwsKmsClient("arn:unused"))


def test_factory_vault_requires_key_and_credential_ref() -> None:
    settings = _settings(vault_key_provider="vault", vault_addr="https://vault:8200")
    with pytest.raises(KekConfigurationError):
        get_key_provider(settings, client=_FakeVaultTransitClient())


def test_factory_azure_requires_uri_and_key_name() -> None:
    settings = _settings(vault_key_provider="azure")
    with pytest.raises(KekConfigurationError):
        get_key_provider(settings, client=_FakeAzureKeyClient("k"))


# ---------------------------------------------------------------------------
# Prod-grade gating (ADR-0032 §2): local provider barred in production
# ---------------------------------------------------------------------------


def test_require_production_grade_refuses_local_provider_in_prod() -> None:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    provider = EnvKeyProvider(_settings(kek=kek))
    with pytest.raises(LocalKeyProviderInProductionError) as excinfo:
        require_production_grade(provider, is_prod=True)
    message = str(excinfo.value)
    assert "EnvKeyProvider" in message
    assert "not permitted in production" in message
    assert "D11/ADR-0032 §2" in message


def test_require_production_grade_allows_kms_provider_in_prod() -> None:
    provider = _aws()
    # Must not raise — a KMS backend is permitted in production.
    require_production_grade(provider, is_prod=True)


def test_require_production_grade_allows_local_provider_outside_prod() -> None:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    provider = EnvKeyProvider(_settings(kek=kek))
    require_production_grade(provider, is_prod=False)  # local is fine in dev


def test_local_provider_in_production_error_is_runtime_error() -> None:
    """The gate raises a RuntimeError subclass (ADR-0032 §2 refuse-to-start)."""
    assert issubclass(LocalKeyProviderInProductionError, RuntimeError)


# ---------------------------------------------------------------------------
# No-leak: raw SDK exceptions wrapped; credential_ref never logged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(_PROVIDERS))
def test_raw_sdk_exception_never_surfaces_verbatim(name: str) -> None:
    """A raw client exception is wrapped as a typed KeyProviderError (reason class only)."""
    provider: KeyProvider = _PROVIDERS[name]()
    provider._client.down = True  # type: ignore[attr-defined]
    with pytest.raises(KeyProviderError) as excinfo:
        provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    err = excinfo.value
    # Coarse machine reason only — the raw "unreachable" message must not surface.
    assert "unreachable" not in str(err)
    assert "unreachable" not in repr(err)
    assert err.reason_class  # a class-name label, safe to log


def test_provider_repr_scrubbed_of_secrets() -> None:
    """Provider repr carries no key handle / vault URI / credential_ref value."""
    aws = _aws()
    vault = HashiCorpVaultTransitKeyProvider(
        transit_mount="transit",
        transit_key="netops-kek",
        client=_FakeVaultTransitClient(),
        credential_ref="super-secret-approle-id",
    )
    azure = _azure()
    assert "super-secret-approle-id" not in repr(vault)
    assert "super-secret-approle-id" not in str(vault)
    # The class name is fine to show; the configured handles/refs are not the
    # focus, but the credential_ref in particular must never appear.
    for rendered in (repr(aws), repr(vault), repr(azure)):
        assert "super-secret-approle-id" not in rendered


def test_vault_credential_ref_value_never_in_health_or_errors() -> None:
    client = _FakeVaultTransitClient()
    provider = HashiCorpVaultTransitKeyProvider(
        transit_mount="transit",
        transit_key="netops-kek",
        client=client,
        credential_ref="super-secret-approle-id",
    )
    client.down = True
    health = provider.health()
    assert health.detail is not None
    assert "super-secret-approle-id" not in (health.detail or "")
    with pytest.raises(KeyProviderUnavailable) as excinfo:
        provider.wrap_dek(os.urandom(KEY_BYTES), aad=_AAD)
    assert "super-secret-approle-id" not in (str(excinfo.value) + repr(excinfo.value))
