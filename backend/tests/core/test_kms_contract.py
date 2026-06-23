"""Real-SDK call-shape CONTRACT tests for the KMS adapters (P1 W6-T2, ADR-0032 §2).

The offline unit suite (``test_kms_providers.py``) drives the providers via
in-memory doubles of the *adapter* contract. Those doubles cannot, on their own,
prove that the adapters speak the REAL boto3 / hvac / azure call shape — that is
exactly the gap the escalated review flagged (a broken prod path hidden behind a
``# pragma: no cover``). These tests close it: each adapter is exercised against a
mock that records the call, and we assert the EXACT real SDK shape:

* Vault Transit — ``client.secrets.transit.encrypt_data(name=, plaintext=<b64>,
  context=<b64>, mount_point=)`` / ``decrypt_data(...)`` (base64 in, base64
  plaintext out) / ``read_key(name=, mount_point=)["data"]["latest_version"]``;
  auth via ``client.auth.kubernetes.login(role=, jwt=)`` / AppRole.
* Azure Key Vault — ``CryptographyClient.wrap_key(KeyWrapAlgorithm.rsa_oaep_256,
  key).encrypted_key`` / ``unwrap_key(algorithm, encrypted_key).key``.
* AWS KMS — the provider's ``encrypt(KeyId=, Plaintext=, EncryptionContext=)`` /
  ``decrypt(CiphertextBlob=, EncryptionContext=)`` boto3 shape.

No real cloud, no installed SDK: the mocks reproduce the SDK's call surface so
the adapter code runs end-to-end. The CI emulator job (docker-compose.kms-
emulators.yml) is the live integration gate; real-cloud KMS is lab-deferred.
"""

from __future__ import annotations

import base64
import os
from types import SimpleNamespace
from typing import Any

from app.core.crypto import (
    KEY_BYTES,
    AwsKmsKeyProvider,
    _AzureKeyClient,
    _vault_login,
    _VaultTransitClient,
)

_AAD = b"device_credentials:7"


# ---------------------------------------------------------------------------
# Vault Transit adapter — real hvac.secrets.transit.* shape
# ---------------------------------------------------------------------------


class _RecordingTransit:
    """Records the real ``secrets.transit.*`` calls and round-trips like Vault."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._store: dict[str, tuple[str, str | None]] = {}
        self.latest_version = 4

    def encrypt_data(
        self, *, name: str, plaintext: str, context: str, mount_point: str
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "encrypt",
                {"name": name, "plaintext": plaintext, "context": context, "mount": mount_point},
            )
        )
        ref = f"vault:v{self.latest_version}:{os.urandom(6).hex()}"
        self._store[ref] = (plaintext, context)
        return {"data": {"ciphertext": ref}}

    def decrypt_data(
        self, *, name: str, ciphertext: str, context: str, mount_point: str
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "decrypt",
                {"name": name, "ciphertext": ciphertext, "context": context, "mount": mount_point},
            )
        )
        stored_plaintext, stored_context = self._store[ciphertext]
        assert stored_context == context  # Transit binds context natively
        return {"data": {"plaintext": stored_plaintext}}

    def read_key(self, *, name: str, mount_point: str) -> dict[str, Any]:
        self.calls.append(("read_key", {"name": name, "mount": mount_point}))
        return {"data": {"latest_version": self.latest_version}}


def _hvac_like(transit: _RecordingTransit) -> Any:
    return SimpleNamespace(secrets=SimpleNamespace(transit=transit))


def test_vault_adapter_base64_encodes_plaintext_context_and_passes_mount() -> None:
    transit = _RecordingTransit()
    adapter = _VaultTransitClient(_hvac_like(transit), mount="kms-transit")

    dek = os.urandom(KEY_BYTES)
    resp = adapter.encrypt_data(name="netops-kek", plaintext=dek, context=_AAD)
    ciphertext = resp["data"]["ciphertext"]

    name, kwargs = transit.calls[0]
    assert name == "encrypt"
    # plaintext + context are base64 on the wire (real Transit requirement).
    assert kwargs["plaintext"] == base64.b64encode(dek).decode("ascii")
    assert kwargs["context"] == base64.b64encode(_AAD).decode("ascii")
    assert kwargs["mount"] == "kms-transit"  # the bound mount is passed

    # decrypt: ciphertext passes through, context re-encoded, plaintext base64-decoded.
    out = adapter.decrypt_data(name="netops-kek", ciphertext=ciphertext, context=_AAD)
    name, kwargs = transit.calls[-1]
    assert name == "decrypt"
    assert kwargs["context"] == base64.b64encode(_AAD).decode("ascii")
    assert kwargs["mount"] == "kms-transit"
    assert out["data"]["plaintext"] == dek  # raw bytes back to the provider


def test_vault_adapter_read_key_version_reads_latest_version() -> None:
    transit = _RecordingTransit()
    adapter = _VaultTransitClient(_hvac_like(transit), mount="transit")
    assert adapter.read_key_version(name="netops-kek") == 4
    name, kwargs = transit.calls[-1]
    assert name == "read_key"
    assert kwargs == {"name": "netops-kek", "mount": "transit"}


def test_vault_login_uses_kubernetes_auth_with_role_and_jwt(monkeypatch) -> None:
    """k8s-auth login is ``auth.kubernetes.login(role=<credential_ref>, jwt=<SA token>)``.

    The SA JWT comes from the projected token file; ``credential_ref`` is the
    INDIRECT role handle (never a token). After login the lease is renewed.
    """
    import app.core.crypto as crypto_mod

    monkeypatch.setattr(crypto_mod, "_read_sa_jwt", lambda: "sa-jwt-xyz")

    calls: list[tuple[str, dict[str, Any]]] = []
    k8s = SimpleNamespace(login=lambda **kw: calls.append(("k8s", kw)))
    token = SimpleNamespace(renew_self=lambda: calls.append(("renew", {})))
    client = SimpleNamespace(auth=SimpleNamespace(kubernetes=k8s, token=token))

    _vault_login(client, "netops-kek-role")

    assert ("k8s", {"role": "netops-kek-role", "jwt": "sa-jwt-xyz"}) in calls
    assert ("renew", {}) in calls  # auto-renew the short-lived token


def test_vault_login_falls_back_to_approle_when_no_sa_token(monkeypatch) -> None:
    """No SA token file -> AppRole login with the ref as role_id (no token inlined)."""
    import app.core.crypto as crypto_mod

    monkeypatch.setattr(crypto_mod, "_read_sa_jwt", lambda: None)
    monkeypatch.setenv("VAULT_SECRET_ID", "sid-from-agent")

    calls: list[tuple[str, dict[str, Any]]] = []
    approle = SimpleNamespace(login=lambda **kw: calls.append(("approle", kw)))
    token = SimpleNamespace(renew_self=lambda: None)
    client = SimpleNamespace(auth=SimpleNamespace(approle=approle, token=token))

    _vault_login(client, "netops-kek-role")
    assert ("approle", {"role_id": "netops-kek-role", "secret_id": "sid-from-agent"}) in calls


def test_vault_login_noop_without_credential_ref() -> None:
    """No credential_ref -> no auth call (the legacy/ambient-token path)."""
    sentinel = object()
    # A bare object() has no .auth; if _vault_login tried to authenticate it would
    # raise AttributeError. It must simply return.
    _vault_login(sentinel, None)


# ---------------------------------------------------------------------------
# Azure Key Vault adapter — real CryptographyClient wrap/unwrap result shape
# ---------------------------------------------------------------------------


class _RecordingCrypto:
    """Reproduces CryptographyClient.wrap_key/unwrap_key result-object shape."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, bytes]] = []
        self._store: dict[bytes, bytes] = {}

    def wrap_key(self, algorithm: Any, key: bytes) -> Any:
        self.calls.append(("wrap", algorithm, key))
        token = os.urandom(16)
        self._store[token] = key
        # Real WrapResult exposes .encrypted_key (NOT bytes(result)).
        return SimpleNamespace(encrypted_key=token, algorithm=algorithm)

    def unwrap_key(self, algorithm: Any, encrypted_key: bytes) -> Any:
        self.calls.append(("unwrap", algorithm, encrypted_key))
        # Real UnwrapResult exposes .key.
        return SimpleNamespace(key=self._store[encrypted_key], algorithm=algorithm)


def test_azure_adapter_uses_rsa_oaep_256_and_result_attributes() -> None:
    crypto = _RecordingCrypto()
    algorithm = "RSA-OAEP-256"  # stands in for KeyWrapAlgorithm.rsa_oaep_256
    adapter = _AzureKeyClient(crypto, algorithm, key_version="v-real")

    inner = os.urandom(KEY_BYTES)
    wrapped = adapter.wrap_key(inner)
    assert isinstance(wrapped, bytes)  # .encrypted_key, not bytes(WrapResult)

    op, alg, key_arg = crypto.calls[0]
    assert op == "wrap"
    assert alg == algorithm  # pinned algorithm, passed positionally
    assert key_arg == inner

    out = adapter.unwrap_key(wrapped)
    op, alg, _ = crypto.calls[-1]
    assert op == "unwrap"
    assert alg == algorithm
    assert out == inner  # .key round-trips
    assert adapter.key_version() == "v-real"


# ---------------------------------------------------------------------------
# AWS KMS — the provider's boto3 encrypt/decrypt call shape
# ---------------------------------------------------------------------------


class _RecordingKms:
    """Records the boto3 ``kms`` encrypt/decrypt call shape and round-trips."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._store: dict[bytes, tuple[bytes, frozenset[tuple[str, str]]]] = {}

    def encrypt(
        self, *, KeyId: str, Plaintext: bytes, EncryptionContext: dict[str, str]
    ) -> dict[str, Any]:
        self.calls.append(("encrypt", {"KeyId": KeyId, "EncryptionContext": EncryptionContext}))
        blob = os.urandom(16)
        self._store[blob] = (Plaintext, frozenset(EncryptionContext.items()))
        return {"CiphertextBlob": blob, "KeyId": KeyId}

    def decrypt(
        self, *, CiphertextBlob: bytes, EncryptionContext: dict[str, str]
    ) -> dict[str, Any]:
        self.calls.append(("decrypt", {"EncryptionContext": EncryptionContext}))
        plaintext, ctx = self._store[CiphertextBlob]
        assert ctx == frozenset(EncryptionContext.items())
        return {"Plaintext": plaintext}


def test_aws_provider_uses_encrypt_decrypt_with_encryption_context() -> None:
    kms = _RecordingKms()
    arn = "arn:aws:kms:us-east-1:000000000000:key/contract"
    provider = AwsKmsKeyProvider(key_arn=arn, client=kms)

    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek

    op, kwargs = kms.calls[0]
    assert op == "encrypt"
    assert kwargs["KeyId"] == arn
    # Row-id bound natively via EncryptionContext (the cross-row replay guard).
    assert kwargs["EncryptionContext"] == {"row_id": _AAD.decode("utf-8")}
