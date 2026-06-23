"""Integration tests against the KMS emulators (P1 W6-T2, ADR-0032 §2 / §148).

These exercise the REAL provider builders + adapters end-to-end against the
backend-shaped emulators in ``deploy/docker/docker-compose.kms-emulators.yml``
(LocalStack KMS, dev Vault Transit). This is the integration gate that proves the
adapters speak the real boto3 / hvac wire shape — the offline unit suite uses
in-memory doubles and the contract tests pin the call shape, but only THIS run
drives a live, backend-shaped service.

Skip policy (so the offline backend CI job is unaffected):
  * the cloud SDK extras (boto3 / hvac) are NOT installed offline -> ``importorskip``
    skips the whole module there;
  * even with the SDKs present, the module is skipped unless ``KMS_EMULATOR_TEST=1``
    so a dev box with boto3 installed but no emulators running does not fail.

Azure has no first-party local wrap/unwrap emulator (documented exception, see the
G-SEC evidence doc + the compose file): its real call shape is covered by the
contract test (``test_kms_contract.py``) and a real Key Vault is lab-deferred.

The CI ``kms-emulators`` job sets ``KMS_EMULATOR_TEST=1`` and the endpoint env
vars after ``docker compose up`` + key creation.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("KMS_EMULATOR_TEST") != "1",
    reason="KMS emulators not running (set KMS_EMULATOR_TEST=1 in the CI emulator job)",
)

# SDK extras are optional and absent offline; skip the module if missing.
boto3 = pytest.importorskip("boto3")
hvac = pytest.importorskip("hvac")

from app.core.crypto import (  # noqa: E402 - after importorskip
    KEY_BYTES,
    AwsKmsKeyProvider,
    HashiCorpVaultTransitKeyProvider,
)

_AAD = b"device_credentials:integration"
_OTHER_AAD = b"device_credentials:other"


def test_aws_kms_localstack_roundtrip_and_replay_guard() -> None:
    """Real boto3 kms client against LocalStack: round-trip + EncryptionContext guard."""
    endpoint = os.environ["LOCALSTACK_KMS_ENDPOINT"]
    key_arn = os.environ["KMS_KEY_ARN"]
    client = boto3.client("kms", endpoint_url=endpoint)
    provider = AwsKmsKeyProvider(key_arn=key_arn, client=client)

    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek

    # Cross-row replay guard: a different row-id (EncryptionContext) must fail.
    from app.core.crypto import DecryptionError

    with pytest.raises(DecryptionError):
        provider.unwrap_dek(wrapped, aad=_OTHER_AAD)

    assert provider.kek_version == key_arn


def test_vault_transit_dev_roundtrip_replay_guard_and_version() -> None:
    """Real hvac client against dev Vault Transit via the adapter: full contract."""
    addr = os.environ["VAULT_ADDR"]
    token = os.environ["VAULT_TOKEN"]
    transit_key = os.environ.get("VAULT_TRANSIT_KEY", "netops-kek")

    client = hvac.Client(url=addr, token=token)
    assert client.is_authenticated()

    from app.core.crypto import DecryptionError, _VaultTransitClient

    adapter = _VaultTransitClient(client, mount="transit")
    provider = HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key=transit_key, client=adapter
    )

    dek = os.urandom(KEY_BYTES)
    wrapped = provider.wrap_dek(dek, aad=_AAD)
    assert provider.unwrap_dek(wrapped, aad=_AAD) == dek

    # Native Transit context binds the row-id: a different aad must fail.
    with pytest.raises(DecryptionError):
        provider.unwrap_dek(wrapped, aad=_OTHER_AAD)

    # kek_version reflects the REAL latest_version read off the live key.
    assert provider.kek_version.startswith(f"{transit_key}:v")
    assert provider.health().available is True
