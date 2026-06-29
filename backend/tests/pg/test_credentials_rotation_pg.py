"""Credential rotation + scope (ADR-0040 / ADR-0032) re-asserted under REAL PostgreSQL (W5-T0).

The SQLite unit suite (``tests/services/test_credentials_rotation.py``) is the
fast smoke; THIS module re-asserts the W4-T2 credential-vault controls against a
real Postgres so the W5-T3 gate flip rests on PG-accurate tests. These exercise
the credential-rotation **secret-surface** (the vault) under PG:

  * confirm-then-swap KEK re-wrap (``re_wrap_keys``): payload byte-identical, the
    wrapper changes, every row migrates to the active version, and the secret still
    decrypts — over real ``bytea`` envelope columns + JSONB ``audit_log.detail``;
  * per-credential scope deny (``decrypt`` against an out-of-scope device): a
    scoped credential is refused BEFORE any KEK access and the deny is durably
    audited — the ADR-0040 §2 least-privilege boundary;
  * **no plaintext leak** (Requirement 4): no secret, wrapped-DEK bytes, or DEK
    nonce appears in any ``kek.rotate.*`` / ``credential.scope_denied`` audit row
    persisted on PG (asserted on the real JSONB ``detail`` round-trip).

Secret handling (W5-T0 Requirement 4): the only "secret" here is a test sentinel
created INSIDE the test and confined to a :class:`DecryptedSecret`; it is asserted
to be ABSENT from every persisted audit row, never logged, never placed in a
fixture file. The throwaway KEK is generated per test with ``os.urandom``.
"""

from __future__ import annotations

import pytest
import structlog.testing
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import HashiCorpVaultTransitKeyProvider
from app.core.errors import CredentialScopeError
from app.models import AuditLog
from app.models.inventory import CredentialKind, Device, DeviceCredential, DeviceStatus
from app.services.credentials import rotation
from app.services.credentials import service as vault
from tests.core.test_kms_providers import _FakeVaultTransitClient

pytestmark = pytest.mark.integration

#: A test sentinel — created here, asserted ABSENT from every persisted audit row,
#: never logged. NOT a real credential.
_SECRET = "sw0rdf1sh-Sup3rS3cret!"


def _vault_provider(client: _FakeVaultTransitClient) -> HashiCorpVaultTransitKeyProvider:
    """A Vault Transit provider over a shared fake client (mirrors the SQLite suite).

    Rebuilding the provider after bumping ``client.current_version`` re-reads the
    REAL active version (``netops-kek:v<N>``) while old wrapped DEKs in the shared
    store still decrypt — exactly as Vault Transit keeps old key versions readable
    (ADR-0032 §2). This is the deterministic, no-plaintext-leak provider the W6-T3
    rotation suite uses; ``EnvKeyProvider`` cannot model a version bump (a v2
    provider refuses a v1-wrapped DEK), which is why the fake is used here too.
    """
    return HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key="netops-kek", client=client
    )


async def _create(
    session: AsyncSession,
    provider: HashiCorpVaultTransitKeyProvider,
    *,
    name: str,
    secret: str = _SECRET,
    scope_site: str | None = None,
) -> DeviceCredential:
    return await vault.create_credential(
        session,
        provider,
        name=name,
        kind=CredentialKind.SSH,
        username="netops",
        secret=secret,
        params={"port": 22},
        actor="user:alice",
        scope_site=scope_site,
    )


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    result = await session.execute(select(AuditLog).where(AuditLog.action == action))
    return list(result.scalars())


# ---------------------------------------------------------------------------
# Confirm-then-swap KEK re-wrap under PG (ADR-0032 §3) — payload untouched.
# ---------------------------------------------------------------------------


async def test_re_wrap_migrates_all_rows_payload_byte_identical_under_pg(
    pg_session: AsyncSession,
) -> None:
    """KEK bump migrates every row; ciphertext/nonce byte-identical on PG bytea.

    Re-wrap is a confirm-then-swap of the WRAPPER only — never a payload
    re-encrypt. On PG the envelope columns are real ``bytea``; this proves the
    round-trip keeps ciphertext/nonce byte-identical pre/post while the wrapped DEK
    changes and the active version advances over the real database.
    """
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    creds = [await _create(pg_session, v1, name=f"c{i}", secret=f"{_SECRET}-{i}") for i in range(3)]
    before = {c.id: (bytes(c.ciphertext), bytes(c.nonce), bytes(c.wrapped_dek)) for c in creds}
    await pg_session.flush()

    client.current_version = 2  # operator/KMS bump
    v2 = _vault_provider(client)
    result = await rotation.re_wrap_keys(pg_session, v2, actor="system:kek_rotation")
    assert result.to_version == "netops-kek:v2"
    assert result.from_version == "netops-kek:v1"
    assert result.rows_migrated == 3

    for credential in creds:
        await pg_session.refresh(credential)
        ciphertext, nonce, wrapped_dek = before[credential.id]
        assert credential.kek_version == "netops-kek:v2"
        assert bytes(credential.ciphertext) == ciphertext  # payload untouched
        assert bytes(credential.nonce) == nonce
        assert bytes(credential.wrapped_dek) != wrapped_dek  # re-wrapped


async def test_re_wrap_keeps_secret_decryptable_under_pg(pg_session: AsyncSession) -> None:
    """The device secret still decrypts after the DEK is re-wrapped, on real PG."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    credential = await _create(pg_session, v1, name="c", secret=_SECRET)
    await pg_session.flush()

    client.current_version = 2
    v2 = _vault_provider(client)
    await rotation.re_wrap_keys(pg_session, v2, actor="system:kek_rotation")
    await pg_session.refresh(credential)

    decrypted = await vault.decrypt(pg_session, v2, credential, actor="user:alice", reason="verify")
    assert decrypted.plaintext == _SECRET.encode()


async def test_rotation_status_reports_pending_and_versions_under_pg(
    pg_session: AsyncSession,
) -> None:
    """get_rotation_status returns from/to versions + rows_pending on real PG."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    await _create(pg_session, v1, name="c0")
    await _create(pg_session, v1, name="c1")
    await pg_session.flush()

    client.current_version = 2
    v2 = _vault_provider(client)
    status = await rotation.get_rotation_status(pg_session, v2)
    assert status.from_version == "netops-kek:v1"
    assert status.to_version == "netops-kek:v2"
    assert status.rows_pending == 2

    await rotation.re_wrap_keys(pg_session, v2, actor="system:kek_rotation")
    migrated = await rotation.get_rotation_status(pg_session, v2)
    assert migrated.rows_pending == 0
    assert migrated.from_version is None


# ---------------------------------------------------------------------------
# Per-credential scope deny under PG (ADR-0040 §2) — refused before KEK access.
# ---------------------------------------------------------------------------


async def test_scope_deny_refuses_out_of_scope_device_under_pg(
    pg_session: AsyncSession,
) -> None:
    """A site-scoped credential is refused for an out-of-scope device, audited (ADR-0040 §2).

    The structural least-privilege check runs BEFORE any KEK unwrap: a credential
    scoped to ``site=hq`` opening a session against a ``site=branch`` device raises
    :class:`CredentialScopeError` and writes a ``credential.scope_denied`` audit row
    carrying IDS ONLY — never the scope values or device attributes. Asserted over
    the real PG row + JSONB ``detail``.
    """
    v1 = _vault_provider(_FakeVaultTransitClient(current_version=1))
    credential = await _create(pg_session, v1, name="hq-cred", secret=_SECRET, scope_site="hq")
    device = Device(
        hostname="branch-sw1",
        mgmt_ip="10.9.9.1",
        status=DeviceStatus.NEW,
        site="branch",
    )
    pg_session.add(device)
    await pg_session.flush()

    with pytest.raises(CredentialScopeError):
        await vault.decrypt(
            pg_session,
            v1,
            credential,
            actor="user:alice",
            reason="open-session",
            target=device,
        )

    denied = await _audit_rows(pg_session, "credential.scope_denied")
    assert len(denied) == 1
    detail = denied[0].detail or {}
    # IDS / coarse reason ONLY — never the scope value ("hq") or device site.
    assert detail.get("device_id") == str(device.id)
    blob = str(detail)
    assert "hq" not in blob
    assert "branch" not in blob


async def test_in_scope_device_decrypts_under_pg(pg_session: AsyncSession) -> None:
    """A site-scoped credential opens against an in-scope device and decrypts on PG."""
    v1 = _vault_provider(_FakeVaultTransitClient(current_version=1))
    credential = await _create(pg_session, v1, name="hq-cred", secret=_SECRET, scope_site="hq")
    device = Device(
        hostname="hq-sw1",
        mgmt_ip="10.1.1.1",
        status=DeviceStatus.NEW,
        site="hq",
    )
    pg_session.add(device)
    await pg_session.flush()

    decrypted = await vault.decrypt(
        pg_session, v1, credential, actor="user:alice", reason="open-session", target=device
    )
    assert decrypted.plaintext == _SECRET.encode()


# ---------------------------------------------------------------------------
# No plaintext / key-material leak under PG (ADR-0032 §5/§6, Requirement 4).
# ---------------------------------------------------------------------------


async def test_rotation_emits_no_secret_or_key_bytes_under_pg(
    pg_session: AsyncSession,
) -> None:
    """No secret / wrapped-DEK / DEK-nonce bytes appear in any persisted PG audit row.

    The whole create + re-wrap pass is run under PG, then EVERY ``kek.rotate.*`` and
    ``credential.*`` audit row's JSONB ``detail`` is scanned for the plaintext
    secret and the wrapped-DEK / DEK-nonce bytes (hex + repr). The log stream
    captured during the pass is scanned too. Nothing secret may surface — this is
    the credential-rotation no-leak gate asserted against the real database.
    """
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    credential = await _create(pg_session, v1, name="c", secret=_SECRET)
    await pg_session.flush()
    wrapped_dek = bytes(credential.wrapped_dek)
    dek_nonce = bytes(credential.dek_nonce)

    client.current_version = 2
    v2 = _vault_provider(client)
    with structlog.testing.capture_logs() as captured:
        await rotation.re_wrap_keys(pg_session, v2, actor="system:kek_rotation")

    log_blob = str(captured)
    assert _SECRET not in log_blob
    assert wrapped_dek.hex() not in log_blob

    # Scan EVERY persisted audit row's JSONB detail.
    all_rows = list((await pg_session.execute(select(AuditLog))).scalars())
    assert all_rows, "the pass must have written audit rows"
    for row in all_rows:
        detail_blob = str(row.detail)
        assert _SECRET not in detail_blob
        assert wrapped_dek.hex() not in detail_blob
        assert dek_nonce.hex() not in detail_blob
        assert repr(wrapped_dek) not in detail_blob


async def test_rotation_audit_carries_versions_and_counts_only_under_pg(
    pg_session: AsyncSession,
) -> None:
    """kek.rotate.start/complete carry from/to versions + counts only on PG JSONB."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    await _create(pg_session, v1, name="c0")
    await _create(pg_session, v1, name="c1")
    await pg_session.flush()

    client.current_version = 2
    v2 = _vault_provider(client)
    await rotation.re_wrap_keys(pg_session, v2, actor="system:kek_rotation")

    start = await _audit_rows(pg_session, "kek.rotate.start")
    complete = await _audit_rows(pg_session, "kek.rotate.complete")
    assert len(start) == 1
    assert len(complete) == 1
    assert start[0].detail == {"from_version": "netops-kek:v1", "row_count": 2}
    assert complete[0].detail == {"to_version": "netops-kek:v2", "rows_migrated": 2}
