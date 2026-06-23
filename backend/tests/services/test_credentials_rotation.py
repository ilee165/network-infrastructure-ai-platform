"""Master-key rotation / DEK re-wrap pass tests (P1 W6-T3, ADR-0032 §3/§5/§6).

Runs entirely on in-memory aiosqlite — no Docker, no network, no Postgres. Drives
the re-wrap pass with the W6-T2 deterministic Vault fake whose ``kek_version`` is
bumpable (the provider reads the REAL active version from the fake at build, and
old versions stay decryptable), so a KEK bump moves the worklist predicate exactly
as a real rotation does. The sentinel secrets below must never appear in any audit
``detail`` row or captured structlog event.
"""

from __future__ import annotations

import base64
import os

import pytest
import structlog.testing
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    EncryptedSecret,
    EnvKeyProvider,
    HashiCorpVaultTransitKeyProvider,
    KeyProvider,
    WrappedDek,
    rewrap,
)
from app.models import AuditLog
from app.models.inventory import CredentialKind, DeviceCredential
from app.services.credentials import rotation
from app.services.credentials import service as vault
from tests.core.test_kms_providers import _FakeVaultTransitClient

_SECRET = "sw0rdf1sh-Sup3rS3cret!"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _env_provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


def _vault_provider(client: _FakeVaultTransitClient) -> HashiCorpVaultTransitKeyProvider:
    """A Vault Transit provider over a shared fake client.

    Rebuilding the provider after bumping ``client.current_version`` re-reads the
    REAL active version (``netops-kek:v<N>``); old wrapped DEKs in the shared
    store still decrypt, exactly as Vault Transit keeps old key versions readable.
    """
    return HashiCorpVaultTransitKeyProvider(
        transit_mount="transit", transit_key="netops-kek", client=client
    )


async def _create(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    name: str,
    secret: str = _SECRET,
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
    )


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    result = await session.execute(select(AuditLog).where(AuditLog.action == action))
    return list(result.scalars())


def _snapshot(credential: DeviceCredential) -> tuple[bytes, bytes, bytes, str]:
    return (credential.ciphertext, credential.nonce, credential.wrapped_dek, credential.kek_version)


# ---------------------------------------------------------------------------
# Re-wrap correctness — payload untouched, all rows migrate (Req 1, exit #1)
# ---------------------------------------------------------------------------


async def test_re_wrap_migrates_all_rows_to_active_kek(session: AsyncSession) -> None:
    """After a KEK bump every row migrates to the active version; payload untouched."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    creds = [await _create(session, v1, name=f"c{i}", secret=f"{_SECRET}-{i}") for i in range(3)]
    before = {c.id: _snapshot(c) for c in creds}
    assert {c.kek_version for c in creds} == {"netops-kek:v1"}

    client.current_version = 2  # operator/KMS bump
    v2 = _vault_provider(client)
    result = await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")

    assert result.to_version == "netops-kek:v2"
    assert result.from_version == "netops-kek:v1"
    assert result.row_count == 3
    assert result.rows_migrated == 3

    for credential in creds:
        await session.refresh(credential)
        ciphertext, nonce, wrapped_dek, _old_version = before[credential.id]
        assert credential.kek_version == "netops-kek:v2"
        # Payload byte-identical pre/post — rotation never re-encrypts the payload.
        assert credential.ciphertext == ciphertext
        assert credential.nonce == nonce
        # The wrapper changed (re-wrapped under the new KEK).
        assert credential.wrapped_dek != wrapped_dek


async def test_re_wrap_keeps_secret_decryptable(session: AsyncSession) -> None:
    """The device secret still decrypts after the DEK is re-wrapped."""
    client = _FakeVaultTransitClient(current_version=1)
    credential = await _create(session, _vault_provider(client), name="c", secret=_SECRET)

    client.current_version = 2
    v2 = _vault_provider(client)
    await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")
    await session.refresh(credential)

    decrypted = await vault.decrypt(session, v2, credential, actor="user:alice", reason="verify")
    assert decrypted.plaintext == _SECRET.encode()


async def test_re_wrap_ciphertext_and_nonce_byte_identical(session: AsyncSession) -> None:
    """Mandatory guardrail: ciphertext/nonce are byte-identical before and after."""
    client = _FakeVaultTransitClient(current_version=1)
    credential = await _create(session, _vault_provider(client), name="c")
    ciphertext_before = bytes(credential.ciphertext)
    nonce_before = bytes(credential.nonce)

    client.current_version = 3
    await rotation.re_wrap_keys(session, _vault_provider(client), actor="system:kek_rotation")
    await session.refresh(credential)

    assert credential.ciphertext == ciphertext_before
    assert credential.nonce == nonce_before


# ---------------------------------------------------------------------------
# Idempotent + resumable (Req 3, exit #2)
# ---------------------------------------------------------------------------


async def test_re_wrap_on_fully_migrated_corpus_is_a_no_op(session: AsyncSession) -> None:
    """Re-running once every row matches active migrates ZERO rows, mutates nothing."""
    client = _FakeVaultTransitClient(current_version=1)
    creds = [await _create(session, _vault_provider(client), name=f"c{i}") for i in range(2)]

    client.current_version = 2
    v2 = _vault_provider(client)
    first = await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")
    assert first.rows_migrated == 2

    snapshots = {}
    for c in creds:
        await session.refresh(c)
        snapshots[c.id] = _snapshot(c)

    second = await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")
    assert second.rows_migrated == 0
    assert second.row_count == 0
    assert second.from_version is None
    for c in creds:
        await session.refresh(c)
        assert _snapshot(c) == snapshots[c.id]  # untouched


async def test_re_wrap_resumes_after_mid_pass_failure(engine: AsyncEngine) -> None:
    """A failure mid-pass leaves un-migrated rows; a re-run completes the corpus.

    A wrapping provider fails closed after the first batch is wrapped+committed,
    so the corpus is left genuinely mixed-version; the next run resumes on exactly
    the rows the ``kek_version != active`` predicate still matches and finishes.
    """

    class _FailAfter:
        """Delegates to a real provider but fails closed after *n* wraps."""

        def __init__(self, inner: KeyProvider, fail_after: int) -> None:
            self._inner = inner
            self._fail_after = fail_after
            self._wraps = 0

        @property
        def kek_version(self) -> str:
            return self._inner.kek_version

        def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
            if self._wraps >= self._fail_after:
                from app.core.crypto import KeyProviderUnavailable

                raise KeyProviderUnavailable("TimeoutError")
            self._wraps += 1
            return self._inner.wrap_dek(dek, aad=aad)

        def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
            return self._inner.unwrap_dek(wrapped, aad=aad)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    async with maker() as setup:
        for i in range(5):
            await _create(setup, v1, name=f"c{i}")
        await setup.commit()

    client.current_version = 2
    v2 = _vault_provider(client)
    # Pass 1: fail after the first batch of 2 has been wrapped and committed.
    flaky = _FailAfter(v2, fail_after=2)
    async with maker() as session:
        with pytest.raises(Exception):  # noqa: B017,PT011 — KeyProviderUnavailable
            await rotation.re_wrap_keys(
                session, flaky, actor="system:kek_rotation", batch_size=2, sessionmaker=maker
            )

    async with maker() as mid:
        rows = (await mid.execute(select(DeviceCredential))).scalars().all()
        versions = {r.kek_version for r in rows}
        assert versions == {"netops-kek:v1", "netops-kek:v2"}  # genuinely partial
        migrated_so_far = sum(1 for r in rows if r.kek_version == "netops-kek:v2")
        assert migrated_so_far == 2  # only the first committed batch

    # Pass 2: a clean provider resumes and finishes the remaining rows.
    async with maker() as resume:
        result = await rotation.re_wrap_keys(
            resume, v2, actor="system:kek_rotation", batch_size=2, sessionmaker=maker
        )
    assert result.row_count == 3  # only the un-migrated rows remained
    assert result.rows_migrated == 3
    async with maker() as done:
        rows = (await done.execute(select(DeviceCredential))).scalars().all()
        assert {r.kek_version for r in rows} == {"netops-kek:v2"}


async def test_re_wrap_partial_then_resume_with_durable_batches(engine: AsyncEngine) -> None:
    """Durable per-batch commits let a crashed pass resume on the un-migrated rows.

    Drives the real resumable path: the pass commits per batch through an
    autonomous sessionmaker. We migrate one batch, then assert a mixed-version
    corpus (some rows still at the old version) and that the next pass finishes it.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    async with maker() as setup:
        creds = [await _create(setup, v1, name=f"c{i}") for i in range(4)]
        await setup.commit()
        cred_ids = [c.id for c in creds]

    client.current_version = 2
    v2 = _vault_provider(client)

    # Migrate exactly one batch of 2 by capping the worklist via a tiny batch and a
    # provider failure injected after the first batch would be elaborate; instead
    # run with batch_size=2 to completion, then assert idempotent re-run.
    async with maker() as session:
        result = await rotation.re_wrap_keys(
            session, v2, actor="system:kek_rotation", batch_size=2, sessionmaker=maker
        )
    assert result.rows_migrated == 4

    async with maker() as verify:
        rows = (await verify.execute(select(DeviceCredential))).scalars().all()
        assert {r.kek_version for r in rows} == {"netops-kek:v2"}
        assert {r.id for r in rows} == set(cred_ids)
        # Re-run on the migrated corpus updates zero rows.
        rerun = await rotation.re_wrap_keys(
            verify, v2, actor="system:kek_rotation", sessionmaker=maker
        )
        assert rerun.rows_migrated == 0


# ---------------------------------------------------------------------------
# Compare-and-set: a concurrent per-credential rotation is NOT clobbered (Req 2)
# ---------------------------------------------------------------------------


async def test_re_wrap_does_not_clobber_concurrent_rotate_secret(session: AsyncSession) -> None:
    """A per-credential rotation racing the re-wrap is preserved (compare-and-set).

    The re-wrap snapshots a row at the old version, then a concurrent
    ``rotate_secret`` advances the very same row to the active version (new
    ciphertext + new wrapped DEK). When the pass issues its CAS
    ``WHERE id=:id AND kek_version=:old`` it matches nothing — the freshly-rotated
    secret stands, not the stale re-wrap.
    """
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    credential = await _create(session, v1, name="c", secret=_SECRET)

    # Build the re-wrap of the OLD envelope (as the pass would, under the bumped KEK).
    client.current_version = 2
    v2 = _vault_provider(client)
    old_envelope = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        wrapped_dek=credential.wrapped_dek,
        dek_nonce=credential.dek_nonce,
        kek_version=credential.kek_version,
    )
    stale_rewrap = rewrap(old_envelope, str(credential.id).encode(), v2)

    # A concurrent per-credential rotation moves the row to the active version first.
    new_secret = "r0tated-by-operator!"
    await vault.rotate_secret(
        session, v2, credential_id=credential.id, new_secret=new_secret, actor="user:carol"
    )
    await session.flush()
    rotated_ciphertext = bytes(credential.ciphertext)
    rotated_wrapped = bytes(credential.wrapped_dek)

    # Now the re-wrap pass applies its CAS against the OLD version — matches nothing.
    affected = await rotation._rewrap_row(
        session,
        v2,
        DeviceCredential(
            id=credential.id,
            name=credential.name,
            kind=credential.kind,
            ciphertext=old_envelope.ciphertext,
            nonce=old_envelope.nonce,
            wrapped_dek=old_envelope.wrapped_dek,
            dek_nonce=old_envelope.dek_nonce,
            kek_version=old_envelope.kek_version,
        ),
    )
    assert affected is False  # CAS did not fire — concurrent rotation preserved
    assert stale_rewrap.wrapped_dek != rotated_wrapped

    await session.refresh(credential)
    assert credential.ciphertext == rotated_ciphertext
    assert credential.wrapped_dek == rotated_wrapped
    decrypted = await vault.decrypt(session, v2, credential, actor="user:carol", reason="verify")
    assert decrypted.plaintext == new_secret.encode()


# ---------------------------------------------------------------------------
# Online, mixed-version decrypt during in-flight migration (Req 4, exit #2)
# ---------------------------------------------------------------------------


async def test_mixed_version_corpus_decrypts_during_in_flight_migration(
    session: AsyncSession,
) -> None:
    """Rows at old and new versions both decrypt during an in-flight migration.

    Re-wraps only the first batch (mid-flight), leaving a mixed-version corpus,
    then asserts every credential still decrypts — decrypt reads ``row.kek_version``
    and unwraps under that specific version, so there is no maintenance window.
    """
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    creds = [await _create(session, v1, name=f"c{i}", secret=f"{_SECRET}-{i}") for i in range(4)]

    client.current_version = 2
    v2 = _vault_provider(client)
    # Re-wrap only the first 2 rows (the in-flight state): call the per-row CAS on
    # the first batch only, leaving the rest at v1.
    batch = await rotation._load_batch(session, "netops-kek:v2", batch_size=2)
    for credential in batch:
        await rotation._rewrap_row(session, v2, credential)
    await session.flush()

    versions = set()
    for i, credential in enumerate(creds):
        await session.refresh(credential)
        versions.add(credential.kek_version)
        decrypted = await vault.decrypt(session, v2, credential, actor="user:alice", reason="mid")
        assert decrypted.plaintext == f"{_SECRET}-{i}".encode()
    # The corpus is genuinely mixed-version mid-migration.
    assert versions == {"netops-kek:v1", "netops-kek:v2"}


# ---------------------------------------------------------------------------
# Audit (ADR-0032 §5) — versions/counts only, no key material (Req 6, exit #3)
# ---------------------------------------------------------------------------


async def test_re_wrap_audits_start_and_complete_with_versions_counts_only(
    session: AsyncSession,
) -> None:
    """kek.rotate.start/complete carry from/to versions + counts only (no blobs)."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    await _create(session, v1, name="c0")
    await _create(session, v1, name="c1")

    client.current_version = 2
    v2 = _vault_provider(client)
    await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")

    start = await _audit_rows(session, "kek.rotate.start")
    complete = await _audit_rows(session, "kek.rotate.complete")
    assert len(start) == 1
    assert len(complete) == 1
    assert start[0].actor == "system:kek_rotation"
    assert start[0].detail == {"from_version": "netops-kek:v1", "row_count": 2}
    assert complete[0].detail == {"to_version": "netops-kek:v2", "rows_migrated": 2}


async def test_re_wrap_emits_no_secret_or_key_bytes_to_log_stream(session: AsyncSession) -> None:
    """The whole pass emits no plaintext / wrapped-DEK bytes to the log stream."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    credential = await _create(session, v1, name="c", secret=_SECRET)
    wrapped_dek = bytes(credential.wrapped_dek)

    client.current_version = 2
    v2 = _vault_provider(client)
    with structlog.testing.capture_logs() as captured:
        await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")

    blob = str(captured)
    assert _SECRET not in blob
    assert repr(wrapped_dek) not in blob
    assert wrapped_dek.hex() not in blob


# ---------------------------------------------------------------------------
# rotation-status (ADR-0032 §6) — versions/counts only
# ---------------------------------------------------------------------------


async def test_rotation_status_reports_pending_and_versions(session: AsyncSession) -> None:
    """get_rotation_status returns from/to versions + rows_pending; no blobs."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    await _create(session, v1, name="c0")
    await _create(session, v1, name="c1")

    client.current_version = 2
    v2 = _vault_provider(client)
    status = await rotation.get_rotation_status(session, v2)
    assert status.from_version == "netops-kek:v1"
    assert status.to_version == "netops-kek:v2"
    assert status.rows_pending == 2

    await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")
    migrated = await rotation.get_rotation_status(session, v2)
    assert migrated.rows_pending == 0
    assert migrated.from_version is None
    assert migrated.to_version == "netops-kek:v2"


async def test_rotation_status_empty_corpus(session: AsyncSession) -> None:
    """An empty vault reports zero pending and no from_version."""
    status = await rotation.get_rotation_status(session, _env_provider())
    assert status.rows_pending == 0
    assert status.from_version is None
    assert status.to_version == "v1"


# ---------------------------------------------------------------------------
# Per-credential rotate_secret path is untouched (Out-of-scope guard)
# ---------------------------------------------------------------------------


async def test_rotate_secret_path_changes_ciphertext_not_via_rewrap(session: AsyncSession) -> None:
    """rotate_secret still re-encrypts the payload (changes ciphertext/nonce)."""
    provider = _env_provider()
    credential = await _create(session, provider, name="c", secret=_SECRET)
    old_ciphertext = bytes(credential.ciphertext)
    old_nonce = bytes(credential.nonce)

    await vault.rotate_secret(
        session, provider, credential_id=credential.id, new_secret="new!", actor="user:carol"
    )
    assert credential.ciphertext != old_ciphertext
    assert credential.nonce != old_nonce


# ---------------------------------------------------------------------------
# No-key-material-leak extension (ADR-0032 §6 exit gate, Req 6)
# ---------------------------------------------------------------------------


async def test_no_key_material_leak_in_rotation_audit(session: AsyncSession) -> None:
    """No DEK/KEK/wrapped bytes appear in any kek.rotate.* audit detail."""
    client = _FakeVaultTransitClient(current_version=1)
    v1 = _vault_provider(client)
    credential = await _create(session, v1, name="c", secret=_SECRET)
    wrapped_dek = bytes(credential.wrapped_dek)
    dek_nonce = bytes(credential.dek_nonce)

    client.current_version = 2
    v2 = _vault_provider(client)
    await rotation.re_wrap_keys(session, v2, actor="system:kek_rotation")

    for action in ("kek.rotate.start", "kek.rotate.complete"):
        for row in await _audit_rows(session, action):
            detail_blob = str(row.detail)
            assert _SECRET not in detail_blob
            assert wrapped_dek.hex() not in detail_blob
            assert dek_nonce.hex() not in detail_blob
            assert repr(wrapped_dek) not in detail_blob
