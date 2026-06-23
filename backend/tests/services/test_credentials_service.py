"""Credential-vault service tests (ADR-0011): lifecycle, AAD binding, audits, redaction.

Runs entirely on in-memory aiosqlite — no Docker, no network, no Postgres.
The plaintext sentinel strings below must never appear in any audit ``detail``
row or captured structlog event.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
import structlog.testing
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    DecryptionError,
    EnvKeyProvider,
    KeyProvider,
    KeyProviderUnavailable,
    ProviderHealth,
    UnknownKekVersionError,
    WrappedDek,
)
from app.core.errors import NotFoundError
from app.models import AuditLog
from app.models.inventory import CredentialKind, DeviceCredential
from app.services.credentials import service as vault

_SECRET = "sw0rdf1sh-Sup3rS3cret!"
_ROTATED_SECRET = "n3w-r0tated-Passw0rd?"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


class _RotatingProvider:
    """Multi-version wrap/unwrap KeyProvider double (stands in for a KMS provider)."""

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
    """A provider that is unreachable; every wrap/unwrap fails closed (ADR-0032 §4)."""

    def __init__(self, version: str = "v1") -> None:
        self._version = version

    @property
    def kek_version(self) -> str:
        return self._version

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        raise KeyProviderUnavailable("TimeoutError")

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        raise KeyProviderUnavailable("TimeoutError")

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=False, kek_version=self._version, detail="unreachable")


async def _create(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    name: str = "lab-ssh",
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


# ---------------------------------------------------------------------------
# create_credential
# ---------------------------------------------------------------------------


async def test_create_persists_envelope_and_decrypt_roundtrips(session: AsyncSession) -> None:
    """create_credential stores ciphertext only; decrypt returns the plaintext."""
    provider = _provider()
    credential = await _create(session, provider)

    reloaded = (
        await session.execute(
            select(DeviceCredential)
            .where(DeviceCredential.id == credential.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.name == "lab-ssh"
    assert reloaded.kind == CredentialKind.SSH
    assert reloaded.username == "netops"
    assert reloaded.params == {"port": 22}
    assert reloaded.kek_version == "v1"
    assert _SECRET.encode() not in reloaded.ciphertext

    decrypted = await vault.decrypt(
        session, provider, reloaded, actor="system:discovery", reason="ssh session"
    )
    assert decrypted.plaintext == _SECRET.encode()


async def test_create_uses_row_id_as_aad_binding_ciphertext_to_row(session: AsyncSession) -> None:
    """Ciphertext copied onto another row fails decryption: AAD is the row id."""
    provider = _provider()
    cred_a = await _create(session, provider, name="cred-a")
    cred_b = await _create(session, provider, name="cred-b", secret="other-secret")

    cred_b.ciphertext = cred_a.ciphertext
    cred_b.nonce = cred_a.nonce
    cred_b.wrapped_dek = cred_a.wrapped_dek
    cred_b.dek_nonce = cred_a.dek_nonce
    cred_b.kek_version = cred_a.kek_version
    await session.flush()

    with pytest.raises(DecryptionError) as excinfo:
        await vault.decrypt(session, provider, cred_b, actor="user:mallory", reason="copied")
    assert _SECRET not in str(excinfo.value)

    # The legitimate row still decrypts.
    decrypted = await vault.decrypt(session, provider, cred_a, actor="user:alice", reason="check")
    assert decrypted.plaintext == _SECRET.encode()


async def test_create_audits_credential_created_without_secret(session: AsyncSession) -> None:
    """One credential.created audit row; no plaintext in detail or log stream."""
    provider = _provider()
    with structlog.testing.capture_logs() as captured:
        credential = await _create(session, provider)

    rows = await _audit_rows(session, "credential.created")
    assert len(rows) == 1
    entry = rows[0]
    assert entry.actor == "user:alice"
    assert entry.target_type == "credential"
    assert entry.target_id == str(credential.id)
    assert entry.detail is not None
    assert _SECRET not in str(entry.detail)
    assert _SECRET not in str(captured)


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------


async def test_rotate_secret_reencrypts_with_fresh_dek_same_aad(session: AsyncSession) -> None:
    """Rotation swaps ciphertext and DEK; the new secret decrypts under the row AAD."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = credential.ciphertext
    old_wrapped_dek = credential.wrapped_dek

    rotated = await vault.rotate_secret(
        session,
        provider,
        credential_id=credential.id,
        new_secret=_ROTATED_SECRET,
        actor="user:carol",
    )

    assert rotated.id == credential.id
    assert credential.ciphertext != old_ciphertext
    assert credential.wrapped_dek != old_wrapped_dek
    decrypted = await vault.decrypt(
        session, provider, credential, actor="user:carol", reason="post-rotation check"
    )
    assert decrypted.plaintext == _ROTATED_SECRET.encode()

    rows = await _audit_rows(session, "credential.rotated")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)
    assert rows[0].actor == "user:carol"
    assert _ROTATED_SECRET not in str(rows[0].detail)
    assert _SECRET not in str(rows[0].detail)


async def test_rotate_secret_unknown_credential_raises_not_found(session: AsyncSession) -> None:
    """Rotating a nonexistent credential raises NotFoundError without leaking the secret."""
    provider = _provider()
    missing = uuid.uuid4()
    with pytest.raises(NotFoundError) as excinfo:
        await vault.rotate_secret(
            session, provider, credential_id=missing, new_secret=_SECRET, actor="user:carol"
        )
    assert _SECRET not in str(excinfo.value)


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


async def test_decrypt_audits_credential_decrypted_with_reason(session: AsyncSession) -> None:
    """Every decrypt writes a credential.decrypted audit row carrying the reason."""
    provider = _provider()
    credential = await _create(session, provider)

    await vault.decrypt(
        session, provider, credential, actor="system:discovery", reason="discovery run 7"
    )

    rows = await _audit_rows(session, "credential.decrypted")
    assert len(rows) == 1
    entry = rows[0]
    assert entry.actor == "system:discovery"
    assert entry.target_type == "credential"
    assert entry.target_id == str(credential.id)
    assert entry.detail == {"reason": "discovery run 7"}


# ---------------------------------------------------------------------------
# rotate_kek
# ---------------------------------------------------------------------------


async def test_rotate_kek_rewraps_every_credential_and_audits_each(session: AsyncSession) -> None:
    """KEK rotation rewraps all DEKs to the current version; payloads untouched."""
    old_kek, new_kek = os.urandom(KEY_BYTES), os.urandom(KEY_BYTES)
    v1_provider = _RotatingProvider({"v1": old_kek}, current="v1")
    credentials = [
        await _create(session, v1_provider, name=f"cred-{i}", secret=f"{_SECRET}-{i}")
        for i in range(3)
    ]
    snapshots = {c.id: (c.ciphertext, c.nonce, c.wrapped_dek) for c in credentials}

    rotated_provider = _RotatingProvider({"v1": old_kek, "v2": new_kek}, current="v2")
    count = await vault.rotate_kek(session, rotated_provider, actor="user:admin")

    assert count == 3
    for i, credential in enumerate(credentials):
        ciphertext, nonce, wrapped_dek = snapshots[credential.id]
        assert credential.kek_version == "v2"
        assert credential.ciphertext == ciphertext  # payload never re-encrypted
        assert credential.nonce == nonce
        assert credential.wrapped_dek != wrapped_dek
        decrypted = await vault.decrypt(
            session, rotated_provider, credential, actor="user:admin", reason="verify"
        )
        assert decrypted.plaintext == f"{_SECRET}-{i}".encode()

    rows = await _audit_rows(session, "credential.rotated")
    assert len(rows) == 3
    assert {r.target_id for r in rows} == {str(c.id) for c in credentials}


async def test_rotate_kek_with_no_credentials_returns_zero(session: AsyncSession) -> None:
    """An empty vault rotates trivially: zero rewrapped, zero audit rows."""
    count = await vault.rotate_kek(session, _provider(), actor="user:admin")
    assert count == 0
    assert await _audit_rows(session, "credential.rotated") == []


async def test_rotate_kek_skips_credentials_already_on_current_version(
    session: AsyncSession,
) -> None:
    """Credentials already wrapped under the current KEK are not rewrapped or audited."""
    provider = _provider()
    credential = await _create(session, provider)
    wrapped_dek_before = credential.wrapped_dek

    count = await vault.rotate_kek(session, provider, actor="user:admin")

    assert count == 0
    assert credential.wrapped_dek == wrapped_dek_before
    assert await _audit_rows(session, "credential.rotated") == []


# ---------------------------------------------------------------------------
# DecryptedSecret redaction + log hygiene
# ---------------------------------------------------------------------------


def test_decrypted_secret_repr_and_str_redacted() -> None:
    """repr/str/format never render the plaintext bytes."""
    secret = vault.DecryptedSecret(b"hunter2")
    assert repr(secret) == "DecryptedSecret(****)"
    assert str(secret) == "DecryptedSecret(****)"
    assert "hunter2" not in f"{secret}"
    assert "hunter2" not in f"{secret!r}"
    assert secret.plaintext == b"hunter2"


async def test_no_plaintext_in_structlog_capture_across_lifecycle(session: AsyncSession) -> None:
    """create + rotate + decrypt + rotate_kek emit no plaintext to the log stream."""
    keys = {"v1": os.urandom(KEY_BYTES), "v2": os.urandom(KEY_BYTES)}
    provider = _RotatingProvider(keys, current="v1")
    rotated_provider = _RotatingProvider(keys, current="v2")
    with structlog.testing.capture_logs() as captured:
        credential = await _create(session, provider)
        await vault.rotate_secret(
            session,
            provider,
            credential_id=credential.id,
            new_secret=_ROTATED_SECRET,
            actor="user:alice",
        )
        await vault.decrypt(session, provider, credential, actor="user:alice", reason="lifecycle")
        await vault.rotate_kek(session, rotated_provider, actor="user:alice")

    blob = str(captured)
    assert len(captured) >= 4  # one audit event per operation
    assert _SECRET not in blob
    assert _ROTATED_SECRET not in blob
    assert "DecryptedSecret(b" not in blob


# ---------------------------------------------------------------------------
# KEK wrap/unwrap audit (ADR-0032 §5) — identifiers/versions only
# ---------------------------------------------------------------------------


async def test_create_audits_kek_wrap_with_version_only(session: AsyncSession) -> None:
    """create_credential emits one kek.wrap row carrying the KEK version, no bytes."""
    provider = _provider()
    credential = await _create(session, provider)

    rows = await _audit_rows(session, "kek.wrap")
    assert len(rows) == 1
    entry = rows[0]
    assert entry.target_id == str(credential.id)
    assert entry.detail == {"kek_version": "v1"}
    assert _SECRET not in str(entry.detail)


async def test_decrypt_audits_kek_unwrap(session: AsyncSession) -> None:
    """decrypt emits a kek.unwrap row alongside credential.decrypted."""
    provider = _provider()
    credential = await _create(session, provider)

    await vault.decrypt(session, provider, credential, actor="system:discovery", reason="ssh")

    rows = await _audit_rows(session, "kek.unwrap")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)
    assert rows[0].detail == {"kek_version": "v1", "reason": "ssh"}


async def test_decrypt_audits_kek_unwrap_even_when_payload_auth_fails(
    session: AsyncSession,
) -> None:
    """CR9: a payload-auth failure still records the kek.unwrap key-access audit.

    The DEK unwrap (key access) succeeds, but the payload GCM auth fails (the
    ciphertext is tampered). The unwrap audit must already be written — key access
    happened — so it is never lost to a downstream payload-auth abort.
    """
    provider = _provider()
    credential = await _create(session, provider)
    # Tamper ONLY the payload ciphertext: the DEK still unwraps (key access), but
    # the payload GCM auth fails -> DecryptionError after the unwrap step.
    credential.ciphertext = bytes(bytearray(credential.ciphertext)[:-1] + b"\x00")

    with pytest.raises(DecryptionError):
        await vault.decrypt(session, provider, credential, actor="system:discovery", reason="ssh")

    unwrap_rows = await _audit_rows(session, "kek.unwrap")
    assert len(unwrap_rows) == 1  # key access audited despite the payload failure
    assert unwrap_rows[0].detail == {"kek_version": "v1", "reason": "ssh"}
    # The success-only credential.decrypted audit is NOT written on the failure.
    assert await _audit_rows(session, "credential.decrypted") == []


async def test_rotate_kek_audits_kek_wrap_per_credential(session: AsyncSession) -> None:
    """KEK rotation emits a kek.wrap row per rewrapped credential (to-version only)."""
    old_kek, new_kek = os.urandom(KEY_BYTES), os.urandom(KEY_BYTES)
    v1_provider = _RotatingProvider({"v1": old_kek}, current="v1")
    creds = [
        await _create(session, v1_provider, name=f"c{i}", secret=f"{_SECRET}{i}") for i in range(2)
    ]

    rotated = _RotatingProvider({"v1": old_kek, "v2": new_kek}, current="v2")
    await vault.rotate_kek(session, rotated, actor="user:admin")

    rows = await _audit_rows(session, "kek.wrap")
    # 2 on create (v1) + 2 on rewrap (v2).
    rewrap_rows = [r for r in rows if r.detail == {"kek_version": "v2"}]
    assert len(rewrap_rows) == 2
    assert {r.target_id for r in rewrap_rows} == {str(c.id) for c in creds}


# ---------------------------------------------------------------------------
# Fail closed (ADR-0032 §4) — provider unreachable
# ---------------------------------------------------------------------------


async def test_create_fails_closed_no_row_written(session: AsyncSession) -> None:
    """An unreachable provider makes create raise 503 and persist no credential row."""
    with pytest.raises(KeyProviderUnavailable) as excinfo:
        await _create(session, _DownProvider())
    assert excinfo.value.status_code == 503
    assert _SECRET not in str(excinfo.value)
    await session.flush()
    rows = (await session.execute(select(DeviceCredential))).scalars().all()
    assert rows == []


async def test_create_fails_closed_audits_provider_unavailable(session: AsyncSession) -> None:
    """The tripped fail-closed gate is audited with the reason class only, no secret."""
    with pytest.raises(KeyProviderUnavailable):
        await _create(session, _DownProvider())

    rows = await _audit_rows(session, "kek.provider.unavailable")
    assert len(rows) == 1
    assert rows[0].detail == {"reason_class": "TimeoutError"}
    assert _SECRET not in str(rows[0].detail)
    # No credential.created / kek.wrap row was written on the failed write.
    assert await _audit_rows(session, "credential.created") == []
    assert await _audit_rows(session, "kek.wrap") == []


async def test_decrypt_fails_closed_when_provider_down(session: AsyncSession) -> None:
    """decrypt raises 503 (so the dependent task retries) and audits the gate."""
    provider = _provider()
    credential = await _create(session, provider)

    with pytest.raises(KeyProviderUnavailable):
        await vault.decrypt(
            session, _DownProvider(), credential, actor="system:discovery", reason="ssh"
        )

    rows = await _audit_rows(session, "kek.provider.unavailable")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)
    # No decrypt audit row when the unwrap fails closed.
    assert await _audit_rows(session, "credential.decrypted") == []


async def test_rotate_secret_fails_closed_when_provider_down(session: AsyncSession) -> None:
    """rotate_secret raises 503 and audits the gate; the payload is left unchanged."""
    provider = _provider()
    credential = await _create(session, provider)
    old_ciphertext = credential.ciphertext

    with pytest.raises(KeyProviderUnavailable):
        await vault.rotate_secret(
            session,
            _DownProvider(),
            credential_id=credential.id,
            new_secret=_ROTATED_SECRET,
            actor="user:carol",
        )

    assert credential.ciphertext == old_ciphertext  # payload untouched
    rows = await _audit_rows(session, "kek.provider.unavailable")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)
    assert _ROTATED_SECRET not in str(rows[0].detail)
    assert await _audit_rows(session, "credential.rotated") == []


async def test_rotate_kek_fails_closed_when_provider_down(session: AsyncSession) -> None:
    """rotate_kek raises 503 mid-pass and audits the gate; no row is mutated."""
    old_kek = os.urandom(KEY_BYTES)
    v1_provider = _RotatingProvider({"v1": old_kek}, current="v1")
    credential = await _create(session, v1_provider)
    wrapped_before = credential.wrapped_dek

    with pytest.raises(KeyProviderUnavailable):
        await vault.rotate_kek(session, _DownProvider(version="v2"), actor="user:admin")

    assert credential.wrapped_dek == wrapped_before
    rows = await _audit_rows(session, "kek.provider.unavailable")
    assert len(rows) == 1
    assert rows[0].target_id == str(credential.id)


# ---------------------------------------------------------------------------
# Durable fail-closed audit (ADR-0032 §4/§5) — survives caller rollback
# ---------------------------------------------------------------------------


async def test_provider_unavailable_audit_survives_caller_rollback(engine: AsyncEngine) -> None:
    """The kek.provider.unavailable row persists even when the caller rolls back.

    Reproduces the real fail-closed path (ADR-0032 §4/§5): create raises 503, the
    caller's transaction is rolled back (the route never reaches ``commit``), yet
    the append-only audit row must remain durably written via the autonomous
    sessionmaker. A read on a *fresh* session sees the committed row.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as request_session:
        with pytest.raises(KeyProviderUnavailable):
            await vault.create_credential(
                request_session,
                _DownProvider(),
                name="lab-ssh",
                kind=CredentialKind.SSH,
                username="netops",
                secret=_SECRET,
                params={"port": 22},
                actor="user:alice",
                sessionmaker=maker,
            )
        # The route would never commit on this path — simulate the rollback.
        await request_session.rollback()

    async with maker() as verify_session:
        rows = await _audit_rows(verify_session, "kek.provider.unavailable")
        assert len(rows) == 1
        assert rows[0].detail == {"reason_class": "TimeoutError"}
        assert _SECRET not in str(rows[0].detail)
        # No credential row was persisted on the failed write.
        creds = (await verify_session.execute(select(DeviceCredential))).scalars().all()
        assert creds == []


async def test_autonomous_sessionmaker_makes_worker_decrypt_audit_durable(
    engine: AsyncEngine,
) -> None:
    """A worker decrypt that fails closed durably audits via autonomous_sessionmaker.

    The worker decrypt sites own an AsyncSession but no explicit sessionmaker, so
    they derive one with :func:`vault.autonomous_sessionmaker` (bound to the same
    engine). On the fail-closed path the caller's transaction is rolled back, yet
    the ``kek.provider.unavailable`` row must survive — a read on a *fresh* session
    sees it. Without the derived autonomous sessionmaker the row would roll back
    with the doomed transaction and be silently lost (the dead-audit gap).
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as setup_session:
        credential = await _create(setup_session, _provider())
        await setup_session.commit()

    async with maker() as worker_session:
        row = await worker_session.get(DeviceCredential, credential.id)
        assert row is not None
        with pytest.raises(KeyProviderUnavailable):
            await vault.decrypt(
                worker_session,
                _DownProvider(),
                row,
                actor="system:discovery",
                reason="discovery",
                sessionmaker=vault.autonomous_sessionmaker(worker_session),
            )
        # The worker session would never commit the decrypt audit on this path.
        await worker_session.rollback()

    async with maker() as verify_session:
        rows = await _audit_rows(verify_session, "kek.provider.unavailable")
        assert len(rows) == 1
        assert rows[0].target_id == str(credential.id)
        assert rows[0].detail == {"reason_class": "TimeoutError"}
        # No decrypt audit row when the unwrap fails closed.
        assert await _audit_rows(verify_session, "credential.decrypted") == []


async def test_provider_unavailable_preserves_original_error_when_audit_fails(
    engine: AsyncEngine,
) -> None:
    """CR8: if the audit write fails on the fail-closed path, the ORIGINAL 503 wins.

    The provider is down (KeyProviderUnavailable) AND the durable-audit sessionmaker
    raises when used (audit DB also down). The caller must still see the
    KeyProviderUnavailable — the fail-closed 503 — not the audit DB error.
    """

    class _ExplodingSessionmaker:
        def __call__(self) -> object:
            raise RuntimeError("audit DB unreachable")

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as request_session:
        with pytest.raises(KeyProviderUnavailable):  # NOT RuntimeError
            await vault.create_credential(
                request_session,
                _DownProvider(),
                name="lab-ssh",
                kind=CredentialKind.SSH,
                username="netops",
                secret=_SECRET,
                params={"port": 22},
                actor="user:alice",
                sessionmaker=_ExplodingSessionmaker(),  # type: ignore[arg-type]
            )


async def test_autonomous_sessionmaker_reuses_caller_engine(engine: AsyncEngine) -> None:
    """autonomous_sessionmaker binds the new sessionmaker to the caller's engine."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        derived = vault.autonomous_sessionmaker(session)
        async with derived() as derived_session:
            assert derived_session.bind is engine


# ---------------------------------------------------------------------------
# Provider-selection audit (ADR-0032 §5) — kek.provider.select
# ---------------------------------------------------------------------------


async def test_audit_provider_select_writes_durable_row(engine: AsyncEngine) -> None:
    """audit_provider_select durably writes the ADR-0032 §5 shape, ids/versions only."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    provider = _provider(version="v1")

    await vault.audit_provider_select(maker, provider, actor="system:startup")

    async with maker() as verify_session:
        rows = await _audit_rows(verify_session, "kek.provider.select")
        assert len(rows) == 1
        entry = rows[0]
        assert entry.actor == "system:startup"
        assert entry.detail == {
            "provider": "EnvKeyProvider",
            "kek_version": "v1",
            "is_production_grade": False,
        }
        # No KEK bytes anywhere in the row.
        kek_b64 = base64.urlsafe_b64encode(provider._kek).decode("ascii")  # type: ignore[attr-defined]
        assert kek_b64 not in str(entry.detail)
