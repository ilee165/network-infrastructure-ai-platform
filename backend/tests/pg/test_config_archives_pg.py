"""Config-archive double-envelope round-trip under REAL PostgreSQL (P4 W1-T1, ADR-0050 §7.3).

The SQLite unit suite exercises the F5 plugin's archive path over fixtures; THIS
module re-asserts the **at-rest encryption surface** — the ``config_archives``
table + its second (platform) envelope — against a real Postgres, so the
secret-bearing storage layer rests on PG-accurate ``bytea`` semantics:

  * store -> load round-trip: the passphrase-encrypted archive bytes survive the
    platform envelope intact and hash to the recorded ``sha256``;
  * genuine double-encryption: the persisted ``ciphertext`` bytea is NOT the
    input bytes (a second envelope is really applied);
  * cross-row AAD binding: the envelope is bound to the archive row id (a wrapped
    DEK lifted onto another row fails to decrypt — the ADR-0032 §1 replay guard);
  * **no plaintext / key-material leak** (ADR-0050 §7.3): neither the archive
    bytes, the sha256-preimage, nor the wrapped DEK appears in any persisted
    ``config_archive.*`` / ``kek.*`` audit row's JSONB ``detail``.

Secret handling: the only "secret" here is a synthetic UCS blob created INSIDE
the test and confined to :class:`~pydantic.SecretBytes`; it is asserted ABSENT
from every persisted audit row, never logged, never placed in a fixture file. The
throwaway KEK is an in-memory :class:`FakeKmsKeyProvider`.
"""

from __future__ import annotations

import base64
import hashlib
import uuid

import pytest
from pydantic import SecretBytes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import DecryptionError, FakeKmsKeyProvider
from app.models import AuditLog
from app.models.config_mgmt import ConfigArchive as ConfigArchiveRow
from app.models.inventory import Device, DeviceStatus
from app.plugins.base import ConfigArchive as ConfigArchivePayload
from app.services import config_archives

pytestmark = pytest.mark.integration

#: A synthetic UCS blob — created here, asserted ABSENT from every audit row.
#: NOT a real backup; contains an obvious sentinel.
_UCS = b"UCSBLOB\x00SYNTHETIC-UCS-MASTER-KEY-DO-NOT-LEAK\x00" + bytes(range(64))
_SHA = hashlib.sha256(_UCS).hexdigest()


async def _seed_device(session: AsyncSession) -> uuid.UUID:
    device = Device(
        hostname=f"bigip-{uuid.uuid4().hex[:8]}",
        mgmt_ip=f"10.20.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
        status=DeviceStatus.NEW,
    )
    session.add(device)
    await session.flush()
    return device.id


def _payload(passphrase_ref: str = "vault:archive-pass:1") -> ConfigArchivePayload:
    return ConfigArchivePayload(
        format="ucs",
        content=SecretBytes(_UCS),
        sha256=_SHA,
        size_bytes=len(_UCS),
        passphrase_ref=passphrase_ref,
    )


async def test_store_then_load_round_trip_under_pg(pg_session: AsyncSession) -> None:
    """The archive bytes survive the platform envelope round-trip and match sha256."""
    provider = FakeKmsKeyProvider()
    device_id = await _seed_device(pg_session)

    row = await config_archives.store_archive(
        pg_session, provider, device_id=device_id, archive=_payload(), actor="user:alice"
    )
    await pg_session.flush()

    # Genuine second envelope: the stored bytea is NOT the input bytes.
    assert bytes(row.ciphertext) != _UCS
    assert row.size_bytes == len(_UCS)
    assert row.sha256 == _SHA

    loaded = await config_archives.load_archive_bytes(pg_session, provider, row, actor="user:alice")
    assert loaded == _UCS  # passphrase-encrypted bytes intact

    ref = config_archives.build_archive_ref(row, loaded)
    assert ref.content.get_secret_value() == _UCS
    assert ref.passphrase_ref == "vault:archive-pass:1"


async def test_cross_row_replay_guard_under_pg(pg_session: AsyncSession) -> None:
    """A wrapped DEK lifted onto another archive row fails to decrypt (ADR-0032 §1)."""
    provider = FakeKmsKeyProvider()
    device_id = await _seed_device(pg_session)
    a = await config_archives.store_archive(
        pg_session, provider, device_id=device_id, archive=_payload(), actor="user:alice"
    )
    b = await config_archives.store_archive(
        pg_session, provider, device_id=device_id, archive=_payload("vault:2"), actor="user:alice"
    )
    await pg_session.flush()

    # Move a's wrapped DEK + nonces onto b's row id: the AAD (b.id) no longer
    # matches, so decryption fails — the cross-row replay guard bites.
    b.wrapped_dek = a.wrapped_dek
    b.dek_nonce = a.dek_nonce
    b.ciphertext = a.ciphertext
    b.nonce = a.nonce
    b.kek_version = a.kek_version
    await pg_session.flush()

    with pytest.raises(DecryptionError):
        await config_archives.load_archive_bytes(pg_session, provider, b, actor="user:alice")


async def test_no_secret_or_key_bytes_in_audit_under_pg(pg_session: AsyncSession) -> None:
    """No archive bytes / sha-preimage / wrapped DEK appear in any persisted audit row."""
    provider = FakeKmsKeyProvider()
    device_id = await _seed_device(pg_session)
    row = await config_archives.store_archive(
        pg_session, provider, device_id=device_id, archive=_payload(), actor="user:alice"
    )
    await pg_session.flush()
    await config_archives.load_archive_bytes(pg_session, provider, row, actor="user:alice")

    # Cover hex, repr, AND base64 encodings of every secret/key byte string, so a
    # serializer that re-encodes bytes differently cannot slip a leak past the
    # check (ADR-0050 §7.3 — the guarantee is "in no persisted audit row").
    forbidden = (
        _UCS.hex(),
        repr(_UCS),
        base64.b64encode(_UCS).decode(),
        bytes(row.wrapped_dek).hex(),
        bytes(row.dek_nonce).hex(),
        base64.b64encode(bytes(row.wrapped_dek)).decode(),
        base64.b64encode(bytes(row.dek_nonce)).decode(),
    )
    rows = list((await pg_session.execute(select(AuditLog))).scalars())
    assert rows, "the pass must have written audit rows"
    for audit_row in rows:
        detail_blob = str(audit_row.detail)
        for token in forbidden:
            assert token not in detail_blob, (
                f"key/secret material leaked into a {audit_row.action!r} audit row"
            )
    # The metadata-only audit surface still carries the log-safe sha256 + size.
    created = next(r for r in rows if r.action == "config_archive.created")
    assert created.detail["sha256"] == _SHA
    assert created.detail["size_bytes"] == len(_UCS)


async def test_persisted_row_survives_reload_under_pg(pg_session: AsyncSession) -> None:
    """The row re-read from PG still decrypts (bytea persistence, not object identity)."""
    provider = FakeKmsKeyProvider()
    device_id = await _seed_device(pg_session)
    row = await config_archives.store_archive(
        pg_session, provider, device_id=device_id, archive=_payload(), actor="user:alice"
    )
    await pg_session.commit()
    # ``pg_session`` uses ``expire_on_commit=False``, so without expiring the
    # identity map ``get()`` could return the in-memory instance without touching
    # Postgres — this test would then pass even if the persisted bytea were wrong.
    # Force a real database round-trip.
    pg_session.expire_all()

    fetched = await pg_session.get(ConfigArchiveRow, row.id)
    assert fetched is not None
    loaded = await config_archives.load_archive_bytes(
        pg_session, provider, fetched, actor="user:alice"
    )
    assert loaded == _UCS
