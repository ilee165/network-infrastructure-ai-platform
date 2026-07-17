"""Seeded throwaway fixture for the PITR drill (ADR-0030 §5.1, P1-PLAN.md §6).

P1 ships a GREEN dry-run with NO hardware: this module builds an in-memory
SQLite database that reproduces the two schema properties the drill asserts —
an append-only ``audit_log`` and an envelope-encrypted ``device_credentials``
row — so the four assertions run end-to-end in CI. The P2 quarterly run swaps
this fixture for a real pgBackRest restore to a throwaway PostgreSQL target; the
assertions in :mod:`assertions` are unchanged.

The audit append-only guarantee is modelled exactly like the production schema:
  * a ``BEFORE UPDATE OR DELETE`` SQLite trigger that RAISES (the portable
    analogue of migration 0009's PL/pgSQL guard and the 0001 baseline
    ``REVOKE UPDATE, DELETE ... FROM PUBLIC`` grant — ADR-0011 §2).

The encrypted credential is produced by the REAL ``app.core.crypto`` envelope so
the fail-closed proof exercises production code, not a stand-in.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.core.config import Settings
from app.core.crypto import (
    EncryptedSecret,
    EnvKeyProvider,
    KeyProvider,
    envelope_encrypt,
)

#: The KEK version the seeded credential is wrapped under (matches dev default).
SEED_KEK_VERSION = "v1"

#: A urlsafe-base64 32-byte KEK used ONLY to seed the in-memory fixture in CI.
#: This is a TEST fixture value, NOT a production secret — production KEKs are
#: resolved at runtime from the KMS handle / mounted reference (ADR-0032). It is
#: deliberately a throwaway constant — the urlsafe-base64 of
#: sha256("netops-pitr-drill-fixture-kek"), decoding to exactly 32 bytes — never
#: used to wrap any production secret (this is harness code, not a manifest).
_FIXTURE_KEK_B64 = "arozku73-ukFSyru40PBaGrCIljC5MmdJhjP33YZFMs="  # 32 bytes decoded.

#: The plaintext device password the drill round-trips through the envelope.
SEED_CREDENTIAL_PLAINTEXT = b"drill-fixture-device-password"

#: AAD binding the ciphertext to its row (ADR-0011: the credential row id).
SEED_CREDENTIAL_AAD = b"device_credentials:drill-seed-0001"


@dataclass(frozen=True, slots=True)
class SeededDrillState:
    """Everything the drill needs after the (simulated) restore.

    Captures the pre-incident audit checkpoint, the restored connection, and the
    envelope-encrypted credential row + its AAD so the assertions can run.
    """

    conn: sqlite3.Connection
    checkpoint_max_id: int
    checkpoint_row_count: int
    credential: EncryptedSecret
    credential_aad: bytes
    credential_plaintext: bytes


def _fixture_provider(
    kek_b64: str = _FIXTURE_KEK_B64, version: str = SEED_KEK_VERSION
) -> KeyProvider:
    """Build an :class:`EnvKeyProvider` over the fixture KEK (CI-only)."""
    return EnvKeyProvider(
        Settings(_env_file=None, kek=kek_b64, kek_version=version)  # type: ignore[call-arg, arg-type]
    )


def matching_kek_provider() -> KeyProvider:
    """The provider holding the matching KEK — decrypt MUST succeed with it."""
    return _fixture_provider()


def absent_kek_provider() -> KeyProvider:
    """A provider whose KEK version does NOT match the seeded row.

    Stands in for "the KEK handle was not restored": ``current_version`` is a
    different label, so unwrapping the seeded row raises ``UnknownKekVersionError``
    from ``app.core.crypto`` — the fail-closed path the drill proves.
    """
    return _fixture_provider(version="kek-absent")


_AUDIT_APPEND_ONLY_TRIGGERS = (
    # Portable analogue of migration 0009's BEFORE UPDATE OR DELETE guard: any
    # UPDATE/DELETE on audit_log RAISES, so the restored log is provably immutable
    # (ADR-0011 §2). SQLite's RAISE(ABORT, ...) mirrors the PL/pgSQL RAISE EXCEPTION.
    """
    CREATE TRIGGER trg_audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT,
                'audit_log is append-only: UPDATE is not permitted (ADR-0011 §2)');
        END;
    """,
    """
    CREATE TRIGGER trg_audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT,
                'audit_log is append-only: DELETE is not permitted (ADR-0011 §2)');
        END;
    """,
)


def build_seeded_state(*, immutable: bool = True, truncate_audit: bool = False) -> SeededDrillState:
    """Build the throwaway DB + seeded rows the drill runs against.

    Args:
        immutable: When True (default), install the append-only audit triggers —
            the property a healthy restore reproduces. When False, OMIT them so a
            DELETE succeeds: the negative test for the audit-immutability assertion
            (a "writable audit log" restore must FAIL the drill).
        truncate_audit: When True, seed FEWER audit rows than the checkpoint
            records, simulating a silently truncated restore — the negative test
            for the no-truncation check.

    Returns:
        The :class:`SeededDrillState` with the connection, checkpoint, and the
        envelope-encrypted credential.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE audit_log ("
        " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        " actor TEXT NOT NULL,"
        " action TEXT NOT NULL,"
        " target_type TEXT NOT NULL)"
    )

    # The pre-incident checkpoint: the audit state captured BEFORE the drill.
    full_rows = [
        ("system", "credential.created", "device_credentials"),
        ("admin", "approval.recorded", "approvals"),
        ("system", "discovery.completed", "discovery_runs"),
    ]
    checkpoint_row_count = len(full_rows)

    # The RESTORED rows. Healthy restore = all rows back; truncated restore = fewer.
    restored_rows = full_rows[:-1] if truncate_audit else full_rows
    conn.executemany(
        "INSERT INTO audit_log (actor, action, target_type) VALUES (?, ?, ?)",
        restored_rows,
    )
    conn.commit()

    # max(seq) checkpoint is the pre-incident high-water mark (== full row count).
    checkpoint_max_id = checkpoint_row_count

    if immutable:
        for trigger in _AUDIT_APPEND_ONLY_TRIGGERS:
            conn.execute(trigger)
        conn.commit()

    # Seed ONE envelope-encrypted device credential via the REAL crypto module.
    provider = matching_kek_provider()
    credential = envelope_encrypt(SEED_CREDENTIAL_PLAINTEXT, SEED_CREDENTIAL_AAD, provider)

    return SeededDrillState(
        conn=conn,
        checkpoint_max_id=checkpoint_max_id,
        checkpoint_row_count=checkpoint_row_count,
        credential=credential,
        credential_aad=SEED_CREDENTIAL_AAD,
        credential_plaintext=SEED_CREDENTIAL_PLAINTEXT,
    )
