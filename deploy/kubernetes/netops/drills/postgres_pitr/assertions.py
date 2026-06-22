"""PITR drill assertions + structured result emission (ADR-0030 §5.1).

These functions are the policy-as-test core of the Postgres restore drill: each
takes a connection to the RESTORED throwaway database (or an explicit input) and
either passes or raises :class:`DrillError`. They are deliberately storage-agnostic
over the DB-API 2.0 ``Connection`` so the same assertions run against the seeded
SQLite fixture in CI (lab-deferred, P1-PLAN.md §6) and against a real restored
PostgreSQL instance in the P2 quarterly run.

Secure-by-default invariants this module proves (never weaken them):
  * The audit log comes back UPDATE/DELETE-locked and NOT truncated.
  * A restored credential is INERT without the matching KEK — the missing-KEK
    path raises a TYPED error from ``app.core.crypto`` and leaks no plaintext.

The credential proof reuses ``app.core.crypto`` (``envelope_decrypt`` /
``EncryptedSecret`` / ``UnknownKekVersionError`` / ``DecryptionError`` /
``KeyProvider``) — the SAME envelope code the platform encrypts with, so the
drill exercises the production fail-closed path, not a re-implementation.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.crypto import (
    DecryptionError,
    EncryptedSecret,
    KeyProvider,
    UnknownKekVersionError,
    envelope_decrypt,
)

#: Prefix for the structured result lines the W5-T5 evidence collector greps for.
DRILL_TAG = "DRILL postgres_pitr"


class DrillError(AssertionError):
    """A drill assertion failed — the restore did NOT reproduce a required property.

    Subclasses :class:`AssertionError` so a failed drill is a hard, un-catchable
    (by a bare ``except Exception``) failure in the Job's ``set -e`` script.
    Carries the assertion name so the emitted ``DRILL`` line names the control.
    """

    def __init__(self, assertion: str, reason: str) -> None:
        self.assertion = assertion
        super().__init__(f"{assertion}: {reason}")


@dataclass(frozen=True, slots=True)
class DrillResult:
    """One assertion outcome, rendered to the structured ``DRILL`` evidence line."""

    assertion: str
    passed: bool
    duration_s: float

    def line(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"{DRILL_TAG} {self.assertion}={status} duration_s={self.duration_s:.3f}"


def emit(result: DrillResult, *, stream: Any = None) -> None:
    """Print the structured result line (the W5-T5 G-REL evidence contract).

    ``stream`` defaults to the LIVE ``sys.stdout`` resolved at call time (not at
    import time) so a test harness that swaps ``sys.stdout`` (pytest capsys) or
    the Job's redirected stdout receives the line.
    """
    print(result.line(), file=stream if stream is not None else sys.stdout, flush=True)


class _Connection(Protocol):
    """The slice of DB-API 2.0 the assertions use (SQLite fixture or psql)."""

    def cursor(self) -> Any: ...

    def execute(self, sql: str, *params: Any) -> Any: ...


@contextmanager
def _timed(assertion: str, *, stream: Any = None) -> Iterator[Callable[[], None]]:
    """Run a timed assertion, emitting exactly one PASS/FAIL line either way.

    The body calls the yielded ``ok()`` only after every check passed; if it
    raises (a real :class:`DrillError` or any unexpected error) a FAIL line is
    emitted and the error re-raised so the Job fails closed.
    """
    start = time.monotonic()
    passed = False

    def ok() -> None:
        nonlocal passed
        passed = True

    try:
        yield ok
    finally:
        duration = time.monotonic() - start
        emit(DrillResult(assertion, passed, duration), stream=stream)


# ---------------------------------------------------------------------------
# (a) RPO ≤ window — WAL replay reached within the PROPOSED window.
# ---------------------------------------------------------------------------


def assert_rpo_within_window(
    *,
    lag_seconds: float,
    window_seconds: float,
    stream: Any = None,
) -> None:
    """Assert the restore's recovery point is within the PROPOSED RPO window.

    ``lag_seconds`` is the gap between the last replayed WAL record and the
    incident point (measured by the restore step). The window is the PROPOSED
    ``backup.postgres.wal.proposedRpoMinutes`` knob (ADR-0030 §6), passed through
    so the drill re-bases on the same value as W5-T1. A negative lag is a clock /
    measurement fault and FAILS closed (we cannot prove RPO from a bad signal).
    """
    with _timed("rpo_within_window", stream=stream) as ok:
        if lag_seconds < 0:
            raise DrillError(
                "rpo_within_window",
                f"measured WAL replay lag {lag_seconds:.1f}s is negative "
                "(clock/measurement fault — cannot prove RPO, fail closed)",
            )
        if lag_seconds > window_seconds:
            raise DrillError(
                "rpo_within_window",
                f"WAL replay lag {lag_seconds:.1f}s exceeds the {window_seconds:.0f}s "
                "RPO window (ADR-0030 §1/§6 — restore did not reach the window)",
            )
        ok()


# ---------------------------------------------------------------------------
# (b) Audit-log immutability re-asserted after restore.
# ---------------------------------------------------------------------------


def _audit_max_id(conn: _Connection) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_log")
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _audit_row_count(conn: _Connection) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_log")
    return int(cur.fetchone()[0])


def _app_role_can_mutate_audit(conn: _Connection) -> bool:
    """True iff a DELETE on ``audit_log`` SUCCEEDS (a FAILED drill).

    The append-only guarantee is enforced two ways (mirrored from the schema):
    a ``BEFORE UPDATE OR DELETE`` guard trigger that RAISES (migration 0009 style,
    ADR-0011 §2) and the ``REVOKE UPDATE, DELETE ... FROM PUBLIC`` grant (0001
    baseline). If either is intact the mutation raises; only a restore that came
    back WRITABLE lets it through — which is exactly the failure this catches.

    The probe runs inside a SAVEPOINT that is always rolled back, so even on a
    writable (failed) restore the throwaway DB is never actually mutated — the
    drill observes the refusal/acceptance without destroying the seeded rows.
    """
    conn.execute("SAVEPOINT audit_immutability_probe")
    try:
        conn.execute("DELETE FROM audit_log")
    except Exception:  # noqa: BLE001 — any DB refusal proves the guard fired
        conn.execute("ROLLBACK TO SAVEPOINT audit_immutability_probe")
        conn.execute("RELEASE SAVEPOINT audit_immutability_probe")
        return False
    # The DELETE was accepted (a writable audit log) — undo it and report failure.
    conn.execute("ROLLBACK TO SAVEPOINT audit_immutability_probe")
    conn.execute("RELEASE SAVEPOINT audit_immutability_probe")
    return True


def assert_audit_log_immutable(
    conn: _Connection,
    *,
    checkpoint_max_id: int,
    checkpoint_row_count: int,
    stream: Any = None,
) -> None:
    """Assert the restored audit log is append-only AND not truncated.

    Three checks (ADR-0030 §5.1.2):
      1. No-truncation: ``max(seq)`` and row-count are >= the pre-incident
         checkpoint captured before the drill (a silently truncated log fails).
      2. Immutability: a probe ``DELETE`` against ``audit_log`` is REFUSED — a
         restore that comes back with a writable audit log is a FAILED drill
         (ADR-0030 §1), not a successful one.

    The probe runs inside a savepoint/rollback by the caller's fixture so a
    (refused) DELETE never actually mutates the throwaway DB.
    """
    with _timed("audit_log_immutable", stream=stream) as ok:
        max_id = _audit_max_id(conn)
        if max_id < checkpoint_max_id:
            raise DrillError(
                "audit_log_immutable",
                f"restored audit_log max(seq)={max_id} is below the pre-incident "
                f"checkpoint {checkpoint_max_id} — the log was truncated (ADR-0030 §5.1.2)",
            )
        row_count = _audit_row_count(conn)
        if row_count < checkpoint_row_count:
            raise DrillError(
                "audit_log_immutable",
                f"restored audit_log row-count={row_count} is below the checkpoint "
                f"{checkpoint_row_count} — rows were lost/truncated (ADR-0030 §5.1.2)",
            )
        if _app_role_can_mutate_audit(conn):
            raise DrillError(
                "audit_log_immutable",
                "the restored audit_log accepted a DELETE — the append-only guard "
                "(trigger + REVOKE) did NOT come back; a writable audit log is a "
                "FAILED drill (ADR-0030 §1 / ADR-0011 §2)",
            )
        ok()


# ---------------------------------------------------------------------------
# (c) Credential separation — fail CLOSED without the matching KEK.
# ---------------------------------------------------------------------------


def assert_credentials_fail_closed(
    secret: EncryptedSecret,
    aad: bytes,
    *,
    matching_provider: KeyProvider,
    absent_kek_provider: KeyProvider,
    expected_plaintext: bytes,
    stream: Any = None,
) -> None:
    """Positive test of fail-closed credential behaviour (ADR-0030 §1 / Alt #4).

    Two halves, both required to PASS:
      * With the MATCHING KEK provider the restored ``device_credentials`` row
        decrypts to the expected plaintext — the restore reproduced the data.
      * With a provider that CANNOT supply the row's ``kek_version`` (the KEK is
        absent — its handle was not restored), decryption raises a TYPED error
        (``UnknownKekVersionError`` or ``DecryptionError``) and leaks NO
        plaintext. This is the "a restored DB is inert for device access until
        the KEK is reachable" property feeding G-SEC.

    A SILENT decrypt (any plaintext) on the absent-KEK path is the worst-case
    failure and FAILS the drill — the whole point is that the missing KEK closes
    the door. ``BaseException``-derived leaks are not swallowed.
    """
    with _timed("credentials_fail_closed", stream=stream) as ok:
        # Positive half: matching KEK reproduces the secret.
        recovered = envelope_decrypt(secret, aad, matching_provider)
        if recovered != expected_plaintext:
            raise DrillError(
                "credentials_fail_closed",
                "matching-KEK decrypt did not reproduce the seeded plaintext — the "
                "restore lost or corrupted the credential payload (ADR-0030 §5.1.3)",
            )

        # Negative/closed half: absent KEK must FAIL CLOSED with a typed error.
        leaked = False
        try:
            envelope_decrypt(secret, aad, absent_kek_provider)
            leaked = True  # reaching here at all is a silent decrypt — the failure.
        except (UnknownKekVersionError, DecryptionError):
            pass  # correct fail-closed path: typed error, no plaintext returned.
        if leaked:
            raise DrillError(
                "credentials_fail_closed",
                "decryption SUCCEEDED without the matching KEK — the restored "
                "credential is NOT inert; G-SEC requires fail-closed (ADR-0030 §1/§5.1.3)",
            )
        ok()


# ---------------------------------------------------------------------------
# (d) pgbackrest verify clean on the restored stanza.
# ---------------------------------------------------------------------------


def assert_pgbackrest_verify_clean(
    verify_runner: Callable[[], tuple[int, str]],
    *,
    stream: Any = None,
) -> None:
    """Assert ``pgbackrest verify`` on the restored stanza exits clean.

    ``verify_runner`` is a callable returning ``(exit_code, output_text)`` — the
    Job wires it to the actual ``pgbackrest --stanza=<stanza> verify`` subprocess;
    the CI fixture wires a recorded result. A non-zero exit OR an empty output is
    a FAILED verify (a verify that produced no output proves nothing — L5
    non-empty guard, mirrored from W5-T1's ``test -s``).
    """
    with _timed("pgbackrest_verify_clean", stream=stream) as ok:
        exit_code, output = verify_runner()
        if not output.strip():
            raise DrillError(
                "pgbackrest_verify_clean",
                "pgbackrest verify produced EMPTY output — a silent/empty verify "
                "proves nothing and fails closed (ADR-0030 §1, L5 non-empty guard)",
            )
        if exit_code != 0:
            raise DrillError(
                "pgbackrest_verify_clean",
                f"pgbackrest verify exited {exit_code} (non-clean stanza) — "
                "an unverifiable restore is a FAILED drill (ADR-0030 §1 req 2)",
            )
        ok()
