"""Postgres PITR restore-drill harness (P1 W5-T2, ADR-0030 §5.1).

This package is the *assertion* half of the Postgres point-in-time-recovery
drill. The K8s ``postgres-pitr-drill-job.yaml`` performs the physical
pgBackRest restore to a THROWAWAY target; this harness then proves the four
properties a naive ``pg_restore`` would skip (ADR-0030 §1 / §5.1):

  (a) RPO-in-window   — WAL replay reached within the PROPOSED window.
  (b) audit immutable — the restored append-only audit log is still
                        UPDATE/DELETE-locked AND not truncated.
  (c) creds fail CLOSED — a restored ``device_credentials`` row decrypts ONLY
                        with the matching KEK version and raises a TYPED error
                        (no plaintext) when the KEK is absent.
  (d) pgbackrest verify — the restored stanza verifies clean.

Each assertion emits one structured ``DRILL postgres_pitr <name>=PASS|FAIL
duration_s=<n>`` line for the W5-T5 G-REL evidence collector. The harness is
SECRET-SURFACE: the fail-closed path (c) is the core invariant and is never
weakened — a missing KEK MUST raise and leak no plaintext.
"""

from __future__ import annotations

from .assertions import (
    DrillError,
    DrillResult,
    assert_audit_log_immutable,
    assert_credentials_fail_closed,
    assert_pgbackrest_verify_clean,
    assert_rpo_within_window,
    emit,
)

__all__ = [
    "DrillError",
    "DrillResult",
    "assert_audit_log_immutable",
    "assert_credentials_fail_closed",
    "assert_pgbackrest_verify_clean",
    "assert_rpo_within_window",
    "emit",
]
