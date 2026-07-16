"""PITR drill entrypoint — restore-then-assert orchestration (ADR-0030 §5.1).

The K8s ``postgres-pitr-drill-job.yaml`` invokes this module as the assertion
step AFTER pgBackRest has restored the latest full + WAL to a THROWAWAY target.
In P1 (no hardware, P1-PLAN.md §6) it runs against the seeded SQLite fixture so
the gate is a green dry-run; in the P2 quarterly run the Job points the same
assertions at the real restored PostgreSQL instance + a live ``pgbackrest verify``.

It runs all four ADR-0030 §5.1 assertions, each emitting one structured
``DRILL postgres_pitr <name>=PASS|FAIL duration_s=<n>`` line for the W5-T5
G-REL evidence collector, and exits non-zero on the first failure (fail closed).

Run:  python -m app.ops.drills.postgres_pitr.run_drill
      (the runtime image installs the backend wheel under ``/opt/venv``).
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from .assertions import (
    DrillError,
    assert_audit_log_immutable,
    assert_credentials_fail_closed,
    assert_pgbackrest_verify_clean,
    assert_rpo_within_window,
)
from .fixture import absent_kek_provider, build_seeded_state, matching_kek_provider


def _fixture_verify_runner() -> tuple[int, str]:
    """Stand-in ``pgbackrest verify`` result for the seeded dry-run (P1).

    Returns a clean exit + non-empty output. The P2 Job replaces this with a real
    ``subprocess.run(["pgbackrest", "--stanza", stanza, "verify"])`` capture.
    """
    return 0, "stanza: netops\n    status: ok\n    verify: ok\n"


def run(
    *,
    rpo_lag_seconds: float = 30.0,
    rpo_window_seconds: float = 300.0,
    argv: Sequence[str] | None = None,
) -> int:
    """Run the full drill against the seeded fixture; return a process exit code.

    Args:
        rpo_lag_seconds: Measured WAL-replay lag for the dry-run (well within the
            300s / 5-min PROPOSED window — ADR-0030 §6).
        rpo_window_seconds: The RPO window (``proposedRpoMinutes`` * 60).
        argv: Unused placeholder for future flags (keeps the entrypoint stable).

    Returns:
        ``0`` if every assertion PASSED, ``1`` on the first failure (fail closed).
    """
    del argv  # reserved for future flags; the drill is parameter-free in P1.
    state = build_seeded_state()
    try:
        assert_rpo_within_window(
            lag_seconds=rpo_lag_seconds,
            window_seconds=rpo_window_seconds,
        )
        assert_audit_log_immutable(
            state.conn,
            checkpoint_max_id=state.checkpoint_max_id,
            checkpoint_row_count=state.checkpoint_row_count,
        )
        assert_credentials_fail_closed(
            state.credential,
            state.credential_aad,
            matching_provider=matching_kek_provider(),
            absent_kek_provider=absent_kek_provider(),
            expected_plaintext=state.credential_plaintext,
        )
        assert_pgbackrest_verify_clean(_fixture_verify_runner)
    except DrillError as exc:
        print(f"DRILL postgres_pitr OUTCOME=FAIL failed_assertion={exc.assertion}", flush=True)
        return 1
    finally:
        state.conn.close()

    print("DRILL postgres_pitr OUTCOME=PASS assertions=4", flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the Job / test wrapper
    sys.exit(run())
