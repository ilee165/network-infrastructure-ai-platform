"""PITR drill harness tests — positive PASS + a NEGATIVE test per assertion.

These prove the assertions actually BITE (ADR-0030 §5.1 risk note): a drill whose
checks are too weak silently passes a broken restore. For every assertion there
is a tampered-input case that MUST raise :class:`DrillError`:

  * audit immutability — a WRITABLE restore (no append-only trigger) must fail.
  * no-truncation       — a TRUNCATED audit log must fail.
  * credential fail-closed — a SUCCESSFUL decrypt without the KEK must fail; and
    the matching-KEK decrypt must succeed (positive half).
  * RPO-in-window       — a lag OUTSIDE the window must fail.
  * pgbackrest verify   — a non-zero/empty verify must fail.

Run (from the backend venv so ``app.core.crypto`` resolves):
  PYTHONPATH=backend:deploy/kubernetes/netops/drills \
    python -m pytest deploy/kubernetes/netops/drills/postgres_pitr/test_drill.py -q
"""

from __future__ import annotations

import io

import pytest

from postgres_pitr.assertions import (
    DrillError,
    DrillResult,
    assert_audit_log_immutable,
    assert_credentials_fail_closed,
    assert_pgbackrest_verify_clean,
    assert_rpo_within_window,
)
from postgres_pitr.fixture import (
    SEED_CREDENTIAL_PLAINTEXT,
    absent_kek_provider,
    build_seeded_state,
    matching_kek_provider,
)
from postgres_pitr.run_drill import run

_SINK = io.StringIO  # fresh stream per assertion so emitted lines don't interleave.


# ---------------------------------------------------------------------------
# Structured-line contract (W5-T5 evidence consumer).
# ---------------------------------------------------------------------------


def test_result_line_format_is_the_t5_contract() -> None:
    line = DrillResult("rpo_within_window", True, 1.2345).line()
    assert line == "DRILL postgres_pitr rpo_within_window=PASS duration_s=1.234"
    fail = DrillResult("audit_log_immutable", False, 0.5).line()
    assert fail == "DRILL postgres_pitr audit_log_immutable=FAIL duration_s=0.500"


# ---------------------------------------------------------------------------
# (a) RPO-in-window.
# ---------------------------------------------------------------------------


def test_rpo_within_window_passes_inside_window() -> None:
    sink = _SINK()
    assert_rpo_within_window(lag_seconds=30.0, window_seconds=300.0, stream=sink)
    assert "rpo_within_window=PASS" in sink.getvalue()


def test_rpo_outside_window_fails_the_drill() -> None:
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_rpo_within_window(lag_seconds=600.0, window_seconds=300.0, stream=sink)
    # A FAIL line is still emitted for the T5 collector even on failure.
    assert "rpo_within_window=FAIL" in sink.getvalue()


def test_rpo_negative_lag_fails_closed() -> None:
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_rpo_within_window(lag_seconds=-1.0, window_seconds=300.0, stream=sink)
    assert "rpo_within_window=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# (b) Audit-log immutability + no-truncation.
# ---------------------------------------------------------------------------


def test_audit_immutable_passes_on_healthy_restore() -> None:
    state = build_seeded_state()
    sink = _SINK()
    try:
        assert_audit_log_immutable(
            state.conn,
            checkpoint_max_id=state.checkpoint_max_id,
            checkpoint_row_count=state.checkpoint_row_count,
            stream=sink,
        )
    finally:
        state.conn.close()
    assert "audit_log_immutable=PASS" in sink.getvalue()


def test_writable_audit_restore_fails_the_drill() -> None:
    # NEGATIVE: a restore that came back WRITABLE (no append-only trigger).
    state = build_seeded_state(immutable=False)
    sink = _SINK()
    try:
        with pytest.raises(DrillError):
            assert_audit_log_immutable(
                state.conn,
                checkpoint_max_id=state.checkpoint_max_id,
                checkpoint_row_count=state.checkpoint_row_count,
                stream=sink,
            )
        # The probe DELETE was rolled back — the seeded rows survive.
        cur = state.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_log")
        assert cur.fetchone()[0] == state.checkpoint_row_count
    finally:
        state.conn.close()
    assert "audit_log_immutable=FAIL" in sink.getvalue()


def test_truncated_audit_log_fails_no_truncation_check() -> None:
    # NEGATIVE: a silently TRUNCATED restore (fewer rows than the checkpoint).
    state = build_seeded_state(truncate_audit=True)
    sink = _SINK()
    try:
        with pytest.raises(DrillError):
            assert_audit_log_immutable(
                state.conn,
                checkpoint_max_id=state.checkpoint_max_id,
                checkpoint_row_count=state.checkpoint_row_count,
                stream=sink,
            )
    finally:
        state.conn.close()
    assert "audit_log_immutable=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# (c) Credential separation — fail closed without the KEK.
# ---------------------------------------------------------------------------


def test_credentials_fail_closed_passes_with_and_without_kek() -> None:
    state = build_seeded_state()
    sink = _SINK()
    try:
        assert_credentials_fail_closed(
            state.credential,
            state.credential_aad,
            matching_provider=matching_kek_provider(),
            absent_kek_provider=absent_kek_provider(),
            expected_plaintext=SEED_CREDENTIAL_PLAINTEXT,
            stream=sink,
        )
    finally:
        state.conn.close()
    out = sink.getvalue()
    assert "credentials_fail_closed=PASS" in out
    # The closed path must never print the plaintext anywhere.
    assert SEED_CREDENTIAL_PLAINTEXT.decode() not in out


def test_credential_that_decrypts_without_kek_fails_the_drill() -> None:
    # NEGATIVE: a provider that wrongly DOES supply the row's KEK to the
    # "absent" slot — decryption succeeds without the matching KEK, which is the
    # exfiltration failure the assertion exists to catch. Pass the MATCHING
    # provider in BOTH slots so the "absent" decrypt succeeds.
    state = build_seeded_state()
    sink = _SINK()
    try:
        with pytest.raises(DrillError):
            assert_credentials_fail_closed(
                state.credential,
                state.credential_aad,
                matching_provider=matching_kek_provider(),
                absent_kek_provider=matching_kek_provider(),
                expected_plaintext=SEED_CREDENTIAL_PLAINTEXT,
                stream=sink,
            )
    finally:
        state.conn.close()
    assert "credentials_fail_closed=FAIL" in sink.getvalue()


def test_matching_kek_that_returns_wrong_plaintext_fails() -> None:
    # NEGATIVE: the matching-KEK decrypt must reproduce the EXACT seeded plaintext;
    # a mismatch (the restore lost/corrupted the payload) fails the positive half.
    state = build_seeded_state()
    sink = _SINK()
    try:
        with pytest.raises(DrillError):
            assert_credentials_fail_closed(
                state.credential,
                state.credential_aad,
                matching_provider=matching_kek_provider(),
                absent_kek_provider=absent_kek_provider(),
                expected_plaintext=b"not-the-seeded-password",
                stream=sink,
            )
    finally:
        state.conn.close()
    assert "credentials_fail_closed=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# (d) pgbackrest verify clean.
# ---------------------------------------------------------------------------


def test_pgbackrest_verify_clean_passes() -> None:
    sink = _SINK()
    assert_pgbackrest_verify_clean(lambda: (0, "stanza: netops\n  status: ok\n"), stream=sink)
    assert "pgbackrest_verify_clean=PASS" in sink.getvalue()


def test_pgbackrest_verify_nonzero_fails() -> None:
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_pgbackrest_verify_clean(lambda: (28, "error: repo invalid\n"), stream=sink)
    assert "pgbackrest_verify_clean=FAIL" in sink.getvalue()


def test_pgbackrest_verify_empty_output_fails_closed() -> None:
    # NEGATIVE: a verify that produced NO output proves nothing (L5 non-empty guard).
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_pgbackrest_verify_clean(lambda: (0, "   \n"), stream=sink)
    assert "pgbackrest_verify_clean=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# End-to-end green dry-run (the P1 gate, P1-PLAN.md §6).
# ---------------------------------------------------------------------------


def test_full_drill_green_dry_run_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert run() == 0
    out = capsys.readouterr().out
    for name in (
        "rpo_within_window=PASS",
        "audit_log_immutable=PASS",
        "credentials_fail_closed=PASS",
        "pgbackrest_verify_clean=PASS",
    ):
        assert name in out
    assert "OUTCOME=PASS assertions=4" in out
