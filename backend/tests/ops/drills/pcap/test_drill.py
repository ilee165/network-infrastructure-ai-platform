"""pcap spot-restore drill harness tests — positive PASS + a NEGATIVE per assertion.

These prove the assertions actually BITE (ADR-0030 §3 risk note): a drill whose
checks are too weak silently passes a broken restore that resurrects a purged
payload. For every property there is a tampered-input case that MUST raise
:class:`DrillError`:

  * no-resurrection — a tombstoned capture forced into the restored set must fail.
  * sha256-match    — a corrupted restored file (wrong bytes) must fail.
  * engineer+ gate  — a sub-engineer actor must be refused.
  * snapshot plan   — the planner must EXCLUDE a tombstoned capture from COPY and
                      INCLUDE it in PRUNE (the live-vs-tombstoned decision, reused
                      from the model).

Run from ``backend/`` with the project virtualenv:
  python -m pytest tests/ops/drills/pcap/test_drill.py -q
"""

from __future__ import annotations

import asyncio
import io
from datetime import UTC, datetime, timedelta

import pytest

from app.engines.packet.capture import sha256_file
from app.ops.drills.pcap.assertions import (
    DrillError,
    PcapDrillResult,
    assert_no_tombstoned_resurrection,
    assert_restore_authorized,
    assert_sampled_sha256_matches,
    is_authorized,
)
from app.ops.drills.pcap.fixture import (
    build_seeded_state,
    live_snapshot_ids,
    tombstoned_capture_ids,
)
from app.ops.drills.pcap.run_drill import run
from app.ops.drills.pcap.snapshot import _effective_expiry, plan
from app.ops.drills.pcap.snapshot import run as snapshot_run

_SINK = io.StringIO  # fresh stream per assertion so emitted lines don't interleave.


# ---------------------------------------------------------------------------
# Structured-line contract (W5-T5 evidence consumer).
# ---------------------------------------------------------------------------


def test_composite_result_line_is_the_t5_contract() -> None:
    line = PcapDrillResult(
        "abc-123", sha256_match=True, tombstoned_resurrected=False, passed=True
    ).line()
    assert line == (
        "DRILL pcap_spot_restore sampled=abc-123 sha256=MATCH tombstoned_resurrected=NO result=PASS"
    )
    fail = PcapDrillResult(
        "def-456", sha256_match=False, tombstoned_resurrected=True, passed=False
    ).line()
    assert fail == (
        "DRILL pcap_spot_restore sampled=def-456 sha256=MISMATCH "
        "tombstoned_resurrected=YES result=FAIL"
    )


# ---------------------------------------------------------------------------
# (c) engineer+ gate (ADR-0023 §5).
# ---------------------------------------------------------------------------


def test_engineer_clears_the_gate() -> None:
    sink = _SINK()
    assert_restore_authorized("engineer", min_role="engineer", stream=sink)
    assert "restore_authorized=PASS" in sink.getvalue()


def test_admin_clears_the_gate() -> None:
    sink = _SINK()
    assert_restore_authorized("admin", min_role="engineer", stream=sink)
    assert "restore_authorized=PASS" in sink.getvalue()


def test_sub_engineer_actor_is_refused() -> None:
    # NEGATIVE: an operator/viewer must NOT be able to restore (ADR-0023 §5).
    for role in ("operator", "viewer"):
        sink = _SINK()
        with pytest.raises(DrillError):
            assert_restore_authorized(role, min_role="engineer", stream=sink)
        assert "restore_authorized=FAIL" in sink.getvalue()


def test_unknown_role_fails_closed() -> None:
    assert is_authorized("nope", "engineer") is False


# ---------------------------------------------------------------------------
# (a) sha256-match (ADR-0023 §3).
# ---------------------------------------------------------------------------


def test_sha256_matches_on_intact_restore(tmp_path) -> None:
    f = tmp_path / "cap.pcap"
    f.write_bytes(b"intact-restored-bytes")
    digest = sha256_file(f)
    sink = _SINK()
    assert_sampled_sha256_matches(
        sampled_capture_id="cap",
        expected_sha256=digest,
        restored_path=str(f),
        hasher=sha256_file,
        stream=sink,
    )
    assert "sampled_sha256_matches=PASS" in sink.getvalue()


def test_corrupted_restore_fails_sha256(tmp_path) -> None:
    # NEGATIVE: the restored bytes differ from the capture-time hash.
    f = tmp_path / "cap.pcap"
    f.write_bytes(b"corrupted-restored-bytes")
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_sampled_sha256_matches(
            sampled_capture_id="cap",
            expected_sha256="a" * 64,  # not the file's real hash.
            restored_path=str(f),
            hasher=sha256_file,
            stream=sink,
        )
    assert "sampled_sha256_matches=FAIL" in sink.getvalue()


def test_missing_capture_hash_fails_closed(tmp_path) -> None:
    f = tmp_path / "cap.pcap"
    f.write_bytes(b"bytes")
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_sampled_sha256_matches(
            sampled_capture_id="cap",
            expected_sha256="",  # no recorded hash → cannot prove integrity.
            restored_path=str(f),
            hasher=sha256_file,
            stream=sink,
        )
    assert "sampled_sha256_matches=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# (b) NO resurrection (ADR-0030 §3) — the load-bearing guard.
# ---------------------------------------------------------------------------


def test_no_resurrection_passes_when_sets_disjoint() -> None:
    sink = _SINK()
    assert_no_tombstoned_resurrection(
        restored_ids={"live-1", "live-2"},
        tombstoned_ids={"dead-1"},
        stream=sink,
    )
    assert "no_tombstoned_resurrection=PASS" in sink.getvalue()


def test_resurrected_tombstone_fails_the_drill() -> None:
    # NEGATIVE: a tombstoned capture present in the restored set is a resurrection.
    sink = _SINK()
    with pytest.raises(DrillError):
        assert_no_tombstoned_resurrection(
            restored_ids={"live-1", "dead-1"},
            tombstoned_ids={"dead-1"},
            stream=sink,
        )
    assert "no_tombstoned_resurrection=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# Fixture + model reuse: live-vs-tombstoned (ADR-0023 §4).
# ---------------------------------------------------------------------------


def test_fixture_snapshot_excludes_tombstoned(tmp_path) -> None:
    # Sync wrapper (matches the postgres_pitr convention — no async-plugin
    # dependency when run from the repo root without the backend pytest config).
    async def _body() -> None:
        state = await build_seeded_state(tmp_path / "pcaps")
        live = await live_snapshot_ids(state)
        dead = await tombstoned_capture_ids(state)
        # The live capture is snapshot-eligible; the tombstoned one is not.
        assert state.live_capture_id in live
        assert state.tombstoned_capture_id not in live
        # The tombstoned one is in the must-not-resurrect set.
        assert state.tombstoned_capture_id in dead
        assert state.live_capture_id not in dead

    asyncio.run(_body())


def test_snapshot_planner_excludes_tombstoned_from_copy(tmp_path) -> None:
    # The planner COPY set must contain the live id and the PRUNE set the tombstoned.
    async def _body() -> None:
        state = await build_seeded_state(tmp_path / "pcaps")
        async with state.sessionmaker() as session:
            doc = await plan(session, pcap_dir=tmp_path / "pcaps", policy_days=30)
        copy_ids = {row["capture_id"] for row in doc["copy"]}
        assert str(state.live_capture_id) in copy_ids
        assert str(state.tombstoned_capture_id) not in copy_ids
        assert str(state.tombstoned_capture_id) in set(doc["prune"])
        # The effective expiry is clamped to the SHORTER of policy vs retention.
        live_row = next(r for r in doc["copy"] if r["capture_id"] == str(state.live_capture_id))
        assert "effective_expiry" in live_row

    asyncio.run(_body())


# ---------------------------------------------------------------------------
# Requirement 3 (load-bearing): window = SHORTER OF (object-store policy) and the
# pcap's retention_expires_at — object-store policy may NEVER extend a pcap past
# its own retention (ADR-0030 §3). The clamp must be exercised with DIVERGENT
# values in BOTH directions, else a prune bug silently extends payload lifetime.
# ---------------------------------------------------------------------------


def test_effective_expiry_clamps_to_retention_when_retention_is_shorter() -> None:
    # retention_expires_at = now + 5d under policy_days=30 → retention is the SHORTER
    # window, so policy must NOT extend the copy past the pcap's own retention.
    now = datetime(2026, 1, 1, tzinfo=UTC)
    retention = now + timedelta(days=5)
    effective = _effective_expiry(retention, policy_days=30, now=now)
    assert effective == retention
    # Proof the policy window (now+30d) was the LONGER value that got rejected.
    assert effective < now + timedelta(days=30)


def test_effective_expiry_clamps_to_policy_when_policy_is_shorter() -> None:
    # Inverse: retention far in the future (now+90d), policy_days=30 → policy is the
    # SHORTER window, so the copy expires at now+policy_days, not at retention.
    now = datetime(2026, 1, 1, tzinfo=UTC)
    retention = now + timedelta(days=90)
    effective = _effective_expiry(retention, policy_days=30, now=now)
    assert effective == now + timedelta(days=30)
    assert effective < retention


def test_planner_effective_expiry_is_retention_when_retention_is_shorter(tmp_path) -> None:
    # End-to-end through plan(): a live capture whose retention_expires_at is strictly
    # earlier than now+policy_days must surface effective_expiry == retention_expires_at
    # in the COPY row (policy cannot extend it). This is the prune-bug guardrail the
    # spec's Risks section names.
    async def _body() -> None:
        state = await build_seeded_state(tmp_path / "pcaps")
        # Shrink the live capture's retention to now+5d so it is strictly shorter than
        # the 30-day policy below, then re-plan.
        async with state.sessionmaker() as session:
            from sqlalchemy import select, update

            from app.models.mixins import utcnow
            from app.models.pcap_metadata import PcapMetadata

            now = utcnow()
            short_retention = now + timedelta(days=5)
            await session.execute(
                update(PcapMetadata)
                .where(PcapMetadata.capture_id == state.live_capture_id)
                .values(retention_expires_at=short_retention)
            )
            await session.commit()
            row = (
                await session.execute(
                    select(PcapMetadata.retention_expires_at).where(
                        PcapMetadata.capture_id == state.live_capture_id
                    )
                )
            ).scalar_one()

            doc = await plan(session, pcap_dir=tmp_path / "pcaps", policy_days=30, now=now)
        live_row = next(r for r in doc["copy"] if r["capture_id"] == str(state.live_capture_id))
        # effective_expiry equals the (shorter) retention, NOT now+30d policy.
        assert live_row["effective_expiry"] == row.isoformat()
        assert datetime.fromisoformat(live_row["effective_expiry"]) < now + timedelta(days=30)

    asyncio.run(_body())


# ---------------------------------------------------------------------------
# End-to-end green dry-run (the P1 gate, P1-PLAN.md §6).
# ---------------------------------------------------------------------------


def test_full_drill_green_dry_run_exits_zero(tmp_path, capsys) -> None:
    rc = run(
        [
            "--restore-path",
            str(tmp_path / "restore"),
            "--actor-role",
            "engineer",
            "--min-role",
            "engineer",
            "--manifest-out",
            str(tmp_path / "manifest.json"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "restore_authorized=PASS" in out
    assert "sampled_sha256_matches=PASS" in out
    assert "no_tombstoned_resurrection=PASS" in out
    assert "sha256=MATCH" in out
    assert "tombstoned_resurrected=NO" in out
    assert "result=PASS" in out
    assert "OUTCOME=PASS assertions=3" in out


def test_full_drill_refuses_sub_engineer_actor(tmp_path, capsys) -> None:
    # NEGATIVE end-to-end: an operator actor fails the gated assertion → exit 1.
    rc = run(
        [
            "--restore-path",
            str(tmp_path / "restore"),
            "--actor-role",
            "operator",
            "--min-role",
            "engineer",
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "restore_authorized=FAIL" in out
    assert "OUTCOME=FAIL" in out


def test_unauthorized_actor_triggers_no_restore_side_effects(tmp_path, capsys) -> None:
    # The engineer+ gate runs BEFORE any restore I/O / manifest materialization: an
    # unauthorized actor must produce ZERO side effects — no manifest written and no
    # restored/ scratch tree created (authorize-before-side-effect; ADR-0023 §5).
    restore_path = tmp_path / "restore"
    manifest_path = tmp_path / "manifest.json"
    rc = run(
        [
            "--restore-path",
            str(restore_path),
            "--actor-role",
            "viewer",
            "--min-role",
            "engineer",
            "--manifest-out",
            str(manifest_path),
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "restore_authorized=FAIL" in out
    assert "OUTCOME=FAIL" in out
    # No restore materialization happened: the manifest was never written and the
    # restored/ scratch dir was never created.
    assert not manifest_path.exists()
    assert not (restore_path / "restored").exists()


# ---------------------------------------------------------------------------
# Fail-closed empty-plan guard (ADR-0030 §3): a missing DSN with no explicit
# dry-run must FAIL the snapshot (non-zero, no plan file) — never a green empty
# snapshot of nothing. The `test -s` file-size guard alone is tautological because
# the planner always wrote a structurally-valid empty doc; the real guard is here.
# ---------------------------------------------------------------------------


def test_snapshot_fails_closed_when_dsn_unset_and_not_dry_run(tmp_path, monkeypatch) -> None:
    # No DB DSN and PCAP_SNAPSHOT_DRY_RUN unset → the planner must FAIL CLOSED
    # (rc != 0) and write NO plan file, so the job cannot pass as a green no-op.
    monkeypatch.delenv("PCAP_DRILL_DB_URL", raising=False)
    monkeypatch.delenv("PCAP_SNAPSHOT_DRY_RUN", raising=False)
    plan_out = tmp_path / "plan.json"
    rc = snapshot_run(["--pcap-dir", str(tmp_path / "pcaps"), "--plan-out", str(plan_out)])
    assert rc == 1
    assert not plan_out.exists()


def test_snapshot_dry_run_allows_empty_plan_when_dsn_unset(tmp_path, monkeypatch) -> None:
    # No DSN but PCAP_SNAPSHOT_DRY_RUN explicitly set → the P1 dry-run path: an
    # empty structurally-valid plan is emitted (rc 0) and the plan file is written.
    monkeypatch.delenv("PCAP_DRILL_DB_URL", raising=False)
    monkeypatch.setenv("PCAP_SNAPSHOT_DRY_RUN", "1")
    plan_out = tmp_path / "plan.json"
    rc = snapshot_run(["--pcap-dir", str(tmp_path / "pcaps"), "--plan-out", str(plan_out)])
    assert rc == 0
    assert plan_out.exists()
    import json as _json

    doc = _json.loads(plan_out.read_text(encoding="utf-8"))
    assert doc["copy"] == []
    assert doc["prune"] == []
