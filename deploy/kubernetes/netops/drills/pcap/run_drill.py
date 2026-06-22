"""pcap spot-restore drill entrypoint — restore-then-assert (ADR-0030 §5.4).

The K8s ``pcap-spot-restore-drill-job.yaml`` invokes this module as the assertion
step. In P1 (no hardware / no live object store, P1-PLAN.md §6) it runs against the
seeded fixture (one live + one tombstoned capture) so the gate is a GREEN dry-run;
the P2 annual run points the same assertions at a real restore from the ``pcaps/``
prefix.

It runs the three ADR-0023/§5.4 assertions and emits, for the W5-T5 G-REL
collector, one composite contract line:
  ``DRILL pcap_spot_restore sampled=<id> sha256=MATCH|MISMATCH
    tombstoned_resurrected=NO|YES result=PASS|FAIL``
plus one ``DRILL pcap_spot_restore <assertion>=PASS|FAIL`` per assertion. It exits
non-zero on the first failure (fail closed).

Run:  python -m pcap.run_drill --restore-path <dir> --actor-role engineer ...
      (wired via PYTHONPATH=/app:/app/drills inside the Job image).
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import shutil
import sys
import tempfile
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from app.engines.packet.capture import sha256_file

from .assertions import (
    DRILL_TAG,
    DrillError,
    PcapDrillResult,
    assert_no_tombstoned_resurrection,
    assert_restore_authorized,
    assert_sampled_sha256_matches,
    emit_line,
)
from .fixture import build_seeded_state, live_snapshot_ids, tombstoned_capture_ids


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pcap.run_drill")
    parser.add_argument("--restore-path", default=None, help="throwaway restore scratch dir")
    parser.add_argument("--s3-prefix", default=None, help="pcap object-store prefix (P2)")
    parser.add_argument("--actor-role", default="engineer", help="role requesting the restore")
    parser.add_argument("--min-role", default="engineer", help="minimum role gate (ADR-0023 §5)")
    parser.add_argument("--manifest-out", default=None, help="path to write the restore manifest")
    return parser.parse_args(list(argv) if argv is not None else None)


async def _run_async(args: argparse.Namespace, *, stream: TextIO | None = None) -> int:
    """Restore the seeded fixture to a throwaway dir and run the three assertions.

    Returns ``0`` if every assertion PASSED, ``1`` on the first failure (fail
    closed). The composite ``DRILL pcap_spot_restore ...`` line is emitted with the
    sampled id and the MATCH/NO outcome either way so the W5-T5 collector always
    sees a result.
    """
    # (c) engineer+ gate FIRST — refuse a sub-engineer actor BEFORE any restore I/O
    # or manifest materialization (ADR-0023 §5). An unauthorized actor must trigger
    # ZERO side effects: no scratch dir, no file copy, no manifest write. We emit the
    # gated FAIL line and fail closed before touching disk.
    try:
        assert_restore_authorized(args.actor_role, min_role=args.min_role, stream=stream)
    except DrillError as exc:
        emit_line(
            PcapDrillResult(
                "unauthorized", sha256_match=False, tombstoned_resurrected=False, passed=False
            ).line(),
            stream=stream,
        )
        emit_line(f"{DRILL_TAG} OUTCOME=FAIL failed_assertion={exc.assertion}", stream=stream)
        return 1

    restore_root = Path(args.restore_path) if args.restore_path else Path(tempfile.mkdtemp())
    pcap_src = restore_root / "src-pcaps"
    restored = restore_root / "restored"
    restored.mkdir(parents=True, exist_ok=True)

    state = await build_seeded_state(pcap_src, min_role=args.min_role)
    sampled = str(state.live_capture_id)

    # Compute the snapshot/restore sets by REUSING the model (live-vs-tombstoned).
    live_ids = await live_snapshot_ids(state)
    tombstoned_ids = await tombstoned_capture_ids(state)

    # Materialize the restore: ONLY live, non-tombstoned captures are copied into
    # the throwaway restored/ dir — the tombstoned capture is never written (the
    # snapshot skipped it and the prune removed any copy). This models the
    # metadata-consistency drop the real restore performs.
    restored_ids: set[str] = set()
    for cid in live_ids:
        if cid in tombstoned_ids:
            continue  # belt-and-braces: a tombstoned id never enters the restore set.
        src = Path(state.live_pcap_path) if cid == state.live_capture_id else None
        if src is not None and src.exists():
            dst = restored / f"{cid}.pcap"
            shutil.copyfile(src, dst)
            restored_ids.add(str(cid))

    manifest = {
        "sampled": sampled,
        "restored": sorted(restored_ids),
        "tombstoned": sorted(str(c) for c in tombstoned_ids),
        "actor_role": args.actor_role,
        "min_role": args.min_role,
    }
    if args.manifest_out:
        Path(args.manifest_out).write_text(json.dumps(manifest), encoding="utf-8")

    sha_match = False
    resurrected = False
    try:
        # (c) authorization is already enforced ABOVE, before any restore I/O.
        # (a) the sampled LIVE capture's restored bytes sha256-match (ADR-0023 §3).
        restored_sample = restored / f"{sampled}.pcap"
        assert_sampled_sha256_matches(
            sampled_capture_id=sampled,
            expected_sha256=state.live_sha256,
            restored_path=str(restored_sample),
            hasher=sha256_file,
            stream=stream,
        )
        sha_match = True

        # (b) NO tombstoned/expired capture was resurrected (ADR-0030 §3).
        assert_no_tombstoned_resurrection(
            restored_ids=restored_ids,
            tombstoned_ids={str(c) for c in tombstoned_ids},
            stream=stream,
        )
        # If any tombstoned id had leaked into restored_ids the assertion would have
        # raised; reaching here means none did.
        resurrected = bool(restored_ids & {str(c) for c in tombstoned_ids})

        # Negative self-check (proves the no-resurrection guard BITES): forcing the
        # tombstoned id into the restore set MUST raise. We run it on a copy so the
        # real result is unaffected; a guard that does NOT raise here is itself a
        # failed drill (the assertion is too weak).
        _assert_guard_bites(tombstoned_ids, stream=stream)
    except DrillError as exc:
        emit_line(
            PcapDrillResult(sampled, sha_match, resurrected, passed=False).line(),
            stream=stream,
        )
        emit_line(f"{DRILL_TAG} OUTCOME=FAIL failed_assertion={exc.assertion}", stream=stream)
        return 1

    emit_line(
        PcapDrillResult(sampled, sha256_match=True, tombstoned_resurrected=False, passed=True).line(),
        stream=stream,
    )
    emit_line(f"{DRILL_TAG} OUTCOME=PASS assertions=3", stream=stream)
    return 0


def _assert_guard_bites(
    tombstoned_ids: set[uuid.UUID], *, stream: TextIO | None = None
) -> None:
    """The no-resurrection guard MUST raise when a tombstoned id is in the set.

    A drill whose guard is too weak silently passes a broken restore (ADR-0030 §3
    risk note). This forces the failure case and requires it to raise; if it does
    NOT, the guard is broken and the drill fails closed.
    """
    if not tombstoned_ids:
        raise DrillError(
            "guard_self_check",
            "fixture seeded no tombstoned capture — the no-resurrection guard cannot "
            "be exercised; a drill that cannot prove the guard bites is not a drill",
        )
    forced = {str(c) for c in tombstoned_ids}
    # Emit the synthetic probe's FAIL line into a THROWAWAY sink, not the real
    # contract stream — the W5-T5 collector must never see this self-check's line.
    silent = io.StringIO()
    try:
        assert_no_tombstoned_resurrection(
            restored_ids=forced,
            tombstoned_ids=forced,
            stream=silent,
        )
    except DrillError:
        return  # correct: the guard bit on the forced resurrection.
    raise DrillError(
        "guard_self_check",
        "the no-resurrection guard did NOT raise when a tombstoned capture was "
        "forced into the restored set — the guard is too weak (ADR-0030 §3)",
    )


def run(argv: Sequence[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Sync wrapper around the async drill (the module entrypoint)."""
    args = _parse_args(argv)
    # Authorization is enforced inside `_run_async` BEFORE any restore I/O (an
    # unauthorized actor triggers zero side effects), so no pre-check is needed here.
    return asyncio.run(_run_async(args, stream=stream))


if __name__ == "__main__":  # pragma: no cover - exercised via the Job / test wrapper
    sys.exit(run())
