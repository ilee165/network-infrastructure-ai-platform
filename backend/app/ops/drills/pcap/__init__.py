"""pcap volume-snapshot + spot-restore drill harness (P1 W5-T4, ADR-0030 §3/§5.4).

This package is the policy-as-test core of the pcap DR tier. The K8s
``pcap-snapshot-cronjob.yaml`` invokes :mod:`app.ops.drills.pcap.snapshot` to
PLAN/APPLY the daily snapshot; ``pcap-spot-restore-drill-job.yaml`` invokes
:mod:`app.ops.drills.pcap.run_drill`
to run the annual spot-restore assertions. Both REUSE the production retention
model — ``app.models.pcap_metadata.PcapMetadata`` and the engine helpers
``expired_capture_ids`` / ``tombstone_capture`` / ``sha256_file`` plus the
``retention_expires_at`` column — so the DR path NEVER re-implements retention
(ADR-0023 §4): a tombstoned/expired capture is decided by the same code the
platform purges with.

The HARD constraint (ADR-0030 §3, the load-bearing requirement): DR HONORS — never
subverts — the ADR-0023 retention contract.
  * the SNAPSHOT captures ONLY live (non-tombstoned) files, prunes object-store
    copies of tombstoned/expired rows, and clamps each file's window to the SHORTER
    of (object-store policy) and its ``retention_expires_at``;
  * the RESTORE is metadata-consistent: a sampled LIVE capture sha256-matches its
    capture-time hash, and a TOMBSTONED capture is NEVER resurrected (it 404s
    post-restore), and the restore is engineer+ gated (ADR-0023 §5).

Each drill assertion emits one structured line for the W5-T5 G-REL collector:
``DRILL pcap_spot_restore sampled=<id> sha256=MATCH|MISMATCH
tombstoned_resurrected=NO|YES result=PASS|FAIL``.

SECRET-SURFACE: captured packet data is the most sensitive artifact class. The
no-resurrection guard (b) and the engineer+ gate (c) are the core invariants and
are never weakened — a tombstoned capture must never come back, and a sub-engineer
actor must never restore.
"""

from __future__ import annotations

from .assertions import (
    DrillError,
    PcapDrillResult,
    assert_no_tombstoned_resurrection,
    assert_restore_authorized,
    assert_sampled_sha256_matches,
    emit,
)

__all__ = [
    "DrillError",
    "PcapDrillResult",
    "assert_no_tombstoned_resurrection",
    "assert_restore_authorized",
    "assert_sampled_sha256_matches",
    "emit",
]
