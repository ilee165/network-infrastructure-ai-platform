"""pcap spot-restore drill assertions + structured result emission (ADR-0030 §3/§5.4).

These functions are the policy-as-test core of the pcap restore drill. Each takes
the restored-state inputs and either passes or raises :class:`DrillError`. They
REUSE the production retention model — ``app.engines.packet.capture.sha256_file``
for the integrity hash and the ``PcapMetadata.tombstoned_at`` /
``retention_expires_at`` columns the platform purges on — so the drill exercises
the SAME retention decision the platform makes, never a re-implementation
(ADR-0023 §4).

Secure-by-default invariants this module proves (never weaken them):
  * a sampled LIVE capture's restored bytes sha256-MATCH the capture-time hash;
  * a TOMBSTONED (or past-retention) capture is NEVER resurrected — it is absent
    from the restore set, and even if forced in, the metadata-consistency guard
    DROPS it (a tombstoned download 404s post-restore, ADR-0023 §5);
  * the restore is engineer+ GATED (ADR-0023 §5) — a sub-engineer actor is refused.

The structured contract the W5-T5 collector greps for is one composite line per
drill run:
  ``DRILL pcap_spot_restore sampled=<id> sha256=MATCH|MISMATCH
    tombstoned_resurrected=NO|YES result=PASS|FAIL``
plus one ``DRILL pcap_spot_restore <assertion>=PASS|FAIL`` line per assertion.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.models.mixins import utcnow

#: Prefix for the structured result lines the W5-T5 evidence collector greps for.
DRILL_TAG = "DRILL pcap_spot_restore"

#: Role rank ladder (ADR-0023 §5): restore is gated to engineer+. Higher rank =
#: more privilege. The gate compares the actor's rank to the required minimum;
#: this is the ordering only — the authoritative RBAC lives in the app, the drill
#: re-states the ladder to prove the gate bites without a live DB session.
_ROLE_RANK = {"viewer": 0, "operator": 1, "engineer": 2, "admin": 3}


class DrillError(AssertionError):
    """A drill assertion failed — the restore did NOT honor a required property.

    Subclasses :class:`AssertionError` so a failed drill is a hard, un-catchable
    (by a bare ``except Exception``) failure in the Job's ``set -e`` script.
    Carries the assertion name so the emitted ``DRILL`` line names the control.
    """

    def __init__(self, assertion: str, reason: str) -> None:
        self.assertion = assertion
        super().__init__(f"{assertion}: {reason}")


@dataclass(frozen=True, slots=True)
class PcapDrillResult:
    """The composite spot-restore outcome rendered to the W5-T5 evidence line."""

    sampled: str
    sha256_match: bool
    tombstoned_resurrected: bool
    passed: bool

    def line(self) -> str:
        sha = "MATCH" if self.sha256_match else "MISMATCH"
        resurrected = "YES" if self.tombstoned_resurrected else "NO"
        result = "PASS" if self.passed else "FAIL"
        return (
            f"{DRILL_TAG} sampled={self.sampled} sha256={sha} "
            f"tombstoned_resurrected={resurrected} result={result}"
        )


def emit_line(text: str, *, stream: Any = None) -> None:
    """Print one structured line (the W5-T5 G-REL evidence contract).

    ``stream`` defaults to the LIVE ``sys.stdout`` resolved at call time (not at
    import time) so a test harness that swaps ``sys.stdout`` (pytest capsys) or
    the Job's redirected stdout receives the line.
    """
    print(text, file=stream if stream is not None else sys.stdout, flush=True)


@dataclass(frozen=True, slots=True)
class _AssertionLine:
    assertion: str
    passed: bool

    def line(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"{DRILL_TAG} {self.assertion}={status}"


def emit(result: _AssertionLine, *, stream: Any = None) -> None:
    """Emit one per-assertion PASS/FAIL line for the collector."""
    emit_line(result.line(), stream=stream)


@contextmanager
def _timed(assertion: str, *, stream: Any = None) -> Iterator[Callable[[], None]]:
    """Run an assertion, emitting exactly one PASS/FAIL line either way.

    The body calls the yielded ``ok()`` only after every check passed; if it
    raises (a real :class:`DrillError` or any unexpected error) a FAIL line is
    emitted and the error re-raised so the Job fails closed.
    """
    passed = False

    def ok() -> None:
        nonlocal passed
        passed = True

    start = time.monotonic()
    try:
        yield ok
    finally:
        _ = time.monotonic() - start
        emit(_AssertionLine(assertion, passed), stream=stream)


# ---------------------------------------------------------------------------
# (c) engineer+ gate — refuse restore for a sub-engineer actor (ADR-0023 §5).
# ---------------------------------------------------------------------------


def is_authorized(actor_role: str, min_role: str) -> bool:
    """True iff ``actor_role`` ranks at or above ``min_role`` (ADR-0023 §5 gate).

    An unknown role ranks below everything (fail closed) — an unrecognized actor
    must never be treated as privileged.
    """
    actor_rank = _ROLE_RANK.get(actor_role, -1)
    min_rank = _ROLE_RANK.get(min_role, max(_ROLE_RANK.values()) + 1)
    return actor_rank >= min_rank


def assert_restore_authorized(
    actor_role: str,
    *,
    min_role: str = "engineer",
    stream: Any = None,
) -> None:
    """Assert the restoring actor clears the engineer+ gate (ADR-0023 §5).

    The restore must flow only through the existing audited engineer+ path; a
    sub-engineer actor is REFUSED so DR opens no new ungated read to PII/credential-
    bearing payloads. An unknown role fails closed.
    """
    with _timed("restore_authorized", stream=stream) as ok:
        if not is_authorized(actor_role, min_role):
            raise DrillError(
                "restore_authorized",
                f"actor role {actor_role!r} does not clear the required minimum "
                f"{min_role!r} — pcap restore is engineer+ gated (ADR-0023 §5); "
                "DR must not open a new ungated read path",
            )
        ok()


# ---------------------------------------------------------------------------
# (a) sha256-match a sampled LIVE capture against its capture-time hash.
# ---------------------------------------------------------------------------


def assert_sampled_sha256_matches(
    *,
    sampled_capture_id: str,
    expected_sha256: str,
    restored_path: str,
    hasher: Callable[[str], str],
    stream: Any = None,
) -> None:
    """Assert the restored bytes sha256-match the capture-time hash (ADR-0023 §3).

    ``hasher`` is ``app.engines.packet.capture.sha256_file`` (the SAME hash the
    platform records at capture-complete and re-checks on download) — passed in so
    the drill REUSES production integrity code. A mismatch means the restore lost
    or corrupted the payload; an empty recorded hash is a fail-closed condition
    (we cannot prove integrity from a missing reference).
    """
    with _timed("sampled_sha256_matches", stream=stream) as ok:
        if not expected_sha256:
            raise DrillError(
                "sampled_sha256_matches",
                f"capture {sampled_capture_id} has no recorded capture-time sha256 "
                "— cannot prove restore integrity (fail closed, ADR-0023 §3)",
            )
        actual = hasher(restored_path)
        if actual != expected_sha256:
            raise DrillError(
                "sampled_sha256_matches",
                f"restored capture {sampled_capture_id} sha256 {actual} != capture-"
                f"time {expected_sha256} — the restore lost/corrupted the payload "
                "(ADR-0023 §3 integrity)",
            )
        ok()


# ---------------------------------------------------------------------------
# (b) NO RESURRECTION — a tombstoned/expired capture must never come back.
# ---------------------------------------------------------------------------


def is_tombstoned_or_expired(
    *,
    tombstoned_at: datetime | None,
    retention_expires_at: datetime,
    now: datetime | None = None,
) -> bool:
    """True iff a capture is purged: tombstoned OR past its ``retention_expires_at``.

    Mirrors the engine's purge worklist predicate (``expired_capture_ids`` selects
    ``retention_expires_at < now AND tombstoned_at IS NULL``); here a capture is
    "must-not-resurrect" if EITHER it is already tombstoned OR its retention has
    elapsed. The same ``retention_expires_at`` column the platform purges on drives
    this — no second retention literal (ADR-0023 §4 / ADR-0030 §3).
    """
    if tombstoned_at is not None:
        return True
    return retention_expires_at < (now or utcnow())


def assert_no_tombstoned_resurrection(
    *,
    restored_ids: set[str],
    tombstoned_ids: set[str],
    stream: Any = None,
) -> None:
    """Assert NO tombstoned/expired capture appears in the restored set (ADR-0030 §3).

    This is the load-bearing guard: a restore that brings back a tombstoned capture
    silently re-extends a purged credential/PII payload past retention. ``restored_ids``
    is the set actually materialized post-restore (after the metadata-consistency
    drop); ``tombstoned_ids`` is the set the model marked tombstoned/expired. Their
    intersection MUST be empty — any overlap is a resurrection and FAILS the drill.
    """
    with _timed("no_tombstoned_resurrection", stream=stream) as ok:
        resurrected = restored_ids & tombstoned_ids
        if resurrected:
            raise DrillError(
                "no_tombstoned_resurrection",
                f"tombstoned/expired captures {sorted(resurrected)} were RESURRECTED "
                "into the restored set — DR must never re-extend a purged payload's "
                "lifetime past retention (ADR-0030 §3 / ADR-0023 §4/§5)",
            )
        ok()
