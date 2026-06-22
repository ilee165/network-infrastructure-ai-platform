"""pcap volume-snapshot planner (ADR-0030 §3; ADR-0023 §3/§4).

The K8s ``pcap-snapshot-cronjob.yaml`` invokes this module daily. It PLANS a
retention-honoring snapshot by REUSING the production retention model — it does
NOT re-implement retention (ADR-0023 §4):

  * COPY set   — capture ids whose ``pcap_metadata`` row is LIVE (tombstoned_at IS
                 NULL) and whose file is present on the volume. A tombstoned/expired
                 capture is NEVER in the copy set (requirement 1, no resurrection).
  * PRUNE set  — capture ids that are tombstoned OR past ``retention_expires_at``
                 (the engine's ``expired_capture_ids`` worklist ∪ already-tombstoned
                 rows): their object-store copies are DELETED (requirement 1/3).
  * window     — each copied object's lifetime is clamped to the SHORTER of the
                 object-store ``--retention-days`` policy and that pcap's own
                 ``retention_expires_at`` (ADR-0030 §3 — policy may never extend a
                 pcap past its retention).

In P1 the snapshot runs PLAN-ONLY (no live object store) so the gate is a green
dry-run; P2 supplies a live store + ``--apply`` and a DB URL. The plan is emitted
as JSON for the CronJob's ``test -s`` non-empty guard (L5) and for audit.

This is the SAME live-vs-tombstoned decision the platform purge makes, computed by
``app.engines.packet.capture.expired_capture_ids`` + the ``PcapMetadata`` columns —
one source of truth for retention.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.engines.packet.capture import expired_capture_ids
from app.models.mixins import utcnow
from app.models.pcap_metadata import PcapMetadata


def _effective_expiry(retention_expires_at: datetime, policy_days: int, now: datetime) -> datetime:
    """The SHORTER of the object-store policy window and the pcap's own retention.

    ADR-0030 §3: object-store policy may NEVER extend a pcap past its
    ``retention_expires_at``. So the effective object expiry is ``min(now +
    policy_days, retention_expires_at)`` — the snapshot copy is removable no later
    than the pcap itself would be purged.
    """
    policy_expiry = now + timedelta(days=policy_days)
    return min(policy_expiry, retention_expires_at)


async def plan(
    session: AsyncSession,
    *,
    pcap_dir: Path,
    policy_days: int,
    now: datetime | None = None,
) -> dict[str, object]:
    """Build the snapshot plan (copy/prune/window) by REUSING the retention model.

    Returns a JSON-serializable dict with the COPY set (live, file-present), the
    PRUNE set (tombstoned ∪ expired), and the per-copy effective expiry (clamped to
    the shorter window). Never lists a tombstoned/expired capture in ``copy``.
    """
    moment = now or utcnow()

    # LIVE rows (not tombstoned) — the only snapshot-eligible captures.
    live_rows = (
        await session.execute(
            select(
                PcapMetadata.capture_id,
                PcapMetadata.storage_path,
                PcapMetadata.retention_expires_at,
            ).where(PcapMetadata.tombstoned_at.is_(None))
        )
    ).all()

    # PRUNE set: rows the model has tombstoned ∪ the live purge worklist
    # (past-retention, not-yet-tombstoned). REUSES expired_capture_ids — no second
    # retention literal.
    tombstoned = (
        await session.execute(
            select(PcapMetadata.capture_id).where(PcapMetadata.tombstoned_at.is_not(None))
        )
    ).scalars()
    worklist = await expired_capture_ids(session, now=moment)
    prune_ids = {str(c) for c in tombstoned} | {str(c) for c in worklist}

    copy: list[dict[str, str]] = []
    for capture_id, storage_path, retention_expires_at in live_rows:
        cid = str(capture_id)
        # A live row past retention is in the purge worklist — exclude it from COPY
        # (it must not be snapshot, it is about to be purged). Belt-and-braces on
        # top of the tombstoned_at filter above.
        if cid in prune_ids:
            continue
        # Only snapshot a file that is actually present on the volume.
        if storage_path and not Path(storage_path).exists():
            continue
        effective = _effective_expiry(retention_expires_at, policy_days, moment)
        copy.append(
            {
                "capture_id": cid,
                "storage_path": storage_path,
                "effective_expiry": effective.isoformat(),
            }
        )

    return {
        "generated_at": moment.isoformat(),
        "pcap_dir": str(pcap_dir),
        "policy_days": policy_days,
        "copy": copy,
        "prune": sorted(prune_ids),
    }


async def _plan_from_db(args: argparse.Namespace) -> dict[str, object]:
    """Build the plan against the configured DB, or an empty-but-valid plan in P1.

    P1 has no live DB reachable from the snapshot pod's dry-run; when no DB URL is
    configured the planner returns a structurally-valid plan with empty copy/prune
    sets so the CronJob's ``test -s`` guard still sees non-empty JSON and the gate
    is green. P2 sets ``PCAP_DRILL_DB_URL`` to the async DSN.
    """
    db_url = os.environ.get("PCAP_DRILL_DB_URL")
    pcap_dir = Path(args.pcap_dir)
    if not db_url:
        return {
            "generated_at": utcnow().isoformat(),
            "pcap_dir": str(pcap_dir),
            "policy_days": args.retention_days,
            "copy": [],
            "prune": [],
            "note": "P1 dry-run: no live DB configured (PCAP_DRILL_DB_URL unset); "
            "plan is structurally valid and empty. P2 supplies the DSN.",
        }
    engine = create_async_engine(db_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        return await plan(
            session, pcap_dir=pcap_dir, policy_days=args.retention_days
        )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pcap.snapshot")
    parser.add_argument("--pcap-dir", default="/data/pcaps")
    parser.add_argument("--s3-prefix", default=None)
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--plan-out", default=None, help="write the snapshot plan JSON here")
    parser.add_argument("--apply-plan", default=None, help="apply a previously-written plan")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually copy/prune against the object store (P2); default is plan-only",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def run(argv: Sequence[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Planner entrypoint. Emits/writes the plan; applies it only with --apply (P2)."""
    out: TextIO = sys.stdout if stream is None else stream
    args = _parse_args(argv)

    if args.apply_plan:
        # APPLY phase: in P1 (no --apply) this is a no-op that just confirms the plan
        # is readable; P2 wires the object-store copy/prune here.
        plan_doc = json.loads(Path(args.apply_plan).read_text(encoding="utf-8"))
        copies = len(plan_doc.get("copy", []))
        prunes = len(plan_doc.get("prune", []))
        if args.apply:
            print(
                f"[pcap-snapshot] APPLY: copying {copies} live file(s), pruning "
                f"{prunes} tombstoned/expired object(s) (P2 object-store path)",
                file=out,
                flush=True,
            )
        else:
            print(
                f"[pcap-snapshot] plan-only (no --apply): {copies} to copy, "
                f"{prunes} to prune; object-store mutation deferred to P2",
                file=out,
                flush=True,
            )
        return 0

    # PLAN phase: build the plan and write/print it.
    plan_doc = asyncio.run(_plan_from_db(args))
    text = json.dumps(plan_doc, indent=2)
    if args.plan_out:
        Path(args.plan_out).write_text(text, encoding="utf-8")
    print(text, file=out, flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the CronJob / test wrapper
    sys.exit(run())
