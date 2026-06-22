"""Full-platform DR drill orchestrator — chain the three tiers + aggregate (W5-T5).

The K8s ``full-platform-dr-drill-job.yaml`` invokes this module AFTER the shell
script has restored Postgres from the object-store repo ALONE into a THROWAWAY
target (the W5-T2 restore step). This orchestrator then runs the three per-tier
ASSERTION harnesses IN CHAIN ORDER:

  1. ``postgres_pitr.run_drill``      — assert the object-store-alone restore
  2. ``topology_rebuild.run_drill``   — rebuild Neo4j over the RESTORED Postgres
  3. ``pcap.run_drill``               — spot-restore pcaps, retention-honoring

It captures each tier's structured ``DRILL ...`` lines, AGGREGATES them via the
collector (W5-T5 requirement 2: aggregate, don't re-implement), measures the
end-to-end RPO/RTO wall-clock, and emits the composite
``DRILL full_platform ...`` line for the G-REL evidence doc. It exits non-zero if
ANY tier failed or produced no terminal verdict (fail closed).

In P1 (no hardware, P1-PLAN.md §6) every tier runs its seeded dry-run, so the
gate is a GREEN end-to-end dry-run at seeded scale; the certified-scale,
clean-cluster run is P2 (ADR-0030 §6). The chain ALWAYS runs all three tiers even
if an earlier one fails, so the evidence table records every tier's measured
result (a partial DR drill that stopped at tier 1 hides where the real gap is).

Run:  python -m full_platform.run_drill --rpo-window-minutes 5 --rto-minutes 60 \
        --topology-rto-minutes 30
      (wired via PYTHONPATH=/app:/app/drills inside the Job image).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
import time
from collections.abc import Sequence
from typing import TextIO

from .collector import DrillEvidence, collect, write_report


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="full_platform.run_drill")
    parser.add_argument(
        "--rpo-window-minutes",
        type=float,
        default=float(os.environ.get("DRILL_RPO_WINDOW_MINUTES", "5")),
        help="PROPOSED RPO window (minutes) the Postgres tier asserts WAL-replay within.",
    )
    parser.add_argument(
        "--rto-minutes",
        type=float,
        default=float(os.environ.get("DRILL_RTO_MINUTES", "60")),
        help="PROPOSED end-to-end RTO budget (minutes) for the whole DR chain.",
    )
    parser.add_argument(
        "--topology-rto-minutes",
        type=float,
        default=float(os.environ.get("TOPOLOGY_RTO_MINUTES", "30")),
        help="PROPOSED topology-RTO budget (minutes) the Neo4j tier asserts against.",
    )
    parser.add_argument(
        "--actor-role",
        default=os.environ.get("DRILL_ACTOR_ROLE", "engineer"),
        help="role requesting the pcap restore (ADR-0023 §5 gate).",
    )
    parser.add_argument(
        "--min-role",
        default=os.environ.get("DRILL_MIN_ROLE", "engineer"),
        help="minimum role gate for the pcap restore.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _run_tier(label: str, fn, *args, **kwargs) -> tuple[int, str]:
    """Run one tier's ``run(...)`` entrypoint, capturing its stdout.

    Each tier writes its ``DRILL ...`` lines to stdout (or an injected stream); we
    capture them so the collector can aggregate. Returns (exit_code, captured_text).
    An exception INSIDE a tier is captured as a failure (the chain still continues
    so the other tiers' evidence is recorded), never propagated as an orchestrator
    crash that would hide the partial table.
    """
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            code = fn(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive; a tier should fail-close itself
        buf.write(f"DRILL {label} OUTCOME=FAIL failed_assertion=tier_raised:{type(exc).__name__}\n")
        code = 1
    return code, buf.getvalue()


def run(argv: Sequence[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Run the full DR chain at seeded scale; return a process exit code.

    Returns ``0`` only if EVERY tier passed; ``1`` if any tier failed or produced
    no terminal verdict (fail closed). Always runs all three tiers so the evidence
    table is complete.
    """
    args = _parse_args(argv)
    out = stream if stream is not None else sys.stdout

    # Import the per-tier entrypoints lazily so a slim host that can run only one
    # tier (e.g. topology_rebuild without app DB deps) still imports this module.
    from postgres_pitr.run_drill import run as run_postgres
    from topology_rebuild.run_drill import run as run_neo4j
    from pcap.run_drill import run as run_pcap

    chain_start = time.monotonic()
    captured: list[str] = []

    # --- Tier 1: Postgres PITR restore from object storage ALONE (the RPO tier). ---
    pg_start = time.monotonic()
    _, pg_out = _run_tier(
        "postgres_pitr",
        run_postgres,
        rpo_window_seconds=args.rpo_window_minutes * 60.0,
    )
    rpo_seconds = time.monotonic() - pg_start
    captured.append(pg_out)
    print(pg_out, end="", file=out)

    # --- Tier 2: Neo4j rebuild over the RESTORED Postgres (the topology-RTO tier). ---
    _, neo_out = _run_tier(
        "neo4j_rebuild",
        run_neo4j,
        ["--rto-seconds", str(args.topology_rto_minutes * 60.0)],
    )
    captured.append(neo_out)
    print(neo_out, end="", file=out)

    # --- Tier 3: pcap spot-restore (retention-honoring; engineer+ gated). ---
    _, pcap_out = _run_tier(
        "pcap_spot_restore",
        run_pcap,
        ["--actor-role", args.actor_role, "--min-role", args.min_role],
    )
    captured.append(pcap_out)
    print(pcap_out, end="", file=out)

    rto_seconds = time.monotonic() - chain_start

    # --- Aggregate (do NOT re-assert): parse every tier's DRILL line into the table.
    evidence: DrillEvidence = collect("\n".join(captured))
    evidence.rpo_seconds = rpo_seconds
    evidence.rto_seconds = rto_seconds
    # Wire the --rto-minutes budget into the aggregate verdict: a chain that passed
    # every tier but exceeded the end-to-end RTO target FAILS the drill (ADR-0030
    # §6 G-REL — passing tiers is necessary but not sufficient).
    evidence.rto_budget_seconds = args.rto_minutes * 60.0
    write_report(evidence, stream=out)

    return 0 if evidence.passed else 1


if __name__ == "__main__":  # pragma: no cover - exercised via the Job / test wrapper
    sys.exit(run())
