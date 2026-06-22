# P1 W5 — G-REL Evidence: full-platform DR drill (from backups alone)

| | |
|---|---|
| **Gate** | G-REL — "DR drill from backups alone, onto a clean cluster" (PRODUCTION.md §11) |
| **Wave / task** | P1 W5-T5 (composes W5-T1..T4) |
| **ADRs** | ADR-0030 §5.3/§6, ADR-0005 D5, ADR-0011 §1/§2, ADR-0023 §3/§4/§5 |
| **Status** | P1 seeded dry-run **GREEN**; certified-scale clean-cluster run **deferred to P2** |
| **Targets** | **PROPOSED** (per A2/Q2) — pending the **Consultant §12** answer; see re-base flag below |

> **PROPOSED-TARGET RE-BASE FLAG (Consultant §12).** Every RPO / RTO / topology-RTO
> number below is measured against a **PROPOSED** target (ADR-0030 §6; PRODUCTION.md
> §11 "PROPOSED targets per A2/Q2 until Consultant answer"). When the Consultant §12
> answer lands, re-base the three knobs from their single sources of truth —
> `backup.postgres.wal.proposedRpoMinutes` (RPO), `backup.drills.fullPlatform.proposedRtoMinutes`
> (end-to-end RTO), `backup.drills.neo4j.proposedRtoMinutes` (topology-RTO) — and
> regenerate this evidence. The drill harnesses read those knobs directly (no
> drill-local literal), so a re-base needs no code change, only a values edit + a
> re-run. **This doc is the single place that flag is surfaced for re-base.**

## What was proven (P1)

The full-platform DR drill (`netops-full-platform-dr-drill`) restores Postgres from
the object-store repo **alone** onto a clean target (throwaway `emptyDir` scratch —
no live PVC mounted), then **chains** the three per-tier drills end-to-end and
**aggregates** their structured `DRILL …` lines (it does not re-implement any
per-tier assertion — ADR-0030 §5.3 requirement 2):

1. **Postgres PITR** (W5-T2) — restore from object storage alone; assert RPO-in-window,
   audit-log immutability, credentials-fail-closed-without-KEK, `pgbackrest verify`.
2. **Neo4j rebuild** (W5-T3) — re-project the whole topology over the **restored**
   Postgres (not a graph dump — ADR-0005 D5); assert counts-match + topology-RTO.
3. **pcap spot-restore** (W5-T4) — restore sampled captures; sha256-verify a live
   sample; prove no tombstoned capture is resurrected; engineer+ gated.

This is the D5 story end-to-end: **one authoritative thing to restore (Postgres) +
one thing to rebuild (the Neo4j projection)**, with pcaps spot-restored
retention-honoring — all from object storage, with no surviving live state.

## Measured vs PROPOSED — seeded dry-run (P1, no hardware)

Numbers are the aggregated output of `python -m full_platform.run_drill` over the
T1–T4 seeded fixtures (the gate is a green dry-run at seeded scale; P1-PLAN.md §6).

| Metric | PROPOSED target | Measured (seeded) | Within target? |
|---|---|---|---|
| **RPO** (WAL-replay window) | ≤ 5 min (300 s) | ~0.007 s (seeded fixture lag) | ✅ |
| **RTO** (end-to-end recovery) | ≤ 1 h (3 600 s) | ~0.86 s (seeded chain wall-clock) | ✅ |
| **Topology-RTO** (Neo4j rebuild) | < 30 min @ 5 000 devices (1 800 s) | 2.000 s (seeded 42-node / 57-edge projection) | ✅ |

> **Seeded-scale caveat (do NOT over-read).** These wall-clock numbers are the
> seeded-fixture dry-run, NOT production scale. They prove the *mechanism* (restore
> → rebuild → spot-restore, end-to-end, from backups alone) and that the assertions
> bite — they do **not** prove the PROPOSED targets hold at 5 000 devices. The
> certified-scale, genuinely-clean-cluster run is **P2** (see below).

## Aggregated per-tier results (the collector's table)

The evidence collector (`full_platform.collector`) parses each tier's `DRILL …`
lines into this table — the single source of measured numbers:

| Tier | Assertions | Topology-RTO (s) | Result |
|---|---|---|---|
| Postgres PITR (object-store-alone restore) | rpo_within_window=PASS, audit_log_immutable=PASS, credentials_fail_closed=PASS, pgbackrest_verify_clean=PASS | — | **PASS** |
| Neo4j rebuild (re-project over RESTORED Postgres) | rto_within_target=PASS, counts_match=PASS | 2.000 | **PASS** |
| pcap spot-restore (retention-honoring) | restore_authorized=PASS, sampled_sha256_matches=PASS, no_tombstoned_resurrection=PASS | — | **PASS** |

Composite end-to-end verdict line (the single grep target for the rolled-up result):

```
DRILL full_platform tiers=3 passed=3 rpo_s=0.007 rto_s=0.860 topology_rto_s=2.000 result=PASS
```

(`rpo_s` / `rto_s` vary by run — they are the seeded wall-clock, well inside the
PROPOSED windows; `topology_rto_s` is the deterministic seeded projection time.)

## Per-tier source-of-truth `DRILL …` lines

Reproduce locally (from the backend venv so `app.*` resolves):

```
PYTHONPATH=backend:deploy/kubernetes/netops/drills \
  python -m full_platform.run_drill \
    --rpo-window-minutes 5 --rto-minutes 60 --topology-rto-minutes 30
```

```
DRILL postgres_pitr rpo_within_window=PASS duration_s=<n>
DRILL postgres_pitr audit_log_immutable=PASS duration_s=<n>
DRILL postgres_pitr credentials_fail_closed=PASS duration_s=<n>
DRILL postgres_pitr pgbackrest_verify_clean=PASS duration_s=<n>
DRILL postgres_pitr OUTCOME=PASS assertions=4
DRILL neo4j_rebuild rto_within_target=PASS
DRILL neo4j_rebuild counts_match=PASS
DRILL neo4j_rebuild seconds=2.000 nodes=42 edges=57 result=PASS
DRILL neo4j_rebuild OUTCOME=PASS assertions=2
DRILL pcap_spot_restore restore_authorized=PASS
DRILL pcap_spot_restore sampled_sha256_matches=PASS
DRILL pcap_spot_restore no_tombstoned_resurrection=PASS
DRILL pcap_spot_restore sampled=<id> sha256=MATCH tombstoned_resurrected=NO result=PASS
DRILL pcap_spot_restore OUTCOME=PASS assertions=3
DRILL full_platform tiers=3 passed=3 rpo_s=<n> rto_s=<n> topology_rto_s=<n> result=PASS
```

## DR runbooks (Documentation Agent dogfooding)

The four DR runbooks are **generated** (ADR-0030 §5 / PRODUCTION.md §8 dogfooding),
not hand-maintained, by `full_platform.runbook` (deterministic / no-LLM — the same
"output matches source content exactly by construction" mode as the Documentation
Agent's inventory + diagram tools, ADR-0019 §2/§3):

- `docs/runbooks/dr-postgres-pitr.md`
- `docs/runbooks/dr-neo4j-rebuild.md`
- `docs/runbooks/dr-pcap-spot-restore.md`
- `docs/runbooks/dr-full-platform.md`

Regenerate after any drill config change (freshness target ≤ 90 days once drills
run in P2 — G-OBS):

```
PYTHONPATH=backend:deploy/kubernetes/netops/drills \
  python -m full_platform.runbook --out docs/runbooks
```

> **Documentation-Agent LLM-narrative path: deferred to P2 (honest note).** The
> Documentation Agent's per-device runbook tool (`app.agents.documentation.tools.
> generate_runbook`) layers a grounded LLM narrative on top of deterministic fact
> tables and needs a reachable `BaseChatModel` provider. The P1 build host has **no
> LLM provider** (no Ollama, no API key), so the LLM-narrative layer could not run
> offline. Per the W5-T5 spec we commit the **generation wiring** + the **seeded,
> deterministically-rendered** runbooks and do **not** fabricate LLM output. When a
> provider is wired in P2, the narrative sections layer on top of these procedure
> tables (the drill facts remain the source of truth).

## Gate status & P2 carry-forward

- ✅ **P1 (this task):** full-platform drill restores Postgres from object storage
  alone → rebuilds Neo4j from the restored Postgres → spot-restores pcaps,
  end-to-end on a clean target; aggregated RPO/RTO/topology-RTO recorded vs the
  PROPOSED targets; runbooks generated; infra gates green (helm lint, kubeconform
  -strict, kube-linter, conftest — the rego rules bite, verified by un-suspending
  the drill and watching conftest fail).
- ⏳ **P2 (deferred — the gate is NOT fully closed at production scale):**
  - Execute the drill ≥ twice yearly (un-suspend `backup.drills.fullPlatform.suspend`).
  - Run it at **certified scale (5 000 devices)** on a **genuinely clean cluster**
    (the seeded dry-run proves the mechanism, not production scale — ADR-0030 §6 /
    PRODUCTION.md §3). **This certified-scale clean-cluster run is explicitly P2.**
  - **Re-base the PROPOSED targets** on the Consultant §12 answer (see the re-base
    flag at the top) and regenerate this evidence + the runbooks.
  - HA / streaming replication that would tighten RPO is also P2 (ADR-0030 §6).

> **This doc does not imply the G-REL gate is fully closed.** P1 proves
> recoverability-from-backups-alone end-to-end at seeded scale; the twice-yearly,
> certified-scale, clean-cluster run + the Consultant-§12 target confirmation are
> the P2 work that closes it.
