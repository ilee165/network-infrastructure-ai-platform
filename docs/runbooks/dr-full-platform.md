# DR Runbook — full-platform DR drill (W5-T5)

> **GENERATED — do not edit by hand.** Produced by `app.ops.drills.full_platform.runbook` (W5-T5, deterministic / no-LLM, ADR-0019 §2 dogfooding mode). Re-run the generator after any drill config change to keep it current (freshness target <= 90 days once drills run in P2 — G-OBS).
>
> The Documentation Agent's LLM-narrative runbook path (`app.agents.documentation.tools.generate_runbook`) needs a reachable LLM provider, which the P1 build host does not have — so the narrative layer is deferred to P2 and these runbooks carry the deterministic procedure tables only (W5-T5 spec: no fabricated generated output).

## Objective

Prove the WHOLE platform is recoverable from object storage ALONE onto a clean cluster, by chaining the three per-tier drills end-to-end and asserting RPO <= 5 min / RTO <= 1 h (PROPOSED) at the measured scale.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0030 §5.3/§6, ADR-0005 D5, ADR-0011 §1/§2 |
| Cadence (P2) | Semiannual / >= twice yearly (04:00, 20th of Jan + Jul) |
| Backup-type label | `full-platform-drill` |
| Job / CronJob | `netops-full-platform-dr-drill` |
| Restore source | object storage ALONE (no surviving live state) |
| Restore target | a clean target — throwaway emptyDir scratch (no live PVC) |
| Execution phase | P2 (built P1, suspended CronJob) |

## What this drill proves

- From backups alone, onto a clean cluster — Postgres from object storage, Neo4j rebuilt over the RESTORED Postgres, pcaps spot-restored (G-REL).
- The D5 'one authoritative thing to restore (Postgres) + one thing to rebuild (the Neo4j projection)' story, end-to-end.
- Aggregated RPO/RTO/topology-RTO recorded vs the PROPOSED targets (the evidence collector parses the per-tier `DRILL ...` lines; it does NOT re-implement the per-tier assertions).

## Procedure

1. Confirm all per-tier credentials are present in the platform Secret (by-reference only): DB password, Neo4j auth, backup + pcap S3 keys, repo cipher pass, KEK reference.
2. Run the on-demand Job from `cronjob/netops-full-platform-dr-drill`.
3. The pod restores Postgres from the repo ALONE into throwaway scratch, then runs `python -m app.ops.drills.full_platform.run_drill`, which chains tier 1 -> 2 -> 3 and aggregates their `DRILL ...` lines.
4. Record the composite `DRILL full_platform ...` line + the aggregated table in `docs/roadmap/evidence/P1-W5-G-REL-evidence.md` (measured-vs-PROPOSED).
5. P2 only: re-run at certified scale (5,000 devices) on a genuinely clean cluster and re-base the PROPOSED targets on the Consultant §12 answer.

## Structured evidence (the `DRILL ...` lines the collector parses)

```
# (the three per-tier OUTCOME lines, then the composite:)
DRILL postgres_pitr OUTCOME=PASS assertions=4
DRILL neo4j_rebuild OUTCOME=PASS assertions=2
DRILL pcap_spot_restore OUTCOME=PASS assertions=3
DRILL full_platform tiers=3 passed=3 rpo_s=<n> rto_s=<n> topology_rto_s=<n> result=PASS
```

## Failure modes & response

| Symptom | Response |
|---|---|
| Any per-tier `OUTCOME=FAIL` | The end-to-end result rolls up to FAIL; the aggregated table names which tier + assertion failed — follow that tier's runbook. |
| `full_platform ... result=FAIL` with a MISSING tier | A tier produced no terminal verdict (silent gap) — the chain ran all tiers, so check that tier's pod logs; a missing tier is never a pass. |
| `rto_s` over budget | End-to-end RTO exceeded the PROPOSED 1 h — record the measured number; re-base on Consultant §12 (do not weaken the gate). |

## Roll-back / safety

- The drill writes ONLY to a throwaway `emptyDir` scratch torn down with the pod; it mounts no live PVC, so there is nothing to roll back and no production data is touched (ADR-0030 §5.3).
- To stop a P2 run mid-flight: `kubectl delete job netops-full-platform-dr-drill` (the CronJob stays suspended until deliberately un-suspended).

