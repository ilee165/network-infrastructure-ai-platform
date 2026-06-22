# DR Runbook — Neo4j rebuild drill (W5-T3)

> **GENERATED — do not edit by hand.** Produced by `full_platform.runbook` (W5-T5, deterministic / no-LLM, ADR-0019 §2 dogfooding mode). Re-run the generator after any drill config change to keep it current (freshness target <= 90 days once drills run in P2 — G-OBS).
>
> The Documentation Agent's LLM-narrative runbook path (`app.agents.documentation.tools.generate_runbook`) needs a reachable LLM provider, which the P1 build host does not have — so the narrative layer is deferred to P2 and these runbooks carry the deterministic procedure tables only (W5-T5 spec: no fabricated generated output).

## Objective

Prove Neo4j needs NO backup: DR is a full RE-PROJECTION from the authoritative Postgres, not a restore of a graph dump. Drop/recreate the projected graph, re-project the WHOLE inventory, and assert the rebuilt counts match within the topology-RTO budget.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0030 §2/§5.2, ADR-0005 D5 |
| Cadence (P2) | Quarterly (02:00, 15th of Jan/Apr/Jul/Oct) |
| Backup-type label | `neo4j-rebuild-drill` |
| Job / CronJob | `netops-neo4j-rebuild-drill` |
| Restore source | the authoritative Postgres (re-projected, NOT a graph dump) |
| Restore target | a clean Neo4j graph (re-derived; no PVC restore) |
| Execution phase | P2 (built P1, suspended CronJob) |

## What this drill proves

- Counts-match — rebuilt node/edge counts equal the pre-wipe projection within tolerance (the rebuildable-projection invariant, ADR-0005 D5).
- Topology-RTO — `topology_rebuild_seconds` < the PROPOSED budget (< 30 min at 5,000 devices).

## Procedure

1. Confirm Postgres is the authoritative inventory source and Neo4j auth is present in the platform Secret (by-reference).
2. Run the on-demand Job from `cronjob/netops-neo4j-rebuild-drill`.
3. The pod re-projects via `app.engines.topology` (recording `topology_rebuild_seconds` + node/edge gauges) and runs `python -m topology_rebuild.run_drill`.
4. Collect the `DRILL neo4j_rebuild ...` lines (incl. the measured topology-RTO seconds) for the G-REL evidence doc.

## Structured evidence (the `DRILL ...` lines the collector parses)

```
DRILL neo4j_rebuild rto_within_target=PASS
DRILL neo4j_rebuild counts_match=PASS
DRILL neo4j_rebuild seconds=<n> nodes=<n> edges=<n> result=PASS
DRILL neo4j_rebuild OUTCOME=PASS assertions=2
```

## Failure modes & response

| Symptom | Response |
|---|---|
| `counts_match=FAIL` | The re-projection dropped or invented topology — the projection pipeline is incomplete (ADR-0005 D5); fix the projector. |
| `rto_within_target=FAIL` | Rebuild exceeded the PROPOSED topology-RTO — profile the projection at scale; re-base the target on Consultant §12. |

## Roll-back / safety

- The drill writes ONLY to a throwaway `emptyDir` scratch torn down with the pod; it mounts no live PVC, so there is nothing to roll back and no production data is touched (ADR-0030 §5.3).
- To stop a P2 run mid-flight: `kubectl delete job netops-neo4j-rebuild-drill` (the CronJob stays suspended until deliberately un-suspended).

