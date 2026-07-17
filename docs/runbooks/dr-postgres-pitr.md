# DR Runbook — Postgres PITR restore drill (W5-T2)

> **GENERATED — do not edit by hand.** Produced by `app.ops.drills.full_platform.runbook` (W5-T5, deterministic / no-LLM, ADR-0019 §2 dogfooding mode). Re-run the generator after any drill config change to keep it current (freshness target <= 90 days once drills run in P2 — G-OBS).
>
> The Documentation Agent's LLM-narrative runbook path (`app.agents.documentation.tools.generate_runbook`) needs a reachable LLM provider, which the P1 build host does not have — so the narrative layer is deferred to P2 and these runbooks carry the deterministic procedure tables only (W5-T5 spec: no fabricated generated output).

## Objective

Prove the encrypted pgBackRest backup tier (W5-T1) is restorable: restore the latest full + WAL from the object-store repo ALONE into a throwaway target and assert the four properties a naive `pg_restore` would skip.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0030 §5/§5.1, ADR-0011 §1/§2 |
| Cadence (P2) | Quarterly (02:00, 1st of Jan/Apr/Jul/Oct) |
| Backup-type label | `drill` |
| Job / CronJob | `netops-postgres-pitr-drill` |
| Restore source | pgBackRest object-store repo (MinIO/S3) ALONE |
| Restore target | throwaway emptyDir scratch via `--pg1-path` (never the live PVC) |
| Execution phase | P2 (built P1, suspended CronJob) |

## What this drill proves

- RPO-in-window — WAL replay reached within the PROPOSED window (<= 5 min).
- Audit-log immutability — the restored append-only audit log is still UPDATE/DELETE-locked and not truncated.
- Credentials fail CLOSED — a restored credential decrypts ONLY with the matching KEK and raises a typed error (no plaintext) without it.
- pgbackrest verify — the restored stanza verifies clean.

## Procedure

1. Confirm the backup repo is reachable and the cipher pass / S3 credential are present in the platform Secret (by-reference only).
2. Run the on-demand Job: `kubectl create job --from=cronjob/netops-postgres-pitr-drill netops-postgres-pitr-drill-manual`.
3. The pod restores into the throwaway scratch, runs `pgbackrest verify`, then `python -m app.ops.drills.postgres_pitr.run_drill` (the four assertions).
4. Collect the `DRILL postgres_pitr ...` lines for the G-REL evidence doc.

## Structured evidence (the `DRILL ...` lines the collector parses)

```
DRILL postgres_pitr rpo_within_window=PASS duration_s=<n>
DRILL postgres_pitr audit_log_immutable=PASS duration_s=<n>
DRILL postgres_pitr credentials_fail_closed=PASS duration_s=<n>
DRILL postgres_pitr pgbackrest_verify_clean=PASS duration_s=<n>
DRILL postgres_pitr OUTCOME=PASS assertions=4
```

## Failure modes & response

| Symptom | Response |
|---|---|
| `rpo_within_window=FAIL` | WAL replay lag exceeded the PROPOSED window — investigate archive_command / WAL shipping cadence (W5-T1). |
| `credentials_fail_closed=FAIL` | A restored credential decrypted WITHOUT the KEK — envelope encryption is broken; escalate (G-SEC). |
| Empty restore / `PG_VERSION` missing | The L5 `test -s` guard failed the job — the restore stream was silently empty; check repo + stanza. |

## Roll-back / safety

- The drill writes ONLY to a throwaway `emptyDir` scratch torn down with the pod; it mounts no live PVC, so there is nothing to roll back and no production data is touched (ADR-0030 §5.3).
- To stop a P2 run mid-flight: `kubectl delete job netops-postgres-pitr-drill` (the CronJob stays suspended until deliberately un-suspended).

