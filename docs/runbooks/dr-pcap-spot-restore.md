# DR Runbook — pcap spot-restore drill (W5-T4)

> **GENERATED — do not edit by hand.** Produced by `app.ops.drills.full_platform.runbook` (W5-T5, deterministic / no-LLM, ADR-0019 §2 dogfooding mode). Re-run the generator after any drill config change to keep it current (freshness target <= 90 days once drills run in P2 — G-OBS).
>
> The Documentation Agent's LLM-narrative runbook path (`app.agents.documentation.tools.generate_runbook`) needs a reachable LLM provider, which the P1 build host does not have — so the narrative layer is deferred to P2 and these runbooks carry the deterministic procedure tables only (W5-T5 spec: no fabricated generated output).

## Objective

Prove DR HONORS the pcap retention contract: a sampled live capture restores and sha256-matches its capture-time hash, a tombstoned capture is NEVER resurrected, and the restore stays engineer+ gated.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0030 §3/§5.4, ADR-0023 §3/§4/§5 |
| Cadence (P2) | Annual (03:00, Jan 2nd) |
| Backup-type label | `pcap-drill` |
| Job / CronJob | `netops-pcap-spot-restore-drill` |
| Restore source | the `pcaps/` object-store prefix ALONE |
| Restore target | throwaway emptyDir scratch (never the live capture volume) |
| Execution phase | P2 (built P1, suspended CronJob) |

## What this drill proves

- Live-restore + sha256 — a sampled live capture's restored bytes match the capture-time hash (ADR-0023 §3 integrity).
- No resurrection — a tombstoned/expired capture is absent from the restore set, and a forced one is dropped by the metadata guard (ADR-0030 §3).
- Gated access — the restore is refused for a sub-engineer actor (ADR-0023 §5); DR opens no new ungated read path to PII/credential payloads.

## Procedure

1. Confirm the engineer+ actor identity and that the pcap S3 credential + DB password are present in the platform Secret (by-reference).
2. Run the on-demand Job from `cronjob/netops-pcap-spot-restore-drill`.
3. The pod restores sampled captures into the throwaway scratch and runs `python -m app.ops.drills.pcap.run_drill` (the three assertions, incl. the negative no-resurrection self-check).
4. Collect the `DRILL pcap_spot_restore ...` lines for the G-REL evidence doc.

## Structured evidence (the `DRILL ...` lines the collector parses)

```
DRILL pcap_spot_restore restore_authorized=PASS
DRILL pcap_spot_restore sampled_sha256_matches=PASS
DRILL pcap_spot_restore no_tombstoned_resurrection=PASS
DRILL pcap_spot_restore sampled=<id> sha256=MATCH tombstoned_resurrected=NO result=PASS
DRILL pcap_spot_restore OUTCOME=PASS assertions=3
```

## Failure modes & response

| Symptom | Response |
|---|---|
| `no_tombstoned_resurrection=FAIL` | A purged capture came back — DR re-extended a payload past retention; STOP and escalate (ADR-0030 §3). |
| `sampled_sha256_matches=FAIL` | Restore lost/corrupted bytes — investigate object-store integrity / the snapshot pipeline (W5-T4). |
| `restore_authorized=FAIL` | Expected for a sub-engineer actor — the gate bit; re-run as engineer+ for the positive path. |

## Roll-back / safety

- The drill writes ONLY to a throwaway `emptyDir` scratch torn down with the pod; it mounts no live PVC, so there is nothing to roll back and no production data is touched (ADR-0030 §5.3).
- To stop a P2 run mid-flight: `kubectl delete job netops-pcap-spot-restore-drill` (the CronJob stays suspended until deliberately un-suspended).

