# W5-T4 — pcap Volume Snapshot Under the ADR-0023 Retention Contract

| | |
|---|---|
| **Wave** | P1 W5 — Backup / DR baseline |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet spec + **strong** quality — **escalated** (pcaps hold cleartext credentials/PII; the whole risk is DR resurrecting purged payloads) |
| **Depends on** | W5-T1 (same MinIO/S3 object store) |
| **ADRs** | ADR-0030 §3, §5.4; ADR-0023 §3 (sha256/disk layout), §4 (30-day tombstone retention), §5 (gated download) |
| **PRODUCTION.md** | §8 (pcap daily snapshot, annual spot-restore), §11 G-SEC |
| **Status** | Proposed |

## Objective

Snapshot the pcap disk volume to the same object store as W5-T1, with the hard constraint that DR
**honors — never subverts — the ADR-0023 retention contract**: the snapshot only captures live
(non-tombstoned) files, prunes any snapshot whose `pcap_metadata.tombstoned_at` is set, and a
restore is metadata-consistent (sha256-checked, tombstoned rows never resurrected). pcaps are the
lowest-criticality tier (diagnostic artifacts), so the drill is an annual spot-restore.

## Scope

**In**
- Daily snapshot/rsync `CronJob` of `/data/pcaps/{capture_id}.pcap` (ADR-0023 §3) to the
  `pcaps/` object-store prefix (separate from `pgbackrest/`).
- **Retention-honoring prune**: snapshot only live files; prune from the object store any snapshot
  whose `pcap_metadata.tombstoned_at` is set; snapshot retention window = **shorter of**
  (object-store policy) and (the pcap's `retention_expires_at`).
- **Metadata-consistent restore** path: on restore, re-check the `sha256` recorded at
  capture-complete (ADR-0023 §3) against the restored file; drop any file whose row is tombstoned
  or whose hash mismatches. A tombstoned capture's download still 404s post-restore (ADR-0023 §5).
- **Gated access preserved**: restored pcaps reachable only via the existing `engineer`+ audited
  download path (ADR-0023 §5); object-store ACLs on the pcap prefix least-privilege; the snapshot
  job credential is a `credential_ref`, **write-to-prefix only**.
- Annual spot-restore drill job (built P1, run from P2) asserting: a sampled live capture restores
  and sha256-matches; a tombstoned capture is **not** resurrected.

**Out**
- Postgres backup of `pcap_metadata` rows — those live in Postgres, covered by W5-T1 (the *audit
  record that a capture existed and was purged* survives in the Postgres backup; the payload does not).
- Packet-capture/analysis runtime (M5 `engines/packet/`).

## Requirements (grounded in ADR-0030 §3, §5.4; ADR-0023 §4–§5)

1. **The snapshot must not resurrect purged payloads** (ADR-0030 §3 — the load-bearing constraint).
   ADR-0023 §4 deletes the file + tombstones the row at expiry; DR must not silently re-extend the
   lifetime of credential/PII-bearing payloads past retention. **Snapshot only non-tombstoned
   files; prune object-store copies of tombstoned rows.**
2. **Restore is metadata-consistent** (ADR-0030 §3): sha256-match against the capture-time hash; a
   mismatch or a file for a tombstoned row is dropped, so a restored volume never serves a payload
   the metadata says was purged. Tombstoned download 404s post-restore.
3. **Retention window is the shorter of the two** (ADR-0030 §3) — never let object-store policy
   extend a pcap past its `retention_expires_at`.
4. **Access stays gated** (ADR-0023 §5): no new ungated read path; restored pcaps flow through the
   existing audited `engineer`+ download; snapshot credential is least-privilege write-only.
5. **Job independence** (ADR-0030 §4): K8s `CronJob`, not Celery beat.
6. **Lowest-criticality tier:** annual spot-restore (ADR-0030 §5.4), not quarterly.
7. **Built P1, run P2** — wire + green dry-run over a seeded fixture (one live + one tombstoned
   capture); the assertion that the tombstoned one is not resurrected runs green in CI.

## Contracts / artifacts

- `deploy/kubernetes/<chart>/templates/backup/pcap-snapshot-cronjob.yaml` +
  `pcap-spot-restore-drill-job.yaml`, behind `backup.pcap.enabled` (default on) /
  `backup.drills.pcap.enabled`.
- Snapshot/restore script that joins `pcap_metadata` (read-only) to decide live-vs-tombstoned and
  to source the capture-time sha256 — co-located under `deploy/<...>/drills/pcap/`.
- Structured output `DRILL pcap_spot_restore sampled=<id> sha256=MATCH|MISMATCH
  tombstoned_resurrected=NO|YES result=PASS|FAIL` for the W5-T5 collector.

## Test & gate plan

- Dry-run over a seeded fixture (one live capture, one tombstoned): snapshot captures only the live
  file; prune removes the tombstoned snapshot; spot-restore sha256-matches the live file and the
  `tombstoned_resurrected=NO` assertion PASSES.
- Negative test: force a tombstoned row into the snapshot set → the prune/restore path drops it and
  the assertion would catch a `YES` (proves the guard bites).
- Infra gates: `helm lint` / `kubeconform` / `kube-linter` / `conftest` — CronJob present, snapshot
  credential is a write-only-prefix external-secret ref, no broad object-store grant in rendered
  manifests, runAsNonRoot + resource limits.

## Exit criteria

- [ ] Daily pcap snapshot to `pcaps/` prefix, **on by default**, least-privilege write-only credential.
- [ ] Snapshot skips tombstoned files; prune removes tombstoned object-store copies; window = shorter
      of policy vs `retention_expires_at` (G-SEC data-minimization preserved).
- [ ] Spot-restore sha256-matches and refuses to resurrect a tombstoned capture; tombstoned download
      404s post-restore.
- [ ] No new ungated read path; restored access via the audited `engineer`+ download only.
- [ ] Dry-run green; negative test proves the no-resurrection guard bites; infra gates green.

## Workflow (P1-PLAN.md §3)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (strong —
escalated: PII/payload + retention-bypass surface)** in parallel → `wf-fixer` (strong) if findings
→ `wf-verifier` → **one atomic commit**.

## Risks

- The single off-host object store is itself a new exfiltration surface for PII-bearing pcaps
  (ADR-0030 Negative) — mitigated by least-privilege prefix + retention-honoring prune; exercised
  by the spot-restore drill.
- A subtle prune bug silently extends payload lifetime past retention — the no-resurrection negative
  test is the guardrail and must be present.
