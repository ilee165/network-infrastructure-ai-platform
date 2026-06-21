# W5-T1 — pgBackRest Postgres Backup Tier (WAL + full/incr → MinIO)

| | |
|---|---|
| **Wave** | P1 W5 — Backup / DR baseline |
| **Owner** | `wf-infra` (declarative infra + policy-as-test) |
| **Review tier** | sonnet spec + **strong** quality (backup carries encrypted credentials + audit/PII rows) |
| **Depends on** | W4 (Helm GA chart deploy targets + namespaces) |
| **ADRs** | ADR-0030 §1, §4; ADR-0011 §1–§2; ADR-0004 (D4) |
| **PRODUCTION.md** | §8 (DR table), §9 (external-secret refs), §11 G-REL / G-SEC |
| **Status** | Proposed |

## Objective

Stand up the load-bearing DR tier: continuous WAL archiving plus full/incremental pgBackRest
backups of the PostgreSQL system of record, encrypted at the repo layer, written to a
MinIO/S3-compatible object store, scheduled as Helm-shipped K8s `CronJob`s (Compose parity via
host cron). This task ships the **backup + verify** half; the restore drill is W5-T2.

## Scope

**In**
- pgBackRest stanza config against the primary (sidecar/CronJob, not Celery beat — ADR-0030 §4/§5).
- Postgres `archive_command = pgbackrest ... archive-push`, `archive_mode = on` (continuous WAL).
- Full **weekly** + incremental **daily** `CronJob`s; `pgbackrest verify` after every backup.
- MinIO/S3 repo (`pgbackrest/` prefix); `repo-cipher-type=aes-256-cbc` repo encryption with the
  cipher passphrase + object-store credential supplied as **external-secret references** (never inlined).
- Retention: `repo-retention-full=35d`-equivalent + monthly fulls kept 1 year (ADR-0030 §1 table).
- Helm wiring: backup **on by default** (secure/resilient-by-default = opt-out); object-store
  endpoint + credential are required chart values resolved via external-secrets/CSI.
- Compose parity one-shot/host-cron path for the single-node target.

**Out**
- Restore / PITR drill and the post-restore integrity assertions → **W5-T2**.
- Neo4j (W5-T3), pcap snapshot (W5-T4), full-platform drill + runbook (W5-T5).
- Streaming replication / HA (explicitly P2 — ADR-0030 §6, PRODUCTION.md §3).

## Requirements (grounded in ADR-0030 §1)

1. **WAL archiving is the RPO floor.** `archive_mode=on` + `archive-push` so recovery reaches
   the last archived WAL segment, sizing toward the PROPOSED **RPO ≤ 5 min** (ADR-0030 §1/§6).
   Treat the target as PROPOSED — note it in values + the evidence stub for W5-T5.
2. **Cadence:** full weekly, incremental daily, as separate CronJobs (or a single job with
   `--type` selection on schedule). Each backup runs `pgbackrest verify` and fails the job on a
   non-clean verify (policy-as-test: a backup that cannot be verified is a failed backup).
3. **Repo encryption is independent of the object store's SSE** (ADR-0030 §1 / Alt #3): repo
   `aes-256-cbc` on, passphrase from the platform secret store as a `credential_ref`. SSE may be
   layered *with* it, never instead of it.
4. **The backup is not a credential-exposure path** (ADR-0011 §1): the dump contains only
   `ciphertext, nonce, wrapped_dek, kek_version` — never plaintext, never the DEK. The **KEK is
   never co-located with the repo** (separate escrow drill — out of scope here). Do not add any
   step that materializes a KEK alongside the backup.
5. **Audit rows ride inside every Postgres backup** (ADR-0030 §1) — no separate audit backup; the
   7-year audit *data* retention (PRODUCTION.md §7) is satisfied by the longest-retained full, and
   the 35-day repo retention does **not** override it. Document this relationship in values comments.
6. **Independence from app/broker health** (ADR-0030 §4/§5, Alt #5): K8s `CronJob`s, **not**
   Celery beat, so backups keep running when the app/Redis is degraded.
7. **Least-privilege object access:** the backup job credential is write-to-`pgbackrest/`-prefix
   only; document the bucket/prefix layout (`pgbackrest/`, leaving `pcaps/` for W5-T4).

## Contracts / artifacts

- `deploy/kubernetes/<chart>/templates/backup/pgbackrest-*.yaml` — CronJob(s) + ConfigMap +
  external-secret refs; values under `backup.postgres.*` (`enabled: true` default, `schedule`,
  `retention`, `repo.endpoint`, `repo.encryption`, secret refs).
- pgBackRest stanza config (ConfigMap) + Postgres `archive_command`/`archive_mode` wiring
  (StatefulSet env / `postgresql.conf` patch).
- `deploy/docker/` Compose parity: host-cron / `ofelia`-style one-shot for full/incr + verify.
- Values documentation in the chart `values.yaml` comments + chart README delta.

## Test & gate plan (infra gates — ADR-0016 §, P1-PLAN.md §2 `wf-infra` discipline)

- `helm lint` + `helm template` render clean with backup enabled (default) **and** explicitly
  disabled (opt-out path renders no CronJob, no dangling secret refs).
- `kubeconform` schema-valid; `kube-linter`/`kubescape` clean (no privileged, runAsNonRoot,
  resource limits set on the CronJob pods).
- `conftest`/OPA policy-as-test asserting: backup CronJob **present by default**; repo encryption
  key + object-store credential are external-secret refs, **never literal** in rendered manifests
  (regex-deny inline secrets); `pgbackrest verify` step present; schedule matches weekly-full /
  daily-incr cadence.
- A rendered-manifest assertion that the cipher passphrase value is a `valueFrom.secretKeyRef`
  (no `value:` literal) — secret-surface gate.

## Exit criteria

- [ ] Chart renders pgBackRest WAL archiving + weekly-full + daily-incr CronJobs to a MinIO/S3
      repo, **on by default**, repo encryption on, all secrets by reference (G-SEC).
- [ ] `pgbackrest verify` gates every backup job; a failed verify fails the job.
- [ ] No KEK / plaintext credential / inline secret in any rendered manifest (policy test green).
- [ ] Opt-out path (`backup.postgres.enabled=false`) renders cleanly with no orphaned refs.
- [ ] Compose parity path documented and rendered.
- [ ] Helm lint / kubeconform / kube-linter / conftest all green; chart README updated.

## Workflow (P1-PLAN.md §3 per-task pattern)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (strong —
escalated: backup touches credential/audit surface)** review in parallel → `wf-fixer` (strong) if
findings → `wf-verifier` confirms → **one atomic commit**.

## Risks

- A mis-configured off-host repo (wrong retention, missing encryption, reachable credential) is a
  new exfiltration surface for audit/PII/credential-bearing data (ADR-0030 Negative). Mitigated by
  the repo-encryption + external-secret-ref + least-privilege-prefix policy tests above; fully
  exercised only by the W5-T2 / W5-T5 drills.
- RPO ≤ 5 min is PROPOSED (ADR-0030 §6) pending the Consultant §12 answer; build to the default,
  flag for re-base in the W5-T5 evidence doc.
