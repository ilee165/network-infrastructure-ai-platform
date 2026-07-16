# W5-T2 — Postgres PITR Restore-Drill Job + Integrity Assertions

| | |
|---|---|
| **Wave** | P1 W5 — Backup / DR baseline |
| **Owner** | `wf-infra` (policy-as-test job + assertions) |
| **Review tier** | sonnet spec + **strong** quality — **escalated** (audit-immutability + credential-separation are the secret-surface invariants this task proves) |
| **Depends on** | W5-T1 (pgBackRest repo + WAL) |
| **ADRs** | ADR-0030 §1, §5.1; ADR-0011 §1 (envelope), §2 (append-only audit) |
| **PRODUCTION.md** | §8 (quarterly timed drill), §11 G-REL / G-SEC |
| **Status** | Proposed |

## Objective

Ship the **restore-drill job and its assertions** for Postgres: restore latest full + WAL to a
clean instance and prove the three things a naive `pg_restore` would skip — RPO is within window,
the append-only audit log comes back immutable, and a restored credential row **fails closed**
without the matching KEK. The job is built in P1; it is **executed quarterly from P2**
(ADR-0030 §5, P1-PLAN.md §6) — P1 delivers a green dry-run against a seeded fixture.

## Scope

**In**
- A `postgres-pitr-drill` Job (Helm-shipped K8s `Job`, Compose one-shot) that restores from the
  W5-T1 repo to a throwaway instance and runs timed, pass/fail assertions.
- Assertion suite (ADR-0030 §5.1):
  1. **RPO ≤ 5 min** — WAL replay reaches within the PROPOSED window.
  2. **Audit-log immutability re-asserted** — app role still lacks `UPDATE`/`DELETE` on
     `audit_log`; `BEFORE UPDATE OR DELETE` guard trigger exists and fires; row count / `max(id)`
     ≥ the pre-incident checkpoint (no truncation). If audit hash-chaining is live (PRODUCTION.md
     §5), re-verify the chain end-to-end as the strongest immutability check.
  3. **Credential separation proof** — a `device_credentials` row decrypts **only** with the
     matching `kek_version`, and **fails closed** (typed error, no plaintext) without it.
  4. `pgbackrest verify` clean on the restored stanza.
- A seeded fixture (audit rows + ≥1 encrypted credential) so the drill runs green in CI without
  hardware (lab-deferred posture, P1-PLAN.md §6).

**Out**
- The backup/WAL pipeline itself (W5-T1).
- Full-platform cross-store drill + RPO/RTO end-to-end timing (W5-T5 §5.3).
- KEK escrow/recovery (separate drill, PRODUCTION.md §8 — not pgBackRest's scope).

## Requirements (grounded in ADR-0030 §1, §5.1)

1. **Restore is asserted, not assumed.** A physical pgBackRest restore reproduces data, grants,
   and triggers — but the drill must *prove* it. A restore that comes back with a **writable audit
   log is a FAILED drill**, not a successful one (ADR-0030 §1).
2. **Credential separation is a positive test of fail-closed behavior.** The matching-KEK decrypt
   must succeed; the missing-KEK decrypt must raise a typed error and leak **no plaintext** — this
   is the "a restored DB is inert for device access until the KEK is reachable" property
   (ADR-0030 §1 / Alt #4), feeding G-SEC "no plaintext device credential in any … backup sample."
3. **Timed + pass/fail (policy-as-test).** Each assertion emits a clear pass/fail and the restore
   is timed; results feed gate **G-REL** ("DR drill from backups alone … RPO ≤ 5 min").
4. **No-truncation check** uses the pre-incident `max(id)` / row-count checkpoint captured before
   the drill, so a silently truncated audit log fails the assertion.
5. **Built P1, run P2** — wire the Job + schedule (quarterly) but mark execution as P2; the P1
   gate is a green dry-run over the seeded fixture.

## Contracts / artifacts

- `deploy/kubernetes/<chart>/templates/backup/postgres-pitr-drill-job.yaml` — `Job` +
  (suspended) quarterly `CronJob`, gated behind `backup.drills.enabled`.
- Drill script / assertion harness (shell + psql, or a small Python assert module
  reusing `app.core.crypto` for the credential-decrypt proof) packaged under
  `backend/app/ops/drills/postgres_pitr/` in the installed backend wheel.
- Seed fixture (SQL or factory) producing the audit checkpoint + encrypted credential row.
- Pass/fail output contract: structured lines `DRILL postgres_pitr <assertion>=PASS|FAIL
  duration_s=<n>` for the G-REL evidence collector (W5-T5).

## Test & gate plan (infra + policy-as-test)

- Dry-run the drill in CI against the seeded fixture: all four assertions PASS, restore timed.
- Negative tests: (a) tamper the restored grant so the app role *can* `DELETE` audit rows → drill
  **fails**; (b) supply a wrong `kek_version` → credential decrypt fails closed and the
  separation assertion PASSES (proving the closed path); (c) truncate audit fixture → no-truncation
  assertion fails. These prove the assertions actually bite.
- `helm lint` / `kubeconform` / `conftest`: Job present, drill credential is an external-secret
  ref, drill writes only to a throwaway namespace/instance, no plaintext in logs.

## Exit criteria

- [ ] PITR drill restores from the W5-T1 repo and runs the four ADR-0030 §5.1 assertions, timed.
- [ ] Audit-immutability assertion fails a writable-audit restore; credential-separation assertion
      proves fail-closed without the KEK and success with it (G-SEC).
- [ ] No-truncation assertion catches a truncated audit log.
- [ ] Negative tests demonstrate each assertion bites.
- [ ] Job/CronJob renders cleanly, secrets by reference, P2-execution flagged.
- [ ] Infra gates green; structured pass/fail output consumable by W5-T5.

## Workflow (P1-PLAN.md §3)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (strong —
escalated: this task IS the credential/audit-integrity proof)** in parallel → `wf-fixer` (strong)
if findings → `wf-verifier` → **one atomic commit**.

## Risks

- A drill whose assertions are too weak silently "passes" a broken restore — mitigated by the
  mandatory negative tests above (the assertions must fail a tampered restore).
- RPO ≤ 5 min PROPOSED (ADR-0030 §6): the within-window assertion is parameterized off the same
  values knob as W5-T1 and re-bases on the Consultant §12 answer.
