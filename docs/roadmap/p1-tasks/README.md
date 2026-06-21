# P1 W5 / W6 — Task Specs

Per-task decomposition of **P1-PLAN.md §3** waves **W5 (Backup/DR baseline)** and
**W6 (Security hardening: KMS, CI supply-chain, rate-limit)**. Each task below is a
single atomic-commit unit that runs the **P1-PLAN.md §3 per-task pattern**:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two reviews).

Escalation rule (P1-PLAN.md §2, `.claude/agents/README.md`): every secret-surface task
(KEK/credential/audit/auth, leak/exit-criteria tests) escalates **reviewers + fixer to the
strong model (`fable`)**; nothing in a secret pipeline runs on a downgraded model.

## W5 — Backup / DR baseline (ADR-0030, PRODUCTION.md §8, gate G-REL)

Owner: **`wf-infra`** (declarative infra + policy-as-test, not Python-TDD). Drills are
*built* in P1, *executed* from P2 (ADR-0030 §5, P1-PLAN.md §6).

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W5-T1](W5-T1-pgbackrest-postgres-backup.md) | pgBackRest Postgres backup tier (WAL + full/incr → MinIO) | `wf-infra` | strong quality | W4 (chart) |
| [W5-T2](W5-T2-postgres-pitr-restore-drill.md) | Postgres PITR restore-drill job + integrity assertions | `wf-infra` | **strong** quality (audit/credential surface) | W5-T1 |
| [W5-T3](W5-T3-neo4j-rebuild-drill.md) | Neo4j rebuild-drill job + topology-RTO metric | `wf-infra` (+ Python metric hook) | strong quality | W4 |
| [W5-T4](W5-T4-pcap-volume-snapshot.md) | pcap volume snapshot under ADR-0023 retention | `wf-infra` | **strong** quality (PII/payload surface) | W5-T1 |
| [W5-T5](W5-T5-dr-drill-runbook-evidence.md) | Full-platform DR drill wiring + runbook + G-REL evidence | `wf-infra` | strong quality | W5-T1..T4 |

## W6 — Security hardening, P1 subset (PRODUCTION.md §5, gates G-SEC / G-SCA / G-MNT)

Three disjoint streams — **KMS** (`wf-implementer`, Python), **CI supply-chain**
(`wf-infra`), **rate-limit** (`wf-implementer`, Python). All secret-surface tasks escalate
reviewers to strong (P1-PLAN.md §3: "All secret-surface → escalated").

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W6-T1](W6-T1-keyprovider-wrap-unwrap-interface.md) | `KeyProvider` wrap/unwrap interface + fail-closed credential service | `wf-implementer` (strong) | **strong** spec + quality | — |
| [W6-T2](W6-T2-kms-backends.md) | KMS backends (AWS / Azure / Vault Transit) + prod-grade gating | `wf-implementer` (strong) | **strong** spec + quality | W6-T1 |
| [W6-T3](W6-T3-master-key-rotation-rewrap.md) | Master-key rotation / DEK re-wrap job + key-access audit | `wf-implementer` (strong) | **strong** spec + quality | W6-T1 (W6-T2 for KMS versions) |
| [W6-T4](W6-T4-ci-dependency-secret-scanning.md) | CI dependency + secret scanning (pip-audit, npm audit, gitleaks) | `wf-infra` | **strong** quality | — |
| [W6-T5](W6-T5-sbom-image-signing-admission.md) | SBOM (syft) + cosign signing + admission verify + Trivy gate raise | `wf-infra` | **strong** quality | W6-T4, W4 (admission) |
| [W6-T6](W6-T6-redis-rate-limit-login-lockout.md) | Redis-backed API rate-limit + login throttle/lockout | `wf-implementer` (strong) | **strong** spec + quality | — |

## Sequencing (within P1-PLAN.md §4)

- W5 and W6 both follow **W4** (need chart deploy targets + namespaces).
- **W5:** T1 first (defines the pgBackRest repo + object store), then T2 (restore drill over
  T1's repo) and T4 (pcap snapshot to the same store) in parallel; T3 is independent of T1;
  T5 last (composes all four into the full-platform drill + runbook + evidence).
- **W6 KMS:** T1 (interface) blocks T2 (backends) and T3 (rotation). T2 and T3 can then run in
  parallel (disjoint files; T3 reads KMS-version semantics defined in T2's table but does not
  import T2 backends).
- **W6 CI:** T4 (scanning jobs) before T5 (SBOM/signing extends the same `ci.yml` docker job).
- **W6 rate-limit (T6)** is independent of every other W6 task (auth/middleware files).
- KMS, CI, and rate-limit streams run **concurrently** across owners; the per-task pattern
  serializes only the two reviews inside each task.

## Spec template

Every spec uses the same sections: **Metadata · Objective · Scope (In/Out) · Deliverables ·
Requirements · Contracts · Test & gate plan · Exit criteria · Workflow · Risks.**
Requirements are grounded line-by-line in the cited ADR/PRODUCTION.md §; nothing here
re-decides an ADR — these specs *implement* the W0 design gate (ADR-0025…0032).
