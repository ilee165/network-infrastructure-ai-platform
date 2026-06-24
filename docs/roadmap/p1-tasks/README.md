# P1 W5 / W6 / W7 — Task Specs

Per-task decomposition of **P1-PLAN.md §3** waves **W5 (Backup/DR baseline)**,
**W6 (Security hardening: KMS, CI supply-chain, rate-limit)**, and **W7 (Evals +
phase-exit gate)**. Each task below is a
single atomic-commit unit that runs the **P1-PLAN.md §3 per-task pattern**:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two reviews).

Escalation rule (P1-PLAN.md §2, `.claude/agents/README.md`): every secret-surface task
(KEK/credential/audit/auth, leak/exit-criteria tests) escalates **reviewers + fixer to the
session strong model**; nothing in a secret pipeline runs on a downgraded model.
**`fable` is UNAVAILABLE — escalate to `opus` (the live strong model).** A dead-model
escalation returns a silently "clean" review (P1 W0 false-clean root cause); never inline
`model: 'fable'`. See `.claude/agents/README.md` → Escalation rule.

## Carry-forward from W4 — READ BEFORE STARTING (`../P1-W4-LESSONS.md`)

W4 (Helm/K8s GA chart, PR #59) cost a CI red and a review round on traps that recur
directly in these waves. Each lesson there is mapped to the task(s) it will bite here —
apply the rule up front, don't re-learn it:

| Lesson | Rule | Bites which task(s) here |
|---|---|---|
| **L1** new gating CI tool | Run the tool LOCALLY (install or throwaway container) before pushing it as gating; local gate set ≠ CI gate set. | **W6-T4** (pip-audit/npm-audit/gitleaks), **W6-T5** (syft/cosign/Trivy raise) |
| **L2** sanctioned deviations | Scoped-suppress the generic scanner (`.trivyignore` via `TRIVY_IGNOREFILE` on one step) + back it with a stronger conftest rule; never globalize or weaken. | **W6-T5** (raises Trivy gate — extend, don't drop, existing suppressions) |
| **L3** exec argv `$(VAR)` | K8s does NOT substitute `$(VAR)` in probe/Job exec argv — wrap in `sh -c "tool \"$VAR\""`; grep sibling manifests when fixing one. | **W5-T1..T5** backup/restore CronJobs (pgBackRest/psql/neo4j-admin), exec probes |
| **L4** helm secret idempotency | Reuse-or-generate dev secrets via `lookup` (empty in CI, reused on live upgrade) — regen on `helm upgrade` breaks auth. | **W6** KMS dev secrets, **W5** chart-rendered backup creds |
| **L5** CI pipe masks exit code | `set -o pipefail` + `test -s <out>` on any `cmd \| filter > file` (CI or job). | **W5** backup pipelines (`pg_dump \| gzip \| mc`), any W5/W6 piped CI step |
| **L6** `gh pr merge` fatal | Local-checkout fatal under sibling worktrees is harmless — verify `gh pr view --json state` MERGED, then `git push origin --delete`. | all waves (merge step) |
| **L7** session windows | One-atomic-commit-per-task survives session-limit kills; resume via `resumeFromRunId` (cache-replay), discard half-done uncommitted task work. | any multi-task workflow run |
| **L8** agent registry | Confirm every `agentType` the workflow calls is in the LIVE registry before launch; substitute + fold discipline into the prompt if missing. | any workflow launch (`wf-infra` now loaded) |

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

## W7 — Evals + phase-exit gate (ADR-0033, PRODUCTION.md §5/§11, gate G-SEC)

Owner: **`wf-eval-designer`** (suites) + **`wf-release-auditor`** (gate evidence — NEW
agent, `.claude/agents/wf-release-auditor.md`). The **LAST** P1 wave and the phase-exit
gate. Full plan: [`../P1-W7-PLAN.md`](../P1-W7-PLAN.md). Builds the *proof* (eval suites),
not new controls. **Decisions (2026-06-24):** new `wf-release-auditor` for T4; **T1/T2
reviewers escalated to strong** (ED4 secret-non-exfil + leak/exit-criteria = secret-surface,
overrides the P1-PLAN W7 "sonnet").

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W7-T1](W7-T1-prompt-injection-deterministic-suite.md) | Deterministic injection suite (ED1–ED5) + held-out corpus + matrix meta-test | `wf-eval-designer` | **strong** spec + **strong** quality | — |
| [W7-T2](W7-T2-prompt-injection-real-llm-layer.md) | Real-LLM layer (ED6), flag/marker-gated, non-gating | `wf-eval-designer` | **strong** quality | W7-T1 |
| [W7-T3](W7-T3-cross-vendor-routing-rerun.md) | Cross-vendor routing re-run for 3 new Wave-1 plugins | `wf-eval-designer` | sonnet spec + quality | W1 plugins |
| [W7-T4](W7-T4-gate-evidence-p1-readiness.md) | G-* gate evidence doc + P1 readiness; flip ADR-0033 → Accepted | `wf-release-auditor` (strong) | **strong** quality | W7-T1..T3 |

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
- **W7** is last (needs all plugins + auth + infra in place to evaluate). T1 first (defines the
  corpus + loader); T2 after T1 (shared loader, different module); T3 parallel (disjoint file,
  `test_routing_eval.py`); T4 last (cites T1/T2/T3, flips ADR-0033 + roadmap on green).
  **Rebase the W7 branch onto `origin/main` first** (W6 squash-merged `01e46c9`).

## Spec template

Every spec uses the same sections: **Metadata · Objective · Scope (In/Out) · Deliverables ·
Requirements · Contracts · Test & gate plan · Exit criteria · Workflow · Risks.**
Requirements are grounded line-by-line in the cited ADR/PRODUCTION.md §; nothing here
re-decides an ADR — these specs *implement* the W0 design gate (ADR-0025…0032).
