GOAL: Deliver P5 W1 from clean, updated `origin/main`: close report-dispatch loss and duplicate-effect windows with ADR-0059's transactional outbox, eliminate bare Celery publication behind a biting static ratchet, and back PRODUCTION.md §6 reconciliation rows 5/6/9 with jobs, rules, alerts, runbooks, and fault evidence. Headline: Durable.

**Read first.** Repo root R = `/mnt/d/Multi-Agent workflow/network-infrastructure-ai-platform/.worktrees/p5-w1-goal`.

- `R/docs/goals/2026-07-22-2323-netops-p5-w1-durability-rider.md`.
- `R/docs/roadmap/P5-PLAN.md` §0/§0a/§3 and `R/docs/roadmap/p5-tasks/README.md` W1.
- `R/docs/roadmap/p5-tasks/W1-T1-report-outbox-relay.md`, `W1-T2-send-task-ratchet.md`, and `W1-T3-observability-reconciliation.md`.
- `R/docs/adr/0059-durable-dispatch.md` and `R/docs/roadmap/PRODUCTION.md` §6/§11.
- `R/.claude/agents/README.md` and `R/.claude/workflows/README.md`.

**Preflight.** Fetch `origin/main`; work on `feat/p5-w1` based at or after `17638820`. Prove `git log origin/main..HEAD --oneline` contains only W1 work and this pair. Preserve unrelated work; never reset it. Query Graphify first when its graph exists.

**Posture.** Implement only W1-T1/T2/T3; no cloud, hybrid-topology, scale, retention, or audit-chain redesign. Migrations are expand-only. Payloads contain IDs, never secrets. At-least-once publication plus idempotent consumption is the claim—never “exactly once.” No new queues or changed routing. No `git push`. W1-T1 is escalated: implementer, both reviewers, fixer, and verifier use the live strong model. T2/T3 use repository tiers. Arm a baseline-relative usage guard.

**Three task outcomes.**

- **T1 outbox.** Both scheduled and on-demand report paths atomically persist the run transition and unique safe envelope; bounded `SKIP LOCKED` claims, lease recovery, retry/dead handling, audited RBAC requeue, stable dispatch ID, idempotent consumer, metrics/alerts/runbook. Real-PG tests enumerate every ADR-0059 crash window.
- **T2 ratchet.** Inventory all publication sites, route them through the hardened wrapper without behavior drift, and block `.send_task`, direct `apply_async`, and `.delay` outside path+symbol exceptions. Target an empty allowlist; syntax fixtures and mutation proof bite.
- **T3 reconciliation.** Idempotent jobs detect missed scheduled backups within 15 minutes, executed terminal CRs missing required audit lifecycle records, and trace/session/step orphans after a settled grace window. Series have bounded labels; recording/burn/staleness rules, runbook URLs, healthy cases, and planted inconsistencies are promtool-proven. Flip §6 rows 5/6/9 to backed.

**Workflow.** Execute the rider's P1–P9 checkpoints. Each task follows implementer → spec + quality review → conditional fixer → verifier and ends as one resumable atomic task commit. Parallelize tasks only after an ownership check; reviews may parallelize. After a kill/5xx, salvage coherent work and rerun only gaps.

**Verification.**

- T1: integration collection proves every new `backend/tests/pg/*.py` is marked; real-PG crash tests, report conformance, migration check, D16, `pg-integration`, and outbox promtool tests pass; coverage on new modules is at least 80%.
- T2: the site inventory reports zero unjustified bare publication calls; every forbidden syntax fixture returns non-zero; the blocking CI gate and existing dispatch tests pass.
- T3: `promtool check/test rules` passes; planted missed-backup, CR-without-audit, and orphan-trace cases fire while healthy/grace cases stay quiet; D16 passes.
- Final `git log origin/main..HEAD --oneline` contains only this pair plus the W1 task/fix commits; `git status --short` is clean; Graphify is updated.

**Stop when** all three specs' exit criteria and transcript-provable checks pass, the reviewed fixes are verified, W1 status/evidence is recorded, and all work is committed locally—or stop after 30 turns and report the exact failing gate or unfinished task.
