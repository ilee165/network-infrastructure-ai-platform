# NetOps P5 W1 — Durability Rider

This rider holds the prescriptive constraints for
`/mnt/d/Multi-Agent workflow/network-infrastructure-ai-platform/.worktrees/p5-w1-goal/docs/goals/2026-07-22-2323-netops-p5-w1-durability-goal.md`.
It supersedes nothing in prior riders; their invariants still apply. It adds
the execution contract for the three P5 W1 tasks. The authority order is
`AGENTS.md` → `docs/architecture/DECISIONS-BRIEF.md` → ADR-0059 →
`docs/roadmap/P5-PLAN.md` → the three W1 deep specs → this rider.

All paths below are relative to repository root
`/mnt/d/Multi-Agent workflow/network-infrastructure-ai-platform/.worktrees/p5-w1-goal`
unless explicitly absolute.

## Posture (decided — do not redesign)

- P5 remains contracted and W1 is debt closure. Do not pull W2 cloud work, W3
  hybrid topology, W4 scale certification, or W5 release work forward.
- Start from refreshed `origin/main` at or after merge `17638820`; branch
  `feat/p5-w1`. `git log origin/main..HEAD` must contain only this goal+rider
  and W1 work.
- ADR-0059 is decided. Transport is at least once; the stable dispatch ID and
  atomic consumer claim provide exactly one render/state-transition effect.
  Never claim exactly-once delivery.
- Outbox envelopes contain allowlisted task names, queues, aggregate IDs, and
  safe payload IDs only. No report body, credential, token, raw exception, or
  other secret-bearing material.
- Alembic is expand-only. PostgreSQL is authoritative; Redis/Celery is not
  transactionally joined and Neo4j is irrelevant to this wave.
- Preserve task names, queue routing, countdown/ETA, and existing caller
  idempotency. Do not create queues or change task business behavior in T2.
- Reconciliation changes observe existing state. Do not change retention,
  backup scheduling, ChangeRequest lifecycle, audit-chain semantics, or trace
  persistence semantics.
- W1-T1 is an escalation surface: strong implementer, dual strong reviewers,
  strong fixer, strong verifier. Resolve the live strong model before launch;
  stop if unavailable. T2/T3 use repository tiers.
- No `git push`. Do not modify or discard unrelated work. After a kill or
  transient API error, trust git, validate coherent uncommitted work, commit
  salvageable scope, and focused-rerun gaps.

## Data model and state machines

### `dispatch_outbox` (PostgreSQL, expand-only)

The migration and ORM model match ADR-0059 exactly:

| Field | Contract |
|---|---|
| `id` UUID | Immutable dispatch identity and Celery `task_id`. |
| `aggregate_type`, `aggregate_id` | Initially report run; never secret data. |
| `task_name`, `queue`, `payload_json` | Allowlisted safe envelope. |
| `state` | `pending`, `claimed`, `dispatched`, `dead`. |
| `attempts`, `available_at` | Bounded retry/backoff state. |
| `claimed_at`, `claim_owner` | Lease ownership and stale recovery. |
| `created_at`, `dispatched_at` | Lifecycle timestamps. |
| `last_error_code` | Stable redacted code, never raw exception text. |

Unique key: `(aggregate_type, aggregate_id, task_name)`.

State transitions:

```text
pending --claim/commit--> claimed --broker ack--> dispatched
   ^                         |
   |-- retry/backoff --------|
   |-- stale-lease reaper ---|
claimed --nonretryable/exhausted--> dead --audited RBAC replay--> pending
```

Claim at most a configured bounded batch with `FOR UPDATE SKIP LOCKED`. Commit
the claim before broker publication. A pre-send crash becomes a stale lease.
A post-send/pre-mark crash redelivers the same `dispatch_id`; the consumer's
atomic report-run claim returns the existing result without rendering or
transitioning twice.

### Reconciliation outputs

Do not add high-cardinality labels. Each job emits aggregate status/count and
last-success/freshness series sufficient for recording and alert rules:

| Row | Inconsistency | Required exclusions / grace |
|---|---|---|
| 5 | Due scheduled config backup lacks terminal success | Disabled schedules excluded; alert within 15 minutes of miss. |
| 6 | Executed terminal ChangeRequest lacks required audit lifecycle records | Daily run; query failure is failure, never zero. |
| 9 | Required session lacks trace, trace lacks session, or step lacks trace parent | Apply one documented settled grace window. |

Jobs are idempotent. Repeating a healthy or unhealthy run does not create
duplicate durable effects. If PG joins/locking determine behavior, cover them
in integration-marked real-PG tests.

## Algorithms and contracts

### Atomic report enqueue

```text
request_report(transaction, report_request):
    create_or_transition_report_run(transaction)
    insert dispatch_outbox with unique aggregate/task key
    commit both together
    return report_run
```

There is no Celery call before commit and no post-commit direct publication in
either scheduled or on-demand request paths. Rollback leaves neither the new
transition nor an outbox row.

### Relay and recovery

```text
relay(batch_size, owner, now):
    claim eligible pending rows with SKIP LOCKED
    commit claims
    for each row:
        durable_dispatch(..., task_id=row.id)
        on ack: mark dispatched
        on retryable failure: attempts++, set available_at, clear lease
        on invalid/exhausted: mark dead with redacted error code

reap(now):
    return expired claimed rows to pending and increment recovered metric
```

Metrics cover pending count, oldest pending age, claims, retries, dead rows,
stale recoveries, failures, and duplicate consumer claims. Alerts resolve to
`docs/runbooks/report-outbox-relay.md`. Dead-row replay is an audited,
RBAC-protected operation that revalidates allowlisting and replay safety.

### Static publication ratchet

Use AST analysis, not raw substring grep. The checker rejects `.send_task`,
direct `apply_async`, and `.delay` outside the wrapper and a path+symbol scoped
allowlist. It detects aliases, multiline calls, and nested paths. Checked-in
fixtures cover each forbidden syntax and accepted wrapper use. Removing any
visitor branch must make its fixture test fail. Any exception is documented
with path, symbol, reason, and test; the target is an empty allowlist.

### Reconciliation alert contract

Every row has:

1. a bounded-label emitted series and last-success/freshness signal;
2. recording rules;
3. burn/staleness alerts with resolvable runbook URLs;
4. should-fire and should-not-fire promtool cases;
5. a mutation/negative-control bite that demonstrates the gate turns red.

Thresholds inherited from the contract are 15 minutes for a missed backup and
daily CR reconciliation. The trace grace window must be derived from existing
session/trace write timing, documented beside the rule, and tested at both
boundary sides; do not invent an unexplained constant.

## Phases (nine checkpoints)

The unit of resumability is one atomic commit per W1 task. Each task uses the
repository workflow: implementer writes named tests first and proves red,
implements, runs gates, commits; reviewers inspect the commit; a conditional
fixer commits enumerated must-fixes; a verifier confirms them. Review comments
outside correctness, security, test gaps, and performance regressions are
advisory and do not expand scope.

### P1 — Preflight, ownership census, and guarded workflow

- Fetch `origin/main`; verify branch ancestry and empty unexpected commit range.
- Read `.claude/agents/README.md` and `.claude/workflows/README.md`.
- Query Graphify before raw searches; confirm source ownership for T1/T2/T3.
- Check for overlap before parallel task launches. If overlap exists, sequence
  the tasks; only their two reviewers remain parallel.
- Capture `BASELINE = budget.spent()` and arm a baseline-relative usage guard.
- Confirm a live strong model for every T1 role.

Checks:
- `p5_w1_branch_descends_from_refreshed_origin_main`
- `p5_w1_commit_range_contains_no_prior_wave_history`
- `w1_task_file_ownership_overlap_is_resolved_before_launch`
- `w1_t1_live_strong_model_is_resolved`
- `workflow_usage_guard_is_baseline_relative`

### P2 — W1-T1 red proofs and implementation

The T1 implementer owns the outbox migration/model/service, report request
integration, relay/reaper/consumer idempotency, recovery API, related metrics
and alerts/runbook, and focused tests. Write named tests first:

- `report_outbox_rollback_persists_neither_transition_nor_envelope`
- `report_outbox_committed_row_survives_crash_before_relay`
- `report_outbox_scheduled_and_ondemand_paths_share_atomic_enqueue`
- `report_outbox_concurrent_relays_claim_each_row_once`
- `report_outbox_stale_claim_returns_to_pending_after_lease`
- `report_outbox_post_send_pre_mark_redelivery_renders_once`
- `report_outbox_poison_envelope_becomes_dead_with_redacted_code`
- `report_outbox_dead_requeue_requires_rbac_and_writes_audit_event`
- `report_outbox_payload_and_metrics_never_contain_secret_or_raw_error`
- `report_outbox_duplicate_consumer_returns_existing_terminal_result`

All row-locking/crash-window assertions run against real PostgreSQL. Every new
`backend/tests/pg/*.py` file has module-level
`pytestmark = pytest.mark.integration`.

### P3 — W1-T1 strong review, fix, and evidence checkpoint

- Run dual strong spec/quality review over the committed T1 diff.
- Apply only enumerated must-fixes through the strong fixer; strong verifier
  reports no remaining finding.
- Show integration collection, focused real-PG results, report conformance,
  migration check, D16, `pg-integration`, promtool, and ≥80% new-module
  coverage evidence.
- Retain the red proof for the old crash window and alert/rule bite.

Checks:
- `report_outbox_every_adr_0059_crash_window_is_named_and_green_on_postgres`
- `report_outbox_transport_claim_is_at_least_once_not_exactly_once`
- `report_outbox_strong_reviews_and_verifier_are_clean`

### P4 — W1-T2 red proofs and implementation

The T2 implementer owns the site inventory, wrapper migration, AST checker,
fixtures/tests, blocking CI wiring, and documentation. Named tests:

- `dispatch_ratchet_inventory_has_zero_unjustified_bare_sites`
- `dispatch_ratchet_rejects_send_task_alias_and_multiline_forms`
- `dispatch_ratchet_rejects_apply_async_outside_wrapper`
- `dispatch_ratchet_rejects_delay_outside_wrapper`
- `dispatch_ratchet_checks_nested_paths`
- `dispatch_ratchet_accepts_only_path_symbol_scoped_exceptions`
- `dispatch_wrapper_preserves_queue_countdown_eta_and_task_id`
- `dispatch_wrapper_redacts_publication_errors`
- `dispatch_ratchet_mutating_each_visitor_branch_makes_fixture_fail`
- `dispatch_ratchet_blocking_ci_step_executes_the_negative_control`

The before/after census records every site. If an exception remains, stop and
justify it against ADR-0059 rather than silently widening an allowlist.

### P5 — W1-T2 review and gate-bite checkpoint

- Review the task commit per repository tier; conditionally fix and verify.
- Run checker tests, existing worker/task dispatch tests, import-linter, ruff,
  mypy, full unit suite, and the blocking CI-equivalent command.
- Plant each forbidden form and capture non-zero output; remove planted calls.
- Prove the final census has zero unjustified calls.

Checks:
- `dispatch_ratchet_runs_in_a_blocking_gate`
- `dispatch_ratchet_negative_control_is_red_then_clean_tree_is_green`
- `dispatch_sweep_preserves_existing_routing_behavior`

### P6 — W1-T3 red proofs and implementation

The T3 observability implementer owns the three jobs, series, rule/test files,
fault fixtures/harness, runbooks, chart rendering seams, and PRODUCTION.md §6
rows 5/6/9. Named tests:

- `backup_reconcile_alerts_within_fifteen_minutes_of_due_miss`
- `backup_reconcile_excludes_disabled_schedules_and_accepts_terminal_success`
- `backup_reconcile_is_idempotent_at_boundary_times`
- `cr_audit_reconcile_counts_executed_terminal_change_without_lifecycle_audit`
- `cr_audit_reconcile_fails_closed_on_query_error`
- `cr_audit_reconcile_repeat_run_does_not_duplicate_effects`
- `trace_reconcile_finds_required_session_without_trace`
- `trace_reconcile_finds_trace_without_session`
- `trace_reconcile_finds_step_without_trace_parent`
- `trace_reconcile_respects_both_sides_of_settled_grace_window`
- `reconciliation_series_have_bounded_labels_and_freshness`
- `reconciliation_alerts_all_resolve_to_existing_runbook_urls`

Use PG integration tests where database join semantics matter.

### P7 — W1-T3 review and observability bite checkpoint

- Review per repository tier; conditionally fix and verify.
- Run unit/PG tests, chart/render checks, D16, `promtool check rules`, and all
  should-fire/should-not-fire rule tests.
- Prove planted missed backup, CR-without-audit, and orphan trace each fire.
- Mutate each alert/rule path so the bite harness fails, then restore it.
- Confirm PRODUCTION.md §6 rows 5/6/9 say backed and match deployed series.

Checks:
- `reconciliation_three_planted_inconsistencies_fire`
- `reconciliation_healthy_and_grace_cases_stay_quiet`
- `reconciliation_rules_are_deployed_from_the_promtool_checked_source`
- `production_rows_5_6_9_are_backed_without_semantic_drift`

### P8 — Cross-task integration and failure audit

- Run the complete backend, PG integration, observability, report conformance,
  migration, static-ratchet, and documentation drift lanes together.
- Confirm the T1 wrapper is the T2-approved publication boundary and the
  static checker does not exempt the outbox relay accidentally.
- Confirm T1/T3 metrics do not create unbounded labels and all alert URLs
  resolve.
- If integration exposes a defect, create a focused enumerated fix task,
  commit it atomically, and verify only after the relevant full lanes pass.

Checks:
- `outbox_relay_uses_the_only_ratchet_approved_publication_boundary`
- `w1_metrics_and_alerts_have_bounded_labels_and_resolving_runbooks`
- `w1_full_gate_matrix_runs_and_bites_after_integration`

### P9 — Wave closeout (documentation and evidence only)

- Update P5 wave status/evidence without flipping ADR-0059 to Accepted; ADRs
  remain Proposed until W5-T3.
- Run `graphify update .` after code commits.
- Show `git log origin/main..HEAD --oneline`, `git status --short`, task commit
  SHAs, review/verifier verdicts, red-bite evidence, and final green commands.
- Do not push or open a PR unless separately requested.

Checks:
- `p5_w1_all_three_deep_spec_exit_criteria_are_mapped_to_evidence`
- `p5_w1_graphify_index_is_current`
- `p5_w1_branch_is_clean_and_contains_only_goal_and_w1_commits`

## Integration matrix

| Concern | T1 outbox | T2 ratchet | T3 reconciliation |
|---|---|---|---|
| PostgreSQL semantics | Required real-PG crash/locking tests | Existing dispatch tests unless DB-dependent | Real PG for join semantics |
| Negative control | Old crash window / muted alert | Planted forbidden calls + visitor mutation | Three planted inconsistencies + rule mutation |
| Observability | Relay lag/retry/dead/recovery | Redacted wrapper failures | Completeness/orphan/freshness series |
| CI gate | D16 + pg-integration + report conformance + promtool | Blocking AST ratchet + D16 | D16 + PG where needed + promtool/chart |
| Documentation | Relay runbook/API docs | Site inventory/wrapper contract | Three runbooks + PRODUCTION §6 |
| Review tier | Dual strong throughout | Repository non-secret tier | Observability repository tier |

## Error and recovery canonical pairs

| Error | Recovery |
|---|---|
| Strong model cannot be resolved for T1 | Stop before launch; select a live strong model and restart T1. |
| Branch contains pre-W1 commits not on `origin/main` | Rebase onto refreshed main without discarding work; show the clean range. |
| Outbox row is stuck `claimed` past lease | Run the lease reaper; inspect relay owner and recovery metrics. |
| Outbox row is `dead` | Diagnose the stable redacted code; use audited RBAC requeue only after replay-safety validation. |
| Ratchet finds a bare publication | Route the site through the wrapper; do not add a broad exception. |
| Reconciliation query fails | Mark the job failed/stale and alert; never emit a healthy zero. |
| promtool syntax passes but fixture does not fire | Treat as gate failure; fix the rule/test and rerun the mutation bite. |
| Workflow stops on budget or API failure | Trust git, validate salvageable work, commit it, and focused-rerun only gaps. |

## Out of scope

- P5 W2–W5 implementation: cloud vendors, hybrid topology, scale execution,
  eval corpus, release readiness, or ADR acceptance.
- A general event bus, general workflow engine, new queues, or task behavior
  changes unrelated to publication durability.
- Exactly-once transport claims or distributed transactions spanning
  PostgreSQL and Redis/Celery.
- Report schema redesign, report-content changes, retention changes, or new
  artifact destinations.
- Audit hash-chain, ChangeRequest lifecycle, backup scheduler, or reasoning
  trace persistence redesign.
- Broad CI refactors, dependency upgrades, unrelated cleanup, `git push`, PR,
  or merge.

## Dependencies

- Tier 1: existing Python/FastAPI/SQLAlchemy/Alembic/Celery/Prometheus tooling;
  AST facilities already available in the Python runtime.
- Tier 2: no new architectural dependency expected. Any proposed dependency
  must be justified against ADR-0059 and resolved into the uv lockfile in the
  same commit.
- Tier 3: no Kafka/event-bus introduction, cloud service, live LLM, or
  certified-scale environment.

## Engineering invariants

- The report transition and outbox insert commit or roll back together.
- Stable `dispatch_id` is both durable identity and Celery task ID; unique
  aggregate/task key prevents duplicate envelopes.
- Broker acknowledgement is not a business-effect guarantee. Consumer
  idempotency owns exactly-one effect.
- Claims are bounded and concurrency-safe; stale leases recover; retries are
  bounded; dead rows are visible and replay is audited/RBAC-protected.
- Payloads, metrics, logs, and errors do not leak report content or secrets.
- The static checker has syntax-variant fixtures and mutation proof; broad
  allowlists and raw grep-only enforcement are forbidden.
- Reconciliation query failure is unhealthy/stale, never a zero discrepancy.
- Metrics use bounded labels; promtool-checked rules are the same source the
  Helm chart deploys.
- New PG test modules carry `pytestmark = pytest.mark.integration`, and
  collection is proven explicitly.
- No silent scope expansion. Record future work in the existing roadmap
  mechanism; do not implement it in W1.

## Process invariants

- One resumable atomic commit per task; review/fix commits remain narrowly
  attributable. Never combine unrelated tasks to save a commit.
- Tests are written first and observed red. Every new gate both runs and
  bites; retain the red transcript/run URL and final green evidence.
- Review scope follows `docs/CODERABBIT_REVIEW_POLICY.md`: correctness,
  security, test gaps, and performance regressions. Architecture, naming,
  refactor taste, and doc rewrites do not become must-fixes.
- T1 uses live strong roles end to end. Never silently downgrade or treat a
  dead-model “clean” result as review.
- Parallelize T1/T2/T3 only after an ownership census proves disjoint writes.
  Within each task, parallelize the two reviewers only.
- Use targeted tests during TDD and full relevant gates once before commit.
- Keep workflow prompts task-factual; role discipline stays in role files.
- The workflow usage guard is baseline-relative. On trip, return a commit/SHA
  and remaining-task summary.
- After any kill or transient 5xx, do not `reset --hard`; salvage coherent
  work and focused-rerun gaps.
- P9 updates wave status/evidence and Graphify. ADR-0059 remains Proposed until
  P5 release audit.
