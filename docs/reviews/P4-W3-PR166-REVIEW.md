# P4 W3 / PR #166 Review Report

**Pull request:** [#166 — Compliance & audit reporting suite](https://github.com/ilee165/network-infrastructure-ai-platform/pull/166)  
**Reviewed head:** `da8904eb296260ffaa55e00d656664b0b32511e9`  
**Review:** [COMMENT review with 11 inline findings](https://github.com/ilee165/network-infrastructure-ai-platform/pull/166#pullrequestreview-4729520152)  
**Disposition:** **Not merge-ready — remediation and a clean re-review are required.**

## Outcome

The wave is implemented across W3-T1 through W3-T6, but the current PR head
does not satisfy the W3 exit criteria. The focused report suite is strong and
the design is cohesive; release-blocking PostgreSQL, supply-chain, evidence,
and observability gaps remain.

**Grade: D+ (58/100).**

| Area | Score | Review summary |
|---|---:|---|
| Correctness / evidence integrity | 14/30 | Real-PG claim failure, clock-derived schedule identity, stuck-run path, incomplete compliance coverage, mutable verification history |
| Security | 11/20 | Vulnerable PDF dependency, unbounded generation input, incomplete CSV-injection prefix coverage, audit gap |
| Tests / verification | 15/20 | 207 focused tests pass, but required PG and security gates fail and key prefork/deployment seams are untested |
| Performance / scalability | 8/15 | Unbounded report windows and existing artifact/N+1 review threads leave material scale risks |
| Operability / maintainability | 10/15 | Good runbook/promtool work, but worker metrics are not scrape-correct and the new alert rules are not deployed |
| **Total** | **58/100** | **D+ — not merge-ready** |

## Verification evidence

- Focused local suite: **207 passed, 1 skipped**.
- Required CI failures at the reviewed head:
  - [Real-PostgreSQL integration](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29664425838/job/88132368869): concurrent report claim raises `UniqueViolationError`.
  - [Backend dependency audit](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29664425838/job/88132368873): WeasyPrint advisories fail `pip-audit`.
  - [Backend image scan](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29664425838/job/88132368840): HIGH WeasyPrint CVE fails Trivy.
- The review was read-only: no product code, branch, commit, or PR metadata was changed.
- Eleven new inline comments were posted; unresolved pre-existing review threads
  remain a separate remediation input and were not duplicated here.

## Blocking findings

### 1. PostgreSQL claim arbitration fails under concurrency

`backend/app/workers/tasks/reports.py:164` uses `ON CONFLICT (id) DO NOTHING`,
while the same row also participates in `uq_report_runs_kind_period`.
PostgreSQL can surface the natural-key violation before the loser classifies
the existing row, which is exactly what the blocking real-PG test reports.

**Required proof:** target the correct conflict domain (or all unique conflicts),
classify the existing natural-key row, and keep the concurrent real-PG test green.

### 2. The PDF dependency range excludes its security fix

`backend/pyproject.toml` resolves WeasyPrint 65.1 and caps the dependency below
66. Both `pip-audit` and image Trivy reject that version; the security-fixed
release named by the scanner is 68.0.

**Required proof:** adopt a supported fixed release, regenerate the lock, and
show both dependency and backend-image scans green without suppressing a
fixable finding.

### 3. Report metrics do not survive Celery prefork

Report counters/gauges/histograms are updated in task-pool children, while the
metrics HTTP server is started in the Celery main process using the default
Prometheus registry. Production uses prefork concurrency and does not configure
the Prometheus multiprocess collector, so the new alerts do not have a reliable
source series.

**Required proof:** use a prefork-safe collector/export path and add a real
task-to-scrape test.

### 4. Report alert rules are never installed

`deploy/observability/report-engine.alerts.yaml` is checked and mutation-tested
in CI, but no Helm `PrometheusRule`, ConfigMap, values seam, or Compose path
loads it. The shipped deployment creates none of the four report alerts.

**Required proof:** render the rule groups through the chart's opt-in
PrometheusRule path and assert them in rendered-chart tests.

### 5. Persistence failures leave non-terminal runs

Artifact insertion, audit recording, or the final commit can raise after the
claim row is committed. That path bypasses `_fail_run`, has no task retry, and
can leave the period permanently `running`.

**Required proof:** typed persistence-failure handling plus safe
retry/reconciliation and an injected database-failure test.

### 6. Scheduled identity is based on worker execution time

Beat messages carry only the report kind. The worker derives the period from
its own current clock and settings, so a delayed weekly task or redelivery
crossing UTC midnight can target a different period and run ID.

**Required proof:** put the scheduled slot/bounds in the dispatched message and
test delayed/redelivered ticks across UTC boundaries.

### 7. On-demand report periods are unbounded

API and Documentation-Agent validation reject inverted/future intervals but
set no maximum span. Compliance and audit builders expand each day in memory;
an authorized year-1-to-present request creates roughly 740,000 rows before
CSV/PDF rendering.

**Required proof:** enforce a justified bound at both entry points or redesign
the builders/renderers with hard streaming/resource limits; test the boundary.

### 8. Supported devices without snapshots disappear from posture evidence

The daily sweep skips devices with no snapshot, and the report builds its
device table only from finding rows. A mostly unevaluated supported estate can
therefore look like a small passing estate with no explicit coverage gap.

**Required proof:** surface supported-but-unevaluated devices and cover a mixed
evaluated/unevaluated estate.

### 9. Audit-verification history is mutable evidence

`audit_chain_verification_runs` is a normal mutable table outside the audit hash
chain and lacks append-only privilege/trigger protection. Its `break` or grant
`violation` outcomes can be rewritten to `clean`, and the report trusts the
rewritten rows.

**Required proof:** make the history append-only or cryptographically anchored
and add a PostgreSQL tamper test that must fail loudly.

## Additional findings

- The Documentation-Agent generation path sends the Celery task without the
  API path's durable `report.generation_requested` audit event; the generic
  tool sink is post-execution structlog by default.
- CSV formula neutralization covers tab and carriage return but omits the OWASP
  line-feed prefix case.

## Remediation exit gate

PR #166 can be re-graded only after:

1. all P1 findings above are resolved with biting regression tests;
2. the three currently failing required CI jobs are green on the same head;
3. existing unresolved correctness/security/test/performance review threads are
   adjudicated and either fixed or rejected with evidence;
4. the focused report suite and full repository gates remain green; and
5. a follow-up review confirms the prefork metrics and rendered-alert deployment
   paths, not only their source files.
