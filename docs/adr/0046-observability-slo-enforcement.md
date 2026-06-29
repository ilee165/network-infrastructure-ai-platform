# ADR-0046: Observability-SLO Enforcement (Recording Rules, Multi-Window Burn-Rate Alerts, Golden-Signal Dashboards, Fault-Injection MTTD)

**Status:** Proposed | **Date:** 2026-06-29 | **Milestone:** P3 W0

## Context

`PRODUCTION.md` §6 fixes nine observability **SLOs** (the SLI / SLO / "measured
by" table), and §11 **G-OBS** turns them into release criteria: every §6 SLO must
have a **recording rule** and a **multi-window burn-rate alert**; every alert must
link a **runbook** with freshness ≤ 90 days (§336); **golden-signal dashboards**
(latency / traffic / errors / saturation) must exist for api, each worker queue,
Postgres, Neo4j, Redis, and LLM providers (§335); and a **fault-injection
exercise** (DB down, queue stall, LLM-provider failure) must be detected by alerts
with **MTTD < 5 min** each (§337). ADR-0015 (D15) already ships the *measurement*
plane — structlog JSON, Prometheus `/metrics`, OTel tracing, health endpoints, and
the `netops_*` domain metric set — and §6 is explicitly the **P2-Security
measurement / P3-Platform enforcement** split. This ADR is the P3 enforcement half:
it ratifies *how* the §6 SLOs become enforced so the build wave (W3-T2…W3-T5) has a
fixed contract, not an improvised one.

This ADR is the **design gate**. It ratifies the recording-rule naming convention,
the burn-rate methodology + budget/window pairs, the runbook-link rule, the
dashboard-as-code format, the fault-injection scenarios + MTTD budget, and the
**alert-as-test gate** (`promtool` firing proof). It does **not** implement them —
W3-T2 writes the recording rules, W3-T3 the burn-rate alerts + `promtool` firing
tests + runbook links, W3-T4 the dashboards-as-code, and W3-T5 the fault-injection
MTTD harness.

Bounded by **ADR-0015** (observability — the metric set, the `netops_*` namespace,
expose-don't-bundle posture, and the cardinality discipline this ADR's rules sit
on), **ADR-0045** (audit→SIEM export — the export-lag SLI is the §6 row whose
recording rule and burn-rate alert live in *this* enforcement wave), **ADR-0016**
(testing/CI — the `promtool` gate joins `all-gates` under the D16 contract), and the
P3 ADRs whose HA/scale-out mechanisms these SLIs observe (ADR-0042 PG HA, ADR-0043
HPA/KEDA, ADR-0044 Redis Sentinel / WebSocket fan-out). `PRODUCTION.md` §6 (the
nine-row SLO table), §11 G-OBS §§334–339, and §12 (the Consultant scale / GPU /
retention open items the SLO targets remain **PROPOSED** against) are the
line-by-line source.

Per `P3-PLATFORM-PLAN.md` §0, **G-OBS is fully enforceable in CI** (`promtool` over
synthetic series — no cluster required) and is targeted as a **true full PASS**,
unlike the reduced-scale + named-ceiling posture that G-SCA / G-REL carry. The
**live-cluster** MTTD run (alerts firing against a real fault on the W4-T1 kind
cluster) is the W4 / W5 soak proof; the in-CI `promtool`-over-synthetic-series MTTD
proof is what this ADR mandates as the *blocking* gate (named-deferred live run only
where §0 allows). The defining risk of this enforcement phase (P1-W4 lesson) is a
**green-at-setup alert that never fires** — the alert-as-test gate (§6 below) is the
guard, fixed here so it is not improvised in W3.

## Decision

**Each of the nine §6 SLIs gets exactly one Prometheus recording rule that names the
SLI and pre-computes its ratio/quantile; each SLO gets a multi-window
multi-burn-rate alert (a fast burn + slow burn window pair over the SLO's error
budget, à la the Google SRE method), single-threshold trips disallowed; every alert
carries a mandatory `runbook_url` annotation pointing at an in-repo runbook with
freshness ≤ 90 days; golden-signal (latency / traffic / errors / saturation)
dashboards for api, each worker queue, Postgres, Neo4j, Redis, and LLM providers
ship as linted dashboards-as-code in the repo; a fault-injection harness drives
synthetic DB-down / queue-stall / LLM-provider-failure series and proves each alert
fires within an MTTD < 5 min budget; and every alert ships a *should-fire*
`promtool test rules` case — the anti-false-green gate that must RUN and BITE before
it joins `all-gates`.**

### 1. One recording rule per §6 SLI — naming the SLI (the load-bearing convention)

Each of the **nine** §6 SLIs gets **exactly one** recording rule that pre-computes
the SLI value (a success ratio, a latency quantile, or a lag/freshness gauge) so the
alert and the dashboard both read the *same* derived series — never two divergent
ad-hoc PromQL expressions for the "same" SLI.

- **Naming convention:** recording rules follow Prometheus' canonical
  `level:metric:operation` form, namespaced to the platform and named for the SLI,
  e.g. `slo:netops_api_availability:ratio_rate5m`,
  `slo:netops_api_read_latency:p95_5m`,
  `slo:netops_discovery_success:ratio_rate_run`,
  `slo:netops_audit_siem_export_lag:seconds` (the ADR-0045 export-lag gauge),
  `slo:netops_topology_projection_lag:seconds`. The `slo:` prefix marks the rule as
  an SLI series; the middle segment **names the SLI** (the §6 row); the suffix names
  the window/operation. The base metrics are the existing ADR-0015 `netops_*`
  series (and the ADR-0045 export-lag gauge); the recording rules derive SLIs from
  them, they do not introduce new instrumentation.
- **One-to-one with §6.** The nine rows are: API availability, API read latency,
  agent chat first-token latency, discovery job success rate, scheduled-config-backup
  completeness, ChangeRequest-execution→audit completeness, topology projection
  freshness, audit→SIEM export lag, and reasoning-trace persistence. **W3-T2 ships a
  recording rule for each** — the gate asserts a 1:1 row↔rule mapping (a missing rule
  is an incomplete SLI), closing the "the dashboard says 99.9% but the alert computes
  it differently" drift.
- **Cardinality discipline (ADR-0015 §2 carry).** SLI recording rules aggregate to
  the SLO's reporting dimension only (e.g. per-queue for discovery success, global
  for API availability) — no high-cardinality label (`device_id`, raw path) leaks
  into an SLI series.

### 2. Multi-window multi-burn-rate alerts — fast + slow window pair per error budget (single-threshold trips disallowed)

Every §6 SLO is alerted with a **multi-window multi-burn-rate** rule, not a single
static threshold. For an availability/success SLO with target `T` over the §6
window, the **error budget** is `1 − T`; the alert fires when the *burn rate*
(error rate ÷ budget-consuming rate) is high over **both** a fast window and a slow
confirmation window simultaneously — the Google SRE multi-window method that pages
fast on a real fast burn yet resists single-spike flapping.

- **Window pair + budget stated in the rule comment.** Each alert rule carries, in a
  comment/annotation, the **SLO target**, the **error budget** (`1 − T`), and the
  **window pair + burn-rate factor** it trips on (e.g. for the ≥99.9%/30-day API
  availability SLO: a **page** tier at ~14.4× burn over a 5 m / 1 h window pair, and
  a **ticket** tier at ~6× burn over a 30 m / 6 h pair — the standard 2 %-in-1 h /
  5 %-in-6 h budget-consumption tiers). The exact factors per SLO are fixed in W3-T3
  against §6 targets; the methodology (fast+slow pair, budget-relative) is fixed
  **here**.
- **Single-threshold trips disallowed.** A `for: 5m` over a raw threshold (e.g.
  "latency > 300 ms") is **not** an acceptable SLO alert — it is noisy and slow and
  does not relate the symptom to the error budget. The W3-T3 gate rejects any §6 SLO
  alert that is not a multi-window burn-rate rule (the SLI it reads is the §1
  recording rule). Latency SLOs (API read p95<300 ms/p99<1 s, first-token p95) are
  expressed as a burn-rate over the fraction of requests exceeding the objective
  threshold; lag/freshness SLOs (export lag p95<60 s, projection lag <5 min,
  backup-miss <15 min) are alerted on the §1 lag/freshness recording rule breaching
  the objective over the fast+slow window pair.

### 3. Runbook link mandatory — an alert with no runbook is incomplete (G-OBS §336)

Every alert rule **must** carry a `runbook_url` annotation resolving to an in-repo
runbook under `docs/runbooks/` (the existing runbook home — e.g. the DR runbooks and
`kind-harness.md` already live there). An alert with no runbook is **incomplete**
and the W3-T3 gate rejects it (G-OBS §336: "every alert links to a runbook").

- **Freshness ≤ 90 days (§336).** Each SLO runbook carries a `last-reviewed` date;
  a freshness check (the W3-T3/W5 gate) fails a runbook older than 90 days, matching
  the §336 freshness clause. The runbooks are generated/maintained by the
  Documentation Agent (ADR-0015 §2 / §6 dogfooding) — this ADR fixes the *contract*
  (every alert → a runbook path, freshness-checked), not the prose.
- **No broken links.** The W3-T3 gate asserts every `runbook_url` resolves to an
  existing file (no dangling annotation), so a renamed runbook cannot silently
  orphan an alert.

### 4. Golden-signal dashboards-as-code — in-repo, linted (G-OBS §335)

The four **golden signals** (latency, traffic, errors, saturation) get
dashboards-as-code for **api, each worker queue** (`discovery` / `config` / `packet`
/ `docs`), **Postgres, Neo4j, Redis, and LLM providers** (G-OBS §335). Dashboards
are **code in the repo** (Grafana dashboard JSON, or jsonnet compiled to JSON; the
W3-T4 build picks one and is consistent), under a `deploy/` observability path
consistent with ADR-0015 §2 ("Grafana dashboards shipped as JSON in `deploy/`"), and
are **linted** in CI (JSON schema / structural lint, panels reference the §1
recording-rule / `netops_*` series so a renamed metric breaks the dashboard lint,
not silently the dashboard).

- **Expose-don't-bundle preserved (ADR-0015).** Shipping dashboard *code* does not
  bundle a Prometheus/Grafana stack into the default install — the platform exposes
  the series and provides the dashboards as opt-in artifacts; running the monitoring
  stack stays the operator's choice.
- **Coverage gate.** The W3-T4 gate asserts a dashboard exists for each of the seven
  subjects (api, the four queues, PG, Neo4j, Redis, LLM) with the four golden-signal
  panels — a missing subject or signal is an incomplete dashboard set (§335).

### 5. Fault-injection MTTD < 5 min — proven by `promtool` over synthetic series (G-OBS §337)

A **fault-injection harness** proves each alert actually *detects* its failure
within the MTTD budget. The three §337 scenarios are mandatory:

- **DB down** — Postgres unreachable (readiness/`up`/error series reflect it).
- **Queue stall** — a worker queue stops draining (`netops_celery_queue_depth`
  climbs / discovery success ratio drops).
- **LLM-provider failure** — provider errors / `vault`-style provider-healthy gauge
  / `netops_llm_*` error series spike.

The harness drives a **synthetic time series** representing each fault into
`promtool test rules` and asserts the corresponding burn-rate alert transitions to
*firing* within an **MTTD < 5 min** simulated budget (the alert's `for:` +
evaluation latency under the fast-burn window). This is the **in-CI, cluster-free**
MTTD proof and is the **blocking** G-OBS criterion. The **live-cluster** MTTD run —
the same alerts firing on a real injected fault on the W4-T1 kind cluster, and the
30-day soak (G-REL) confirmation — is named-deferred to W4/W5 per §0 (the live run
is the soak/drill proof; the synthetic-series `promtool` MTTD is the gate that bites
in every CI run). Each MTTD result states the basis (synthetic-series simulated
budget vs. live-cluster observed) so a synthetic proof is never silently claimed as
a live one.

### 6. Alert-as-test gate — every alert ships a *should-fire* `promtool` case (the anti-false-green discipline)

The dominant enforcement-phase risk (P1-W4 lesson, `P3-PLATFORM-PLAN.md` §1) is a
**green-at-setup alert rule that never actually fires**. Therefore **every** alert
rule ships a `promtool test rules` case with a **firing negative control**: a
synthetic series that *should* breach the burn-rate condition is fed in and the test
asserts the alert **fires** (and a below-threshold series asserts it stays silent).

- **The gate must RUN and BITE before it joins `all-gates`.** Per the carry-forward
  rule (`docs/roadmap/p3-tasks/README.md`), the `promtool` gate is proven to bite —
  delete or mute an alert and the corresponding firing test goes red — *before* it is
  promoted to a blocking `all-gates` check. A rules file that loads cleanly but whose
  alerts never fire is exactly the false-green this gate exists to catch.
- **L1 (run-it-locally) + L5 (pipefail) carry.** `promtool` is run locally before it
  is pushed as a gating CI tool; the CI step uses `set -o pipefail` + `test -s` on
  the rules/test output so a piped `promtool` invocation cannot mask a non-zero exit
  (the P1-W4 "CI pipe masks exit code" trap). Where `promtool` is absent on the build
  host, the task says so and leans on the rendered rules + test fixtures, naming the
  CI runner that executes the gate.

### 7. Build-task contract — the assertions this ADR pins

So each build task has a testable contract (the ADR is the design; the gates are the
proof) — owner `wf-observability`, `promtool`/lint gates (not Python-TDD):

- **W3-T2** (recording rules): one recording rule per §6 SLI (§1), named per the
  convention, 1:1 row↔rule; `promtool check rules` passes; cardinality discipline
  held.
- **W3-T3** (burn-rate alerts): a multi-window multi-burn-rate alert per §6 SLO (§2)
  reading the §1 recording rule, budget + window pair stated in the rule comment,
  single-threshold trips rejected; a mandatory resolving `runbook_url` per alert with
  freshness ≤ 90 days (§3); a *should-fire* `promtool test rules` case per alert that
  is **proven to bite** (§6).
- **W3-T4** (dashboards-as-code): linted in-repo golden-signal dashboards for api,
  each queue, PG, Neo4j, Redis, LLM (§4); coverage gate on the seven subjects × four
  signals.
- **W3-T5** (fault-injection MTTD): the DB-down / queue-stall / LLM-failure harness
  proving each alert fires within MTTD < 5 min over synthetic series (§5), blocking
  in CI; live-cluster MTTD named-deferred to W4/W5.

The **export-lag** SLO row (§6 row 8) is the ADR-0045 SLI: its recording rule
(W3-T2) and burn-rate alert + `promtool` firing test (W3-T3) live in *this*
enforcement wave, completing the ADR-0045 §6 build-task contract.

### 8. Scope boundary

**In:** the recording-rule naming convention (one per §6 SLI, naming the SLI); the
multi-window multi-burn-rate methodology + the budget/window-pair statement
requirement; the mandatory runbook-link rule (freshness ≤ 90 days, resolving path);
the dashboards-as-code format (in-repo, linted, golden-signal coverage); the
fault-injection scenarios + MTTD < 5 min budget; and the alert-as-test `promtool`
gate (the anti-false-green discipline). **Out:** the implementation (W3-T2…W3-T5);
the SIEM-export pipeline itself (ADR-0045 / W3-T1 — only its **lag SLO's** rule +
alert live here); the certified-scale SLO numbers (the §6 targets stay **PROPOSED**
pending the Consultant scale / GPU / retention answers, §12 — the rules are
rebased on the answered numbers, not re-decided here); the live-cluster MTTD /
30-day soak (W4 drills / W5, §0); and runbook prose authorship (Documentation Agent,
ADR-0015 §6). This ADR does not re-decide any §6 SLI/SLO target or any other P3 ADR.

## Consequences

**Positive**
- Every §6 SLO becomes **enforced**, not just measured: a named recording rule + a
  multi-window burn-rate alert + a runbook + a dashboard, satisfying G-OBS §§335–337
  as a true full PASS.
- The **one-rule-per-SLI** convention makes the alert and the dashboard read the same
  derived series — no "the dashboard and the alert disagree on the SLI" drift.
- Multi-window burn-rate (fast+slow, budget-relative) pages fast on a real burn yet
  resists single-spike flapping — far better than static thresholds, and fixed up
  front so W3 cannot regress to noisy single-threshold trips.
- The **alert-as-test `promtool` gate** closes the dominant enforcement-phase risk
  (alerts that never fire) deterministically in CI, cluster-free — the gate runs and
  bites in every CI run, not just on the W4 cluster.
- The mandatory resolving-`runbook_url` + freshness check means an alert always hands
  the on-call a current runbook (§336), and a renamed runbook breaks CI, not the
  pager at 3 a.m.
- Dashboards-as-code keep the §335 golden-signal coverage in version control and
  lint-checked, while expose-don't-bundle (ADR-0015) keeps the default footprint
  lean.

**Negative**
- Multi-window burn-rate rules are more PromQL to author and review per SLO than a
  single threshold; the budget/window-pair-in-comment requirement is the
  reviewability mitigation, and the methodology is fixed once here.
- The synthetic-series `promtool` MTTD is a *simulated* budget, not a live-cluster
  observation; the live MTTD (and 30-day soak) is named-deferred to W4/W5 and each
  result states its basis so a synthetic proof is never silently claimed as live.
- Recording rules + alerts + dashboards across nine SLIs and seven dashboard subjects
  is genuine ongoing maintenance, and a renamed `netops_*` base metric breaks the
  rules/dashboard lint — surfaced (by design) rather than silent.
- The §6 SLO **targets** remain PROPOSED pending Consultant scale/GPU/retention
  answers (§12); the rules carry the proposed numbers and are rebased — not
  re-authored — when the answers land.

## Alternatives considered

1. **Single static-threshold alerts (`expr > X` with a `for:`).** Rejected (§2):
   noisy and slow, unrelated to the error budget, and a single spike either flaps or
   is silenced by a long `for:` that blows the MTTD budget. Multi-window
   multi-burn-rate is the §6/G-OBS-grade method and is mandated.
2. **Single-window burn-rate (fast window only).** Rejected: a fast-only window
   flaps on transient spikes; the slow confirmation window is what makes the page
   trustworthy. The fast+slow **pair** is required.
3. **Alerts authored directly off raw `netops_*` metrics (no recording-rule layer).**
   Rejected (§1): the alert and the dashboard would each carry their own ad-hoc
   PromQL for the "same" SLI and drift apart; one recording rule per SLI is the
   single source of the derived SLI series both read.
4. **No firing test — rely on `promtool check rules` (syntax/load only) + manual
   review.** Rejected (§6, P1-W4 lesson): a rules file can load cleanly yet contain
   an alert that never fires (a false-green that masks the very finding the gate
   exists to produce). Every alert ships a *should-fire* `promtool test rules` case
   proven to bite.
5. **Optional / best-effort runbook links.** Rejected (§3): G-OBS §336 makes the
   runbook link a release criterion — an alert with no current runbook hands the
   on-call nothing. The link is mandatory, resolving, and freshness-checked.
6. **Bundle Prometheus + Grafana + alertmanager into the default install and ship
   provisioned dashboards/alerts as running infra.** Rejected (ADR-0015 alt. 1):
   triples the default footprint and duplicates infrastructure every target
   enterprise already runs. Dashboards/rules ship as opt-in **code**; running the
   stack stays the operator's choice.
7. **Only validate MTTD live on the kind/staging cluster (no in-CI synthetic
   proof).** Rejected for the *gate*: a cluster-only MTTD check runs rarely and
   slowly and cannot bite on every PR. The in-CI synthetic-series `promtool` MTTD is
   the blocking gate; the live-cluster MTTD is the complementary W4/W5 soak proof,
   named-deferred, not a substitute.
