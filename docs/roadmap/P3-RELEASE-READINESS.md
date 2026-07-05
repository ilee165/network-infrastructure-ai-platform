# P3-Platform Release Readiness — Phase-exit gate evidence (W5-T3)

**Date:** 2026-07-05
**Branch:** `feat/p3-w5-t3` (release HEAD `8e11b9b` — PR #114; W0–W5-T2 in place)
**Owner:** `wf-release-auditor` (strong)
**Authority:** `docs/roadmap/P3-PLATFORM-PLAN.md` §0 (reduced-scale mechanism-PASS +
named certified-scale ceiling posture, decided 2026-06-29) / §1 (scope) / §5
(per-wave exit criteria); `PRODUCTION.md` §11 (the five production-readiness gates
G-SEC / G-REL / G-SCA / G-OBS / G-MNT) + §1 (phase table, the 2026-06-25 re-scope
amendment, and the P3-Platform IN-PROGRESS entry marker); §6 (the nine observability
SLOs); ADR-0033 §1 (deferrals named, never silent); ADR-0047 (the reduced-scale +
named-ceiling stance + the negative-control-must-bite rule); ADR-0048 **Rejected**
2026-07-03 (kind-harness gate promotion abandoned — the two controls stay static +
runtime enforced, not a blocking kind gate). Mirrors `P1-RELEASE-READINESS.md`
(W7-T4) and `P2-RELEASE-READINESS.md` (W5-T3).
**Companion evidence:**
`P1-RELEASE-READINESS.md` + `P2-RELEASE-READINESS.md` (the inherited G-SEC/G-REL/
G-OBS/G-MNT baselines this phase carries forward), `docs/roadmap/PRODUCTION.md` §6
(SLO table) + §11 (gate criteria), `docs/adr/0042`–`0047` (the P3 design contract,
flipped Accepted by this task) + `docs/adr/0048` (Rejected, cited as-is),
`docs/runbooks/kind-harness.md` (why the live kind run is opt-in signal-only, not a
blocking gate), `.github/workflows/ci.yml` (the `all-gates` required aggregator + the
`observability` + `drill-bite-proofs` blocking jobs).

This document records the **real** gate results captured on the release HEAD. It
judges each of the five §11 gates **against the P3-Platform phase scope** (HA +
scale-out; audit→SIEM export; observability-SLO enforcement; live failover/soak/scale
DR drills; N-2 upgrade rehearsal; dependency lockfile — P3-PLATFORM-PLAN §1). The
§11 gate criteria span the whole P1→P5 production arc; the criteria that need a
**certified-scale cluster or calendar time** (500-device discovery / 100-user load /
5,000-device projection / 30-day calendar soak / external pentest / 6-month
break-glass drill / live-lab vendor golden-paths) are **named explicitly as
deferred**, never silently dropped (ADR-0033 §1). **This host has no certified-scale
cluster, no real network devices, and no LLM provider; live-lab items are NOT claimed
here.** Per the ratified 2026-06-29 posture (P3-PLATFORM-PLAN §0), **G-SCA and the
G-REL live drills exit as "mechanism PASS at reduced scale; certified-scale numbers
named-deferred → GA"**; **G-OBS is a full CI-enforceable PASS**; **G-SEC is
continuous** (the mTLS + collector-egress-deny controls are enforced by static rego +
runtime NetworkPolicy — **not** a blocking kind gate, ADR-0048 Rejected).

---

## 0. Scope discipline — what "gate PASS" means at P3-Platform

`PRODUCTION.md` §11 defines each gate by its **GA** criteria, re-evaluated at the end
of every production phase (P1–P5). P3-PLATFORM-PLAN §0/§5 binds P3-Platform to the
**mechanism-proof-at-reduced-scale** posture: build the full HA/scale machinery and
prove the *mechanism* **bites** at reduced scale on an ephemeral kind topology (each
drill ships a planted-regression negative control), while the **certified-scale
numbers stay named deferred-accepted → GA** with a written promotion path (ADR-0047).
A gate's verdict below is therefore **PASS for the P3-scoped mechanism criteria, with
certified-scale / calendar-time criteria itemised as deferred**. A certified-scale
criterion left unmet is **not** a P3 blocker; an unmet **mechanism** criterion would
be. Each verdict cites a HEAD artifact — a green CI job + a test/drill/script path, a
commit, a rendered manifest, or an SLO rule — that a reviewer can re-derive.

---

## 1. Repo gates — REAL results (release HEAD `8e11b9b`)

The single required CI check is `all-gates` (`.github/workflows/ci.yml:2428`), which
`needs: [backend, frontend, security-scan, docker, infra, kms-emulators,
pg-integration, packet-analysis-bite-proof, lockfile, observability,
drill-bite-proofs]` and (`if: always()`) FAILS unless **every** upstream job is
`success` — so a failed **or skipped** gate blocks merge atomically (no orphan
advisory gate). CI run **28745257330** (head sha
`8e11b9b003097bd175be1a88addc1423644ba9e3`) is `conclusion: success`, confirmed live
via `gh run view 28745257330 --json headSha,conclusion,jobs`:

| Job (ci.yml) | What it gates | Result on HEAD `8e11b9b` (run 28745257330) |
|------|------------------|----------------|
| `all-gates` (required aggregator) | every upstream job `success` | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85235246857)) |
| `backend` (ruff, mypy, import-linter, pytest) | D16 lint/type/imports + full pytest incl. firewall + routing + **SLO-alert coverage matrix** + **SIEM-export conformance** evals | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954969)) |
| `observability` (promtool check + test + alert-as-test bite) | G-OBS: recording rules + burn-rate alerts + MTTD harness + SLO-corpus + dashboard lint, each with a BITE proof | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954997)) |
| `drill-bite-proofs` (cluster-free negative-control bite proofs — **blocking**) | G-REL/G-SCA/G-MNT drills: pg-failover, neo4j-rebuild, worker-kill idempotency, queue-burst, compressed soak, N-2 rehearsal — each proven to bite | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954947)) |
| `pg-integration` (real PostgreSQL — W4 controls under PG) | audit hash-chain + credential rotation re-asserted under real `pgvector` | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954977)) |
| `infra` (helm lint, kubeconform, kube-linter, conftest) | chart policy-as-test + pg_hba weak-hostssl rego bite + mTLS/CNPG/Sentinel render-twice L4 guards + HPA/PDB/KEDA/CNPG/Sentinel policy bites + NetworkPolicy render | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954964)) |
| `lockfile` (backend + frontend dependency drift) | dependency-lockfile drift assertion (W0-T8; closes the P1 systemic TODO) | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954981)) |
| `frontend` (eslint, tsc, vitest, build) | frontend D16 gates | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954934)) |
| `security-scan` (gitleaks — tree + history) | no secret material in tree or full git history | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954962)) |
| `docker` (build + SBOM + Trivy) | image SBOM + Trivy CRIT/HIGH `ignore-unfixed` | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954952)) |
| `docker-publish` (push + cosign sign/verify — main/tags) | keyless cosign sign + verify on the release image | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85235246862)) |
| `kms-emulators` (LocalStack KMS + dev Vault) | KMS-backed master-key integration (P1 G-SEC inherited) | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954956)) |
| `packet-analysis-bite-proof` (executor-split seccomp + tshark — Linux) | ADR-0049 packet-sandbox bite | **SUCCESS** ([job](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/28745257330/job/85234954958)) |
| `pg-test-routing` (SQLite-vs-PG coverage heuristic — **advisory**) | advisory PG-coverage heuristic (not in `all-gates`) | **SUCCESS** |
| `kind-harness` / `kind-harness-ha` (live kind — **opt-in / signal-only**) | live mTLS/collector + HA bring-up; `continue-on-error`, deliberately **NOT** in `all-gates` (ADR-0048 Rejected) | **SKIPPED (by design)** — opt-in via `ci-kind` label / manual dispatch |

> The two `kind-harness*` jobs are **SKIPPED** on this run, which is the intended
> steady state after ADR-0048 was Rejected (2026-07-03): the live kind run is opt-in
> signal-only and is **permanently excluded from `all-gates` needs** (ci.yml:2363–2383,
> deliberate-omission comment). A skipped signal-only job does not affect the phase
> verdict; the two controls it would exercise live are enforced by blocking static +
> runtime layers instead (§2 G-SEC).

### 1.1 Gate-bites confirmation (P1-W4 lesson — a gate green-at-setup masks findings)

Every gate that carries a P3 verdict or flips an ADR was confirmed to actually **RUN
and BITE** on a regression, not merely be green at setup. All bite proofs below are
**cluster-free** negative controls (plant → red → revert-to-green) that run inside the
`all-gates`-blocking `observability` and `drill-bite-proofs` jobs, so a drill or alert
that stops biting blocks merge:

- **G-OBS alert-as-test bites (`observability` job).**
  `deploy/observability/run-promtool-bite.sh` mutes a committed burn-rate alert on a
  temp copy and asserts its firing test goes **RED** (a false-green alert that never
  fires is caught); `run-mttd-bite.sh` slows a fast alert's `for:` hold past the 5-min
  budget and asserts the MTTD assertion goes **RED**; `run-slo-corpus-perturbation-bite.sh`
  (W5-T1) delays a firing case's onset past its window and asserts `promtool test rules`
  reports a genuine `got:[]` assertion failure — the corpus-DELAY counterpart proving the
  fire-within-window floor is not a vacuous "fires eventually" check;
  `dashboards/run-dashboard-lint-bite.sh` asserts a missing golden signal / renamed
  metric / dropped §335 subject each fails the lint. Clean rules pass; the mutations bite.
- **G-REL / G-SCA / G-MNT drill negative controls bite (`drill-bite-proofs` job).**
  Each `ci/kind/selftest/*-bite.sh` runs the **real** drill script against a fake
  `kubectl`/`psql` and asserts the observable polarity flips under a planted regression:
  `pg-failover-bite.sh` (failover ≤ 60 s + zero committed-audit loss → a synchronous-path
  break reds), `neo4j-rebuild-bite.sh`, `worker-kill-idempotency-bite.sh` (a duplicate
  side effect reds), `queue-burst-load-bite.sh` (queue-starvation / p95 / PgBouncer
  budget regression reds), `compressed-soak-bite.sh`, and
  `n2-upgrade-rehearsal-bite.sh` — the last asserts a **contract-too-early** migration
  that drops a column an N-1 pod still reads goes **RED**, and a **force-api-unavail**
  scenario below the ≥ 2-ready floor goes **RED**, with the additive-expand path green
  (the plant → red → revert the live kind run would otherwise be the only place to
  observe). ADR-0047 §2 requires exactly this; the job is in `all-gates` needs.
- **G-SEC static enforcement bites (`infra` job).** `run-pg-hba-bite.sh` feeds a
  **negative** fixture (a weaker `trust`/`clientcert=verify-full` hostssl line) and
  asserts conftest **denies** it, plus a positive fixture that passes — so the mTLS
  pg_hba `hostssl … clientcert=verify-full` requirement is a real policy gate, not a
  vacuous one. The `ci/mtls/render-twice.sh`, `ci/cnpg/render-twice.sh`, and
  `ci/redis-sentinel/render-twice.sh` L4 idempotency guards are RED gates (no
  `continue-on-error`); `run-cnpg-bite.sh`, `run-redis-sentinel-bite.sh`,
  `run-api-hpa-pdb-bite.sh`, and `run-keda-scaledobject-bite.sh` each carry
  negative+positive policy fixtures.
- **`pg-integration` proven to bite (carried).** The W4 audit-integrity + credential
  controls run under **real PostgreSQL**; this gate empirically bit on `dd366bd` during
  P2 (a REVOKE-connection password bug went red → green) and is a member of `all-gates`
  needs, so the SQLite-hides-PG-semantics class stays closed on HEAD.
- **`lockfile` bites.** The dependency-drift assertion (W0-T8) is a blocking gate;
  the P3-W0 lesson (`24e4f17`) required **valid** tamper data to prove it reds (an
  invalid-version plant parse-aborted uv rather than biting) — the corrected control
  reds on a real drift and is green on HEAD.

---

## 2. Per-gate verdicts (PRODUCTION.md §11, on HEAD `8e11b9b`)

### G-OBS — Observability — **PASS (full CI-enforceable)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| 100% of containers expose `/metrics` + liveness + readiness (§390) | **PASS (inherited)** | ADR-0015 (D15, Accepted); P1 W4 posture carried — every workload renders probes; `infra` kube-linter probe checks green. No P3 workload regresses this. |
| Golden-signal dashboards (latency/traffic/errors/saturation) for api, each queue, PG, Neo4j, Redis, LLM providers (§391) | **PASS** | Dashboards-as-code: `dashboards/lint_dashboards.py` asserts all 9 §335 subjects × 4 golden signals exist and every panel target binds to a known `slo:`/`netops_*`/exporter series; `run-dashboard-lint-bite.sh` bites on a missing signal/renamed metric/dropped subject; the provisioning ConfigMap renders + kubeconform-validates (`observability` job green). Live Grafana visual render named-deferred (no host Grafana) — the biting layer is the structural/coverage lint. [W3, ADR-0046 §4] |
| **Every §6 SLO has a recording rule + multi-window burn-rate alert; every alert links a runbook; freshness ≤ 90 days** (§392) | **PASS (6 backed SLOs) + 3 reconciliation rows named-deferred** | The **six §6 SLI rows with a backing Prometheus series** — API availability, API read latency, agent first-token latency, discovery success, topology-projection lag, audit→SIEM export lag — each have a recording rule (`slo-recording.rules.yaml`, 7 `record:` series) + a multi-window burn-rate alert (`slo-burn-rate.alerts.yaml`) + a runbook (`docs/runbooks/slo-*.md`, 6 files). `test_slo_alert_corpus.py` asserts **every** declared alert has both a firing and a healthy case and every class has ≥1 positive + ≥1 negative (coverage + shape), and `test_coverage_matrix_is_grounded_in_production_section6` grounds the set in §6. **Named residual:** §6 rows **5/6/9** (config-backup completeness, CR→audit completeness, reasoning-trace persistence) are **reconciliation-job** rows with no Prometheus series yet — **flagged-deferred** in the recording-rules file with their proposed series names, drift-guarded by that same test (no silent drop); their underlying invariants are the existing M3/CR reconciliation-job spine, not a burn-rate alert. `backend` + `observability` jobs green. |
| **Fault-injection MTTD < 5 min** each (DB down / queue stall / LLM-provider failure) (§393) | **PASS** | `slo-mttd.faultinjection.test.yaml` drives the three §386 synthetic faults and asserts the fast/PAGE alert FIRES at 3 m (strictly < the 5-min budget) with a healthy negative control per scenario; `run-mttd-bite.sh` proves the window is load-bearing (a slowed `for:` hold reds). Cluster-free promtool over compressed synthetic series; live-cluster MTTD run named-deferred (ADR-0046 §0/§5). `observability` job green. [W3-T5] |
| 100% of agent runs traced end-to-end, joinable to audit (§394) | **PASS (inherited)** | ADR-0015 structlog correlation + OTel tracing carried; no new untraced path in P3. |
| **Audit → SIEM export operating within the lag SLO** (§395) | **PASS** | Vendor-neutral export pipeline (RFC5424 syslog + CEF over TLS + HTTPS/JSON) with an **export-lag metric** backing the §6 `Audit → SIEM export lag p95 < 60 s` SLO; that SLO has a recording rule + burn-rate alert + runbook (`slo-audit-siem-export-lag.md`); `test_siem_export_conformance.py` (backend job) asserts the export conformance corpus; the export-lag SLO is one of the six backed rows above. [W3, ADR-0045] |

**G-OBS verdict: PASS (full CI-enforceable).** The enforcement track P3 scoped —
recording rules + multi-window burn-rate alerts + runbooks for every §6 SLO that is
representable as a Prometheus rate/latency series, golden-signal dashboards, MTTD < 5
min, and the audit→SIEM export-lag SLO — is green and **biting** on HEAD (§1.1). The
only residual is the three §6 **reconciliation-job** rows (5/6/9), which are
**named-deferred with documented proposed series** and drift-guarded by a biting
coverage test — not a silent gap. This is the one gate P3 targets as a true full PASS,
and it is.

### G-SCA — Scalability — **mechanism PASS at reduced scale + NAMED certified-scale ceiling**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| Queue-burst: 10× `discovery` depth triggers KEDA scale-out, drains within SLO without starving `config`/`packet`/`docs` (§385) | **PASS (mechanism)** | KEDA ScaledObjects per queue render + pass policy (`run-keda-scaledobject-bite.sh`, `infra`); the **per-queue isolation + drain** mechanism bites in `queue-burst-load-bite.sh` (`drill-bite-proofs`) — a starvation regression reds. [W2-T3 + W4] |
| API load: 100 concurrent users, p95 < 300 ms, zero 5xx, 2→4 replicas linear (§383) | **PASS (mechanism, reduced scale) / certified number DEFERRED** | api HPA + PDB render + policy-bite (`run-api-hpa-pdb-bite.sh`, `infra`); the reduced-scale load + p95 mechanism bites in `queue-burst-load-bite.sh`. **The 100-user certified number → GA** (needs a real cluster). [W2-T1] |
| Discovery of a 500-device estate ≤ 60 min with observed scale-out/in (§382) | **DEFERRED — GA / certified-scale** | The **autoscale mechanism** (KEDA scale-out/in) is proven at reduced scale above; the **500-device number** needs a certified-scale cluster. Named, promotion path ADR-0047. |
| Topology projection + UI usable at 5,000 devices / 100k interfaces (§384) | **DEFERRED — GA / certified-scale** | Projection-lag SLO recording rule + alert exist (G-OBS); the **5,000-device projection number** needs certified scale. Named. |
| Postgres connection budget holds under load via PgBouncer (§386) | **PASS (mechanism)** | PgBouncer rendered in the CNPG HA tier (`run-cnpg-bite.sh`, CNPG render-twice guard, `infra`); the connection-budget mechanism is exercised under the reduced-scale queue-burst/load drill. Certified-scale budget → GA. [W1-T1] |

**G-SCA verdict: mechanism PASS at reduced scale.** Every G-SCA *mechanism*
(KEDA per-queue autoscale + isolation, api HPA/PDB, PgBouncer budget) renders, passes
policy, and **bites** at reduced scale in `all-gates`-blocking jobs. The **certified-scale
numbers — 500-device discovery, 100 concurrent users, 5,000-device projection — are
deferred-accepted → GA / customer cluster** with the ADR-0047 promotion path, exactly
the ADR-0033 §1 discipline. Named, never silently claimed. Not a P3 blocker.

### G-REL — Reliability — **mechanism PASS at reduced scale + NAMED certified-scale ceiling**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| Postgres failover: primary kill → promotion, write restored ≤ 60 s, **zero committed-audit loss** (synchronous audit path) (§372) | **PASS (mechanism)** | CloudNativePG 1+2 with synchronous replication on the `audit_log` write path (ADR-0042); the failover mechanism + the ≤ 60 s + zero-audit-loss assertion bite in `pg-failover-bite.sh` (`drill-bite-proofs`) — a synchronous-path break reds. Re-asserted under real PG via `pg-integration`. [W1-T1] |
| Neo4j destroy-and-rebuild within topology-RTO (§373) | **PASS (mechanism)** | Automated Neo4j-rebuild Job (rebuild = topology-RTO); mechanism bites in `neo4j-rebuild-bite.sh`. Certified-scale rebuild time (< 30 min at 5,000 devices) → GA. [W1] |
| DR drill from backups alone onto a clean cluster (RPO ≤ 5 min / RTO ≤ 1 h) (§374) | **PASS (inherited P1 baseline) / certified-scale DEFERRED** | P1 W5 from-backups-alone drill green at seeded scale (`P1-RELEASE-READINESS` §2 G-REL); P3 adds the HA failover/rebuild mechanisms above. Certified-scale timed DR → GA. |
| Worker node kill mid-run: jobs complete via retry, no duplicate side effects (idempotency) (§375) | **PASS (mechanism)** | `acks_late` + idempotency hardening (W2-T4); `worker-kill-idempotency-bite.sh` reds on a duplicate side effect; re-asserted under real PG. |
| 30-day staging soak meets all §6 SLOs; Celery ≥ 99% after retries over the soak (§371, §376) | **PASS (compressed-soak mechanism) / 30-day calendar DEFERRED** | The soak **mechanism** (SLO adherence + ≥ 99% Celery success) bites in `compressed-soak-bite.sh` + `slo-compressed-soak.test.yaml`. **The 30-day calendar soak → GA** (needs calendar time). Named. |

**G-REL verdict: mechanism PASS at reduced scale.** Failover (≤ 60 s, zero committed-audit
loss via the synchronous audit path), Neo4j rebuild, worker-kill idempotency, and a
compressed soak (Celery ≥ 99%) all **bite** on a planted regression in the
`all-gates`-blocking `drill-bite-proofs` job, re-asserted under real PostgreSQL. The
**30-day calendar soak and certified-scale DR/rebuild numbers are deferred-accepted →
GA** (ADR-0047 promotion path); the P1 backup/DR baseline holds. Named, not a P3 blocker.

### G-SEC — Security — **PASS (continuous)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| Prompt-injection eval: 100% zero unauthorized tool calls; four-eyes; redaction; RBAC (§361–§363, §367–§368) | **PASS (inherited + continuous)** | P1 ED1–ED5 deterministic suite + P2 Security-Agent boundary carried in the `backend` job (no regression on HEAD). |
| Audit log append-only + hash-chain verification (§364) | **PASS (continuous, real PG)** | Re-asserted under real PostgreSQL — `tests/pg/test_audit_hash_chain_pg.py`, `pg-integration` green; the P3 synchronous audit write path (ADR-0042) preserves the chain across failover (`pg-failover-bite.sh` zero-audit-loss assertion). |
| Credential-leak tests green; no plaintext device credential in any output (§363) | **PASS (continuous, real PG)** | `tests/pg/test_credentials_rotation_pg.py`, `pg-integration` green (P2 W4-T2 control, carried). |
| **mTLS api/worker↔postgres** enforced (§5) | **PASS (static + runtime enforced) — NOT a blocking kind gate** | Enforced by **static rego** — `run-pg-hba-bite.sh` (conftest denies a weak `hostssl`/`clientcert` line, negative+positive fixtures) + the `ci/mtls/render-twice.sh` L4 idempotency guard + the external-PG fail-fast guard, all RED gates in the `infra` job — plus the rendered NetworkPolicy/cert material. The **live kind handshake** (`kind-harness.sh`) is `continue-on-error` / opt-in / **outside `all-gates`**; **its promotion to blocking was Rejected (ADR-0048, 2026-07-03)**. Enforcement is static + runtime, not a live kind gate. [ADR-0039 carried] |
| **Collector default-deny egress NetworkPolicy** enforced (§9) | **PASS (static + runtime enforced) — NOT a blocking kind gate** | Chart NetworkPolicies render + pass `infra` policy gates (kubeconform/conftest/kube-linter); the CNI self-test + egress-probe-tristate self-tests are in the opt-in `kind-harness` job. The **live default-deny enforcement** run is `continue-on-error` / outside `all-gates`; promotion Rejected (ADR-0048). Static render + runtime NetworkPolicy carry the control. [ADR-0041 carried] |
| Zero fixable critical/high CVEs in shipped images (§360) | **PASS (CI-gated)** | `docker` job Trivy `CRITICAL,HIGH` + `ignore-unfixed` + `docker-publish` keyless cosign sign/verify; green on HEAD. |
| Secret scan: no secret material in tree or history | **PASS** | `security-scan` gitleaks tree + full history green. |
| KMS-backed master key, no-leak, fail-closed prod gate (§5 P1) | **PASS (inherited)** | `kms-emulators` required job green on HEAD. |
| OIDC + break-glass; **6-month break-glass drill** (§365) | **DEFERRED — operational** | Operational cadence item (needs a deployed operator); named, carried from P1/P2. |
| **External penetration test**, no open high/critical (§366) | **DEFERRED — pre-GA, no substitute** | Point-in-time pentest is pre-GA (ADR-0033 Alt #6); the continuous in-CI suites are complementary, not a substitute. Named, carried. |

**G-SEC verdict: PASS (continuous).** All P1/P2 security controls (prompt-injection
boundary, four-eyes, redaction, RBAC, audit hash-chain + credential rotation under real
PG, KMS no-leak, Trivy/cosign, gitleaks) are inherited and continuously enforced with no
regression on HEAD. The two P2 kind-cluster controls — **mTLS api/worker↔postgres** and
**collector default-deny egress** — are enforced by **blocking static rego + render-twice
guards + runtime NetworkPolicy**, which bite on HEAD; **their live-kind-handshake
promotion to a blocking `all-gates` gate was Rejected (ADR-0048, 2026-07-03)**, so there
is **no blocking kind gate** and none is claimed. External pentest + the 6-month
break-glass drill remain named-deferred (pre-GA / operational).

### G-MNT — Maintainability — **PASS**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| D16 gates green continuously (ruff, mypy strict, pytest ≥80%, eslint/tsc/vitest, import-linter) (§399) | **PASS** | `backend` + `frontend` jobs green on run 28745257330; coverage gate `--cov-fail-under=80`. |
| Every binding decision has a current ADR; no silent drift (§400) | **PASS** | **ADRs 0042–0047 flipped Proposed → Accepted by this task** on their green implementing-wave evidence (§4); **ADR-0048 recorded Rejected** (2026-07-03) — cited, not flipped; the stale "promote to blocking" language in `P3-PLATFORM-PLAN.md` §0a/§1 and `PRODUCTION.md` §1/§11 was reconciled to the ADR-0048 reality in PR #113 (`410e435`). |
| **N-2 → N upgrade rehearsal green in CI on a seeded dataset** (expand/contract + Neo4j rebuild) (§402) | **PASS** | W4-T8 rehearsal (PR #112, `e27f220`) + pre-upgrade migrate Job; the drill's negative control (`n2-upgrade-rehearsal-bite.sh`) bites in `drill-bite-proofs` — contract-too-early and force-api-unavail both red, additive-expand green. Live kind run named-deferred; the bite proof is cluster-free. |
| **Dependency lockfile added** (closes the P1 systemic TODO) | **PASS** | W0-T8 backend + frontend lockfile + the blocking `lockfile` CI drift assertion, green + biting on HEAD (§1.1). |
| Every shipped feature has tests + docs + API docs (§401) | **PASS (spot-audit)** | Per-task TDD across P3 W0–W5; every HA/scale mechanism, the SIEM pipeline, the SLO rules, and each drill ship with tests + an ADR. |
| New-plugin onboarding validated each wave (§403) | **PASS (n/a this phase)** | P3 is platform-only (no vendor wave); the plugin template + conformance harness are unchanged (Wave 3 F5/VMware is P4). |
| Open Consultant questions reviewed each phase (§404) | **PASS (reviewed)** | The four P3-relevant §12 items (scale targets, HA/DR, GPU, retention) were re-checked at W0 kickoff; PROPOSED defaults re-confirmed (`PRODUCTION.md` §1 P3 marker; `docs/consultant/QUESTIONS.md`). |

**G-MNT verdict: PASS.** D16 green; ADR currency restored (0042–0047 Accepted, 0048
Rejected, no silent drift, stale kind-promotion language reconciled); the N-2 upgrade
rehearsal is green and biting; the dependency lockfile closes the P1 systemic TODO; and
`PRODUCTION.md` is amended (§1 P3 exit marker). The only n/a item (new-plugin onboarding)
is a platform-only-phase non-event, named.

---

## 3. Status flips (only on green)

Because every P3-scoped gate criterion is PASS on the HEAD-green CI run **28745257330**
(`8e11b9b`) — with all certified-scale / calendar-time / operational criteria named
deferred in §2, and the kind-live enforcement recorded as static+runtime-enforced (not a
biting kind gate, ADR-0048 Rejected) — the dependent ADR flips are applied in this same
atomic commit (mirrors PR #63 flipping ADR 0025–0032, W7-T4 flipping 0033, and W5-T3
flipping 0034–0041). **Each ADR is flipped only on its implementing wave's green,
biting evidence:**

| ADR | Title | Implementing wave / evidence (green + biting on HEAD `8e11b9b`) | Flip |
|---|---|---|---|
| **0042** | Postgres HA — CloudNativePG (1+2) + PgBouncer + synchronous audit write path | W1 data-tier HA; CNPG render-twice + `run-cnpg-bite.sh` + `run-pg-hba-bite.sh` (`infra`); failover ≤ 60 s + zero-audit-loss `pg-failover-bite.sh` (`drill-bite-proofs`); audit chain under real PG (`pg-integration`) | Proposed → **Accepted** |
| **0043** | api HPA + KEDA per-queue worker autoscaling | W2 compute scale-out; `run-api-hpa-pdb-bite.sh` + `run-keda-scaledobject-bite.sh` (`infra`); queue-burst isolation + drain `queue-burst-load-bite.sh` (`drill-bite-proofs`) | Proposed → **Accepted** |
| **0044** | Redis Sentinel + stateless WebSocket fan-out via Redis pub/sub | W1/W2; Sentinel render-twice + `run-redis-sentinel-bite.sh` (`infra`); WS fan-out relay tests isolated + green (backend job; `7d8d129` NullPool fix) | Proposed → **Accepted** |
| **0045** | Audit→SIEM export (RFC5424 syslog + CEF over TLS + HTTPS/JSON, at-least-once, export-lag SLO) | W3; `test_siem_export_conformance.py` (backend) + the audit→SIEM export-lag recording rule + burn-rate alert + runbook (`observability`) | Proposed → **Accepted** |
| **0046** | Observability-SLO enforcement (recording rules, burn-rate alerts, dashboards, fault-injection MTTD) | W3 + W5-T1; the entire `observability` job (promtool check/test + alert/MTTD/perturbation bites + dashboard lint) + `test_slo_alert_corpus.py` coverage matrix (backend) | Proposed → **Accepted** |
| **0047** | Reliability/scale drill harness + N-2 upgrade rehearsal (reduced-scale mechanism proof + named certified-scale ceiling) | W4; the full `drill-bite-proofs` job (six `ci/kind/selftest/*-bite.sh` negative controls incl. `n2-upgrade-rehearsal-bite.sh`, W4-T8) | Proposed → **Accepted** |

> **ADR-0048** (kind-harness gate promotion → blocking) **stays Rejected** (2026-07-03,
> audit-W2 T7). It is **not** flipped and its two controls are **not** claimed as a
> biting kind gate; they are enforced statically (rego) + at runtime (NetworkPolicy)
> per §2 G-SEC. This is the P1-W4 discipline at phase scale: no ADR flips on a
> non-biting gate.

**Roadmap flip:** `PRODUCTION.md` §1 — the P3-Platform phase row gets an
**✅ EXIT 2026-07-05** marker + a dated P3-Platform EXIT block (mirrors the P2-Security
EXIT block) citing RELEASE_SHA `8e11b9b` + CI run 28745257330, plus the P4 inheritance
note (Wave 3 F5/VMware + application-dependency topology + the compliance & audit
reporting suite). `PRODUCTION.md` §1 is the roadmap index (no separate ROADMAP file).

---

## 4. Deferrals — named explicitly (none silent)

Every item below is **outside P3-Platform scope by design** (P3-PLATFORM-PLAN §0/§1,
`PRODUCTION.md` §1/§6/§11) and is **not** a P3 release blocker:

1. **G-SCA certified-scale numbers** — 500-device discovery, 100 concurrent users,
   5,000-device projection → **GA / customer cluster**; the mechanisms bite at reduced
   scale, promotion path in **ADR-0047** + this doc.
2. **G-REL 30-day calendar soak + certified-scale DR/rebuild timings** → **GA**; the
   compressed-soak + failover + rebuild mechanisms bite at reduced scale; P1 backup/DR
   baseline holds.
3. **G-OBS §6 reconciliation-job SLO rows (5/6/9)** — config-backup completeness,
   CR→audit completeness, reasoning-trace persistence — their recording-rule + burn-rate
   alert representation is **flagged-deferred** (proposed series documented,
   drift-guarded by `test_coverage_matrix_is_grounded_in_production_section6`); the
   underlying invariants are the existing reconciliation-job spine. Promotion = add the
   backing `netops_*` series, then a rule + alert + runbook.
4. **Live kind mTLS-handshake + collector-egress-deny enforcement** — `kind-harness*`
   is opt-in / `continue-on-error` / outside `all-gates`; **promotion to a blocking gate
   was Rejected (ADR-0048, 2026-07-03)**. The controls are enforced by blocking static
   rego + render-twice guards + runtime NetworkPolicy (`docs/runbooks/kind-harness.md`).
   Not a deferral of enforcement — a deferral of the *live-CI-bite mechanism only*,
   permanently by decision.
5. **G-SEC external pentest** (pre-GA) and the **recurring 6-month break-glass drill**
   (operational) — GA-time / operational, carried from P1/P2.
6. **Live-lab vendor golden-paths** — no real devices / cluster / LLM provider on the
   authoring host; same no-hardware deferral as M4/M5/P1/P2. Wave 3 (F5/VMware)
   golden-paths land in **P4**.
7. **Vault / MEMORY sync (out-of-repo)** — the orchestrator's Obsidian vault P3-Platform
   status note + the auto-memory `MEMORY.md` "P3-Platform plan" entry are updated
   **outside** this in-repo commit; **flagged here so the sync is not silently skipped**
   (it must be updated to record P3-Platform COMPLETE + the release SHA `8e11b9b`).

**P4 inheritance (recorded so nothing is dropped):** Wave 3 vendors **F5 BIG-IP +
VMware**; **application-dependency topology**; the **compliance & audit reporting
suite** (change report, compliance posture report, access review, audit-integrity
report — `PRODUCTION.md` §7). The certified-scale G-SCA/G-REL numbers, external pentest,
and 6-month break-glass cadence ride to **GA / operational**. The P4 plan is authored
when P3-Platform exits.

---

## 5. Aggregate verdict

| Gate | P3-Platform-scope verdict | Blocking? |
|---|---|---|
| **G-OBS** | **PASS (full CI-enforceable)** — recording rules + burn-rate alerts + runbooks for the 6 backed §6 SLOs, dashboards, MTTD < 5 min, export-lag SLO, all biting; §6 rows 5/6/9 named-deferred + drift-guarded | No |
| **G-SCA** | **mechanism PASS at reduced scale** (KEDA isolation, HPA/PDB, PgBouncer budget bite); 500/100/5,000 certified numbers **deferred-accepted → GA** (ADR-0047) | No |
| **G-REL** | **mechanism PASS at reduced scale** (failover ≤ 60 s zero-audit-loss, Neo4j rebuild, idempotency, Celery ≥ 99% compressed soak bite); 30-day calendar soak + certified-scale DR **deferred → GA**; P1 baseline holds | No |
| **G-SEC** | **PASS (continuous)** — P1/P2 controls inherited + enforced; mTLS + collector-egress-deny enforced by static rego + runtime NetworkPolicy (**no blocking kind gate — ADR-0048 Rejected**); pentest + break-glass named-deferred | No |
| **G-MNT** | **PASS** — D16 green; ADRs 0042–0047 Accepted / 0048 Rejected (no drift); N-2 rehearsal green + biting; dependency lockfile; `PRODUCTION.md` amended | No |

**P3-Platform is declared COMPLETE.** All five §11 gates pass **simultaneously on the
release HEAD `8e11b9b`** (CI run **28745257330**, `conclusion: success`, `all-gates`
required + all 11 blocking jobs green; the two `kind-harness*` jobs SKIPPED by design).
G-OBS is a full CI-enforceable PASS; G-SCA and the G-REL live drills exit as **mechanism
PASS at reduced scale with the certified-scale numbers named deferred-accepted → GA**
(ADR-0047 promotion path); G-SEC is continuous with the two kind-cluster controls
enforced statically + at runtime (the live-kind promotion permanently Rejected,
ADR-0048); G-MNT restores full ADR currency. Every gate that flips an ADR was confirmed
to **RUN and BITE** on a planted regression in an `all-gates`-blocking job (§1.1) — no
ADR flips on a non-biting gate (the P1-W4 trap avoided at phase scale). Every
certified-scale / calendar-time / operational / live-lab criterion is **named with its
promotion path** — none silent (ADR-0033 §1). No P3-scoped criterion is unmet, so
nothing blocks the phase exit; ADRs 0042–0047 are flipped Proposed → Accepted on their
green implementing evidence, and the `PRODUCTION.md` §1 P3-Platform EXIT marker is added.
