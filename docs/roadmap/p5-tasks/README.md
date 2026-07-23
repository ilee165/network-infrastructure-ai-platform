# P5 — Task Specs (goals + exit criteria)

Per-task decomposition of **P5-PLAN.md §3** waves **W0–W5**. Each task below is
a single atomic-commit unit running the standing per-task pattern:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two
> reviews). Single combined sonnet reviewer allowed for non-secret-surface
> tasks; dual **strong** review on the escalation set.

**Escalation set** (reviewers + fixer on the live strong model; confirm the
model exists in the live registry before launch — a dead-model escalation
returns a silently "clean" review): **W0-T1** (whole ADR), the credential
sections of **W0-T2 / W0-T3**, and the outbox section of **W0-T5** use the W0
table's strong tiers; downstream implementation escalations are **W1-T1**
(report outbox — report-run spine, artifacts leave the platform), **W2-T1**
(cloud credential model + vault kinds), and **W2-T2 / W2-T3** (AWS/Azure
credential flows: access keys, STS tokens, service-principal secrets).

**Carry-forward lessons:** `P5-PLAN.md` §0a — read before starting any wave.
The ones that bite most often: every new gate ships a negative control proven
red at least once (keep the red run URL); new `backend/tests/pg/*.py` files
MUST carry `pytestmark = pytest.mark.integration` (prove collection with
`-m integration --collect-only`); AWS/Azure are template-siblings — sweep
class bugs across both in the same fix commit; new deps land via the uv
lockfile in the same commit.

**Validation posture** (`P5-PLAN.md` §0, user-ratified at W0): no live cloud
account, no LLM provider, no certified-scale cluster on the authoring host.
Cloud plugins validate over recorded fixtures; certification executes at the
maximum feasible reduced scale with targets shipped ready-to-run; live/full
criteria are **named deferred-accepted** with promotion paths, never silent.

**This file carries the goal + exit criteria per task.** The 16 W1–W5 deep
specs alongside it are the executable contract, grounded in ADRs 0055–0060
and using the P4 template: Metadata · Objective · Scope In/Out · Requirements ·
Contracts/artifacts · Test & gate plan · Exit criteria.

---

## W0 — ADRs / entry (design gate)

Owner: **`wf-implementer`**. The six ADRs are the contract every later wave
implements; numbered from **0055** (current max 0054). Nothing downstream
re-decides an ADR.

| Task | Title | Review tier | Depends on |
|---|---|---|---|
| W0-T1 | ADR-0055 cloud credential + normalization model (shared) | **strong** (whole — secret surface) | — |
| W0-T2 | ADR-0056 AWS plugin (boto3, incl. Route53 `DDI_DNS`) | sonnet (**strong** credential section) | W0-T1 |
| W0-T3 | ADR-0057 Azure plugin (azure SDK) | sonnet (**strong** credential section) | W0-T1 |
| W0-T4 | ADR-0058 hybrid topology stitching | sonnet | W0-T2, W0-T3 (model names) |
| W0-T5 | ADR-0059 durable dispatch (outbox + `send_task` ratchet) | sonnet (**strong** outbox section) | — |
| W0-T6 | ADR-0060 scale certification methodology | sonnet | — |
| W0-T7 | PRODUCTION.md "P5 in progress" marker + Consultant re-check + deep specs + ADR index | sonnet | W0-T1..T6 |

### W0-T1 — ADR-0055: cloud credential + normalization model

**Goal.** Decide once, shared by both providers (PRODUCTION.md §2.5 "designed
once and shared with Azure"): the read-only cloud credential kinds stored in
the D11 vault (AWS access-key + optional STS assume-role; Azure service
principal), their rotation hooks (ADR-0040 framework), the
`CLOUD_NETWORK_INVENTORY` capability (name PROPOSED here, decided here), the
normalized cloud model set with the cross-provider equivalence table
(VPC↔VNet, subnet, route table, TGW/peering↔VNet-peering, ENI↔NIC), and the
SG/NSG→`FIREWALL_POLICY` normalization contract so cloud rules feed the
existing Security-Agent engine.

**Exit criteria.**
- [ ] ADR-0055 committed (Proposed) covering: vault credential kinds + JSON shapes, least-privilege read-only role/policy documented for operators, rotation integration, capability interface signature, normalized model names/fields, cross-provider equivalence table, SG/NSG→`FIREWALL_POLICY` mapping rules incl. any-any/port-range semantics.
- [ ] Strong review passed on the whole ADR (secret surface); no plaintext credential material in examples.
- [ ] Explicitly states both plugins are **read-only** in P5 (no cloud write path; future writes CR-gated by inheritance).
- [ ] D16 gates green; one atomic commit.

### W0-T2 — ADR-0056: AWS plugin

**Goal.** Bind the AWS plugin design to ADR-0055: boto3 (D7), session/region
enumeration, pagination and throttling/retry policy, recorded-fixture strategy
(botocore-style stubbed responses stored verbatim), the `CLOUD_NETWORK_INVENTORY`
surface (VPCs, subnets, route tables, TGW/peering, SGs, ENIs), and Route53 as
`DDI_DNS` through the existing DDI framework — completing the
BlueCat/Infoblox/Route53 triad.

**Exit criteria.**
- [ ] ADR-0056 committed (Proposed): client/session design, region strategy, retry/backoff on throttling, fixture recording format, per-capability payload→normalized-model mapping, Route53 zone/record mapping into the DDI models.
- [ ] Credential section strong-reviewed; cites ADR-0055 kinds (no re-decision).
- [ ] D16 green; one atomic commit.

### W0-T3 — ADR-0057: Azure plugin

**Goal.** Mirror ADR-0056 for Azure: azure SDK (D7), service-principal auth
via the ADR-0055 kind, subscription/resource-group enumeration, fixture
strategy, and the `CLOUD_NETWORK_INVENTORY` surface (VNets, subnets, route tables,
peerings, NSGs, NICs) mapped to the shared normalized models.

**Exit criteria.**
- [ ] ADR-0057 committed (Proposed) with the same section shape as 0056; every normalized shape resolves to an ADR-0055 model (no Azure-only divergence without a recorded reason).
- [ ] Credential section strong-reviewed.
- [ ] D16 green; one atomic commit.

### W0-T4 — ADR-0058: hybrid topology stitching

**Goal.** Design the P5 platform deliverable: cloud network nodes/edges
PG-backed (expand-only) and projected to Neo4j (D5), and the stitching
derivation that joins cloud VPC/VNet subnets to the on-prem L3 graph via
VPN / Direct Connect / ExpressRoute interconnect edges — join semantics
(gateway endpoints + CIDR/route-table evidence), per-source provenance,
idempotency, conflict rules, rebuild-drill compatibility, and the hybrid
impact/reachability query extension.

**Exit criteria.**
- [ ] ADR-0058 committed (Proposed): node/edge kinds + PG schema sketch, projection mapping, stitching sources per provider, join-evidence rules, provenance format (consistent with ADR-0052's), idempotency contract, rebuild path statement, impact-query surface.
- [ ] Explicit statement: never Neo4j-only state; `neo4j-rebuild-bite.sh` compatibility is a W3 exit criterion.
- [ ] D16 green; one atomic commit.

### W0-T5 — ADR-0059: durable dispatch

**Goal.** Close the two P4 deferrals as one architecture decision: a
transactional outbox on report runs (both request paths commit the outbox row
atomically with the state transition; relay worker with crash recovery —
at-least-once publication, no dropped run, and exactly one render/state-
transition effect), and a platform-wide mandate that all
Celery dispatch goes through the hardened wrapper, enforced by a static CI
ratchet that fails on any new bare `send_task` site. Start from the exact
current dispatch guarantee recorded in `P4-RELEASE-READINESS.md`.

**Exit criteria.**
- [ ] ADR-0059 committed (Proposed): outbox table shape, atomicity contract, relay/recovery semantics (crash windows enumerated; at-least-once + idempotent-dispatch resolution), sweep scope (site inventory), ratchet mechanism and its negative control.
- [ ] Outbox section strong-reviewed (report-run spine).
- [ ] D16 green; one atomic commit.

### W0-T6 — ADR-0060: scale certification methodology

**Goal.** Define what "scale certification" means on this host (honest,
ADR-0047-consistent): a harness at the §11 G-SCA target numbers shipped
ready-to-run, certification executed at maximum feasible reduced scale with
the achieved scale point recorded, G-SCA re-based when the Consultant
scale-targets answer arrives, and the named GA promotion trigger if a
certified-scale environment materializes. User ratifies this posture here.

**Exit criteria.**
- [ ] ADR-0060 committed (Proposed): target table (the five G-SCA bullets), harness composition (seeded-estate generator, k6 profiles, projection fixture, burst profile), reduced-scale execution + recording format, re-base mechanics, promotion trigger.
- [ ] §0 posture user-ratification recorded.
- [ ] D16 green; one atomic commit.

### W0-T7 — P5 entry marker + Consultant re-check + deep specs

**Goal.** Record the phase entry: PRODUCTION.md §1 "P5 in progress" marker;
Consultant §12 re-check (scale targets, air-gapped operation incl. cloud-API
egress posture, data retention, telemetry; raise the new cloud
least-privilege-role question); cut the full per-task deep-spec files from the
reviewed ADRs (P4 template); update the ADR index with 0055–0060.

**Exit criteria.**
- [ ] PRODUCTION.md marker present and consistent with this plan; no drift between the two (G-MNT §308 discipline).
- [ ] Consultant re-check note recorded in `docs/consultant/QUESTIONS.md`.
- [ ] `docs/roadmap/p5-tasks/W*-T*.md` deep specs exist for every W1–W5 task, each grounded line-by-line in its ADR/PRODUCTION.md section.
- [ ] ADR index rows 0055–0060 (Proposed, P5 W0). D16 green; one atomic commit.

---

## W1 — Dispatch durability + observability debt (ADR-0059, §6 rows)

T1 ∥ T2 ∥ T3 (disjoint files). Lands before W4 (burst drills exercise the
hardened dispatch) and W5 (evals certify the final architecture).

**Status:** Implemented and verified 2026-07-23. See
`docs/roadmap/P5-W1-HANDOFF.md`. P5 remains active; this wave does not accept
ADR-0059 or release the phase.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| W1-T1 | Transactional report outbox + relay/recovery | `wf-implementer` | **strong** (escalated) | W0-T5 |
| W1-T2 | Bare-`send_task` sweep + static ratchet | `wf-implementer` | sonnet | W0-T5 |
| W1-T3 | G-OBS reconciliation rows 5/6/9 | `wf-observability` | sonnet | W0 |

### W1-T1 — Transactional report outbox + relay/recovery

**Goal.** Implement ADR-0059's outbox: both report request paths (scheduled
beat + on-demand) commit a durable outbox row in the same transaction as the
report-run state transition; a relay worker dispatches from the outbox with
crash recovery. The P4-recorded crash window (durable requested-but-unclaimed
work; possible drop/double-dispatch) is closed.

**Exit criteria.**
- [x] Atomicity proven under real PG: a planted crash between state transition and publication leaves a row the relay recovers; a post-send/pre-mark crash may redeliver, while stable dispatch identity produces exactly one render/state-transition effect (`backend/tests/pg/`, `pytestmark = pytest.mark.integration`, collection proven via `pytest -m integration --collect-only backend/tests/pg`).
- [x] At-least-once publication produces no dropped run and no duplicate render/state-transition effect across every enumerated crash window (each window has a named test).
- [x] Relay emits metrics (lag, retries, failures) wired to the existing alert spine.
- [x] P4-W4 report conformance evals stay green (no behavioral regression).
- [x] Strong review passed; D16 + `pg-integration` green; implementation and focused review fixes are atomic commits.

### W1-T2 — Bare-`send_task` sweep + static ratchet

**Goal.** Move every platform bare Celery `send_task` site onto the hardened
dispatch wrapper (site inventory from ADR-0059), then institutionalize it: a
static CI ratchet (lint/import-linter/grep-gate per ADR-0059) that fails on
any new bare site, with a planted-site negative control proven red.

**Exit criteria.**
- [x] Zero bare `send_task` sites outside the wrapper (allowlist empty or each entry justified in ADR-0059).
- [x] Ratchet runs in a blocking CI job; the checked-in six-form negative control goes red, then the clean tree passes.
- [x] Behavior-preserving: existing task dispatch tests green; sibling-class sweep applied if a wrapper gap class is found.
- [x] D16 green; implementation and focused review fix are atomic commits.

### W1-T3 — G-OBS reconciliation rows 5/6/9

**Goal.** Promote the three §6 reconciliation rows — scheduled-config-backup
completeness (misses alerted < 15 min), CR-execution→audit completeness
(daily reconciliation), reasoning-trace persistence (no orphans) — from
flagged-deferred to backed: reconciliation jobs emitting series, recording
rules, multi-window burn alerts, runbook links, each with a biting negative
control. Closes the P3 flag the declined P4-W3-T7 stretch left open.

**Exit criteria.**
- [x] Three reconciliation jobs ship with recording rules + alerts + runbooks; `promtool check/test rules` green.
- [x] Negative controls fire: planted missed backup, planted CR-without-audit-chain, planted orphan trace each raise the alert in the fault-injection harness (bite proof per row).
- [x] §6 table rows updated from flagged-deferred to backed (PRODUCTION.md edit in the same commit).
- [x] D16 green; implementation and focused review fixes are atomic commits.

---

## W2 — Vendor Wave 4 cloud plugins (ADR-0055/0056/0057, §2.5/§2.6)

T1 first; then T2 ∥ T3 (disjoint plugin dirs — sibling-class-bug sweep
applies); T4 last. **Blocks W3-T2.** May run ∥ W1.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| W2-T1 | Cloud foundation: capability + normalized models + credential kinds | `wf-implementer` | **strong** (escalated) | W0-T1 |
| W2-T2 | AWS plugin incl. Route53 + fixtures + lockfile | `wf-implementer` | **strong** (escalated) | W2-T1, W0-T2 |
| W2-T3 | Azure plugin + fixtures + lockfile | `wf-implementer` | **strong** (escalated) | W2-T1, W0-T3 |
| W2-T4 | Cloud inventory surfacing (API + UI) | `wf-implementer-light` | sonnet | W2-T2, W2-T3 |

### W2-T1 — Cloud foundation

**Goal.** Implement ADR-0055 once, consumed by both plugins: the
`CLOUD_NETWORK_INVENTORY` capability interface, the normalized cloud model
set (virtual network, subnet, route table, interconnect/peering, NIC) with
the cross-provider equivalence semantics, the SG/NSG→`FIREWALL_POLICY`
normalization contract, and the cloud credential kinds in the D11 vault with
rotation hooks.

**Exit criteria.**
- [ ] Capability interface + models land with round-trip tests; equivalence table encoded as tests (same input semantics ⇒ same normalized shape for AWS/Azure variants).
- [ ] Credential kinds stored/retrieved via the vault only; credential-leak tests extended (zero plaintext in API responses, logs, fixtures).
- [ ] Strong review passed; D16 green; coverage ≥80% on new modules; one atomic commit.

### W2-T2 — AWS plugin (incl. Route53)

**Goal.** Ship `aws` per ADR-0056: `CLOUD_NETWORK_INVENTORY` over VPCs, subnets, route
tables, TGW/peering, security groups (normalized into `FIREWALL_POLICY`
rules), ENIs; `DDI_DNS` via Route53 through the existing DDI framework;
conformance fixtures (raw payloads verbatim); pagination + throttling retry;
read-only.

**Exit criteria.**
- [ ] Conformance suite passes for every declared capability; raw fixtures stored verbatim; normalized models round-trip.
- [ ] SG rules appear in the Security-Agent engine's `FIREWALL_POLICY` input (integration test); Route53 zones/records pass the DDI conformance layer.
- [ ] Credential flow via the vault, STS path covered by tests, zero plaintext leakage (escalated review).
- [ ] `boto3`/`botocore` land via the uv lockfile in the same commit; drift gate green.
- [ ] Live golden-path script ships ready-to-run; deferral named. Coverage ≥80%; plugin + API docs published; one atomic commit.

### W2-T3 — Azure plugin

**Goal.** Ship `azure` per ADR-0057: `CLOUD_NETWORK_INVENTORY` over VNets, subnets,
route tables, peerings, NSGs (same `FIREWALL_POLICY` normalization), NICs;
service-principal credential flow; conformance fixtures; read-only. Validates
the cross-provider normalization before it is declared stable (§2.5).

**Exit criteria.**
- [ ] Conformance suite passes; fixtures verbatim; models round-trip; NSG rules flow into `FIREWALL_POLICY` normalization.
- [ ] Cross-provider equivalence tests green against W2-T2's shapes (VNet↔VPC, NSG↔SG).
- [ ] Credential flow via the vault, zero plaintext leakage (escalated review); sibling-class sweep run against W2-T2 findings.
- [ ] `azure-*` deps via the lockfile; drift gate green. Golden path named-deferred. Coverage ≥80%; docs published; one atomic commit.

### W2-T4 — Cloud inventory surfacing

**Goal.** Surface the new inventory read-only in API + UI, mirroring the
existing inventory pages (device / VS-pool / VM-host precedents): cloud
networks, subnets, interconnects, security-rule summaries per provider.

**Exit criteria.**
- [ ] API endpoints + UI pages ship with route gates/RBAC consistent with existing inventory pages; every new API import added to every sibling `vi.mock` (L-FE-1).
- [ ] Frontend + backend suites green; one atomic commit.

---

## W3 — Hybrid topology stitching (ADR-0058, §2.5, D5)

T1 → T2 → T3; T1 may start on ADR-0058 alongside W2.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| W3-T1 | PG schema + projector for cloud topology | `wf-implementer` | sonnet | W0-T4, W2-T1 |
| W3-T2 | Stitching derivation pipelines + Route53 DNS linkage | `wf-implementer` | sonnet | W3-T1, W2-T2, W2-T3 |
| W3-T3 | Hybrid impact/reachability + agent tool + UI view | `wf-implementer` | sonnet | W3-T1, W3-T2 |

### W3-T1 — PG schema + projector

**Goal.** Land the cloud topology layer per ADR-0058: cloud network node/edge
tables in Postgres (expand-only Alembic migration), Neo4j projection via
`engines/topology/`, with the auto-rebuild path extended to the new kinds.

**Exit criteria.**
- [ ] Expand-only migration; projection produces the new nodes/edges; idempotent re-projection (no dupes) asserted under real PG.
- [ ] **`neo4j-rebuild-bite.sh` stays green with the new kinds** (rebuild from Postgres alone reproduces the layer).
- [ ] Projection-lag SLO recording rule unbroken. D16 + `pg-integration` green; one atomic commit.

### W3-T2 — Stitching derivation + DNS linkage

**Goal.** Derive the hybrid joins: interconnect edges (VPN gateway / Direct
Connect / ExpressRoute) connecting cloud subnets to the on-prem L3 graph
using ADR-0058's join-evidence rules; link Route53 zones into the
DNS-dependency graph. Deterministic, idempotent, per-source provenance on
every edge.

**Exit criteria.**
- [ ] Both providers' interconnect edges derived from recorded fixtures; join evidence (gateway endpoint + CIDR/route-table match) recorded as provenance on each edge.
- [ ] Re-run ⇒ no duplicate edges (real PG assertion); removed source ⇒ edge retracted (inverse test).
- [ ] Route53 zones/records visible in the DNS-dependency graph with provenance.
- [ ] D16 + `pg-integration` green; one atomic commit.

### W3-T3 — Hybrid impact/reachability + UI

**Goal.** Make the stitched graph usable: extend the impact/reachability
query surface ("what on-prem depends on this VPC/subnet", "path from device
to cloud workload"), expose it as a Troubleshooting-Agent tool (answers cite
graph provenance — explainability), and render the hybrid topology UI view.

**Exit criteria.**
- [ ] Query surface + agent tool ship; answers reference edge provenance; deterministic CI eval layer covers the tool (no-LLM posture).
- [ ] UI hybrid view renders on-prem + cloud + interconnect edges with provenance display; scoped queries only (no full-graph fetch).
- [ ] Frontend + backend suites green; one atomic commit.

---

## W4 — Scale certification (ADR-0060, §11 G-SCA, ADR-0047 promotion path)

Needs W1 (hardened dispatch under burst) and W3-T1/T2 (hybrid layer present).
Drills must run AND bite.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| W4-T1 | Certification harness at target numbers | `wf-reliability` | **strong** | W0-T6 |
| W4-T2 | Executed reduced-scale certification runs | `wf-reliability` | **strong** | W4-T1, W1, W3-T1/T2 |
| W4-T3 | G-SCA re-base + certification evidence doc | `wf-release-auditor` | **strong** | W4-T2 |

### W4-T1 — Certification harness

**Goal.** Build the harness at the §11 G-SCA target numbers, parameterized by
scale point: 500-device seeded-estate generator, 100-user k6 API profile
(p95 < 300 ms read at 2 replicas, linear at 4), 5k-device/100k-interface
projection fixture, 10× discovery queue-burst profile with per-queue
isolation checks, PgBouncer connection-budget probes. Ready-to-run at full
targets on a certified-scale cluster.

**Exit criteria.**
- [ ] Every G-SCA bullet has a harness component runnable at both reduced and full-scale parameters from one config.
- [ ] Each drill ships a planted-regression negative control proven to bite (red run URL kept).
- [ ] Harness documented (runbook); D16 green; one atomic commit.

### W4-T2 — Executed certification runs

**Goal.** Run the harness at the maximum feasible reduced scale on the kind
harness with the hybrid layer present and the W1 hardened dispatch in the
path: observe autoscale out/in, queue-burst drain without starving sibling
queues, PgBouncer budget held, projection/UI usable at the achieved scale
point. Record achieved-vs-target per bullet.

**Exit criteria.**
- [ ] All five G-SCA mechanisms exercised and green at the recorded scale point; results captured in a structured evidence artifact (achieved numbers, run URLs).
- [ ] Hybrid/cloud kinds present in the estate under test; P3 `drill-bite-proofs` suite stays green.
- [ ] Any mechanism failure at reduced scale is fixed or named-blocked (no silent skip); one atomic commit.

### W4-T3 — G-SCA re-base + evidence doc

**Goal.** Re-check the Consultant scale-targets item: if answered, re-base the
G-SCA numbers and re-run affected drills; if not, re-confirm the PROPOSED
targets. Publish the certification evidence doc: achieved scale point vs
target per bullet, with the named GA promotion path for every gap (ADR-0060
trigger).

**Exit criteria.**
- [ ] Evidence doc committed; every gap carries a named deferral + promotion path (ADR-0033 §1 discipline — named, never silent).
- [ ] G-SCA gate text updated (re-based or re-confirmed) with no PRODUCTION.md/plan drift.
- [ ] Run URLs verified at the evidenced HEAD (no unexecuted-proof claims); one atomic commit.

---

## W5 — Evals + phase-exit gate (§2.6, §11)

The LAST P5 wave. Builds the *proof*, not new features. **Rebase onto
`origin/main` first.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| W5-T1 | Plugin conformance + cross-vendor eval re-run (13-family roster) | `wf-eval-designer` | **strong** | W2 |
| W5-T2 | Hybrid-stitching derivation eval corpus | `wf-eval-designer` | **strong** | W3 |
| W5-T3 | `P5-RELEASE-READINESS.md` + ADR flips + P5 EXIT marker | `wf-release-auditor` | **strong** | W5-T1/T2, all waves |

### W5-T1 — Conformance + cross-vendor re-run

**Goal.** Extend the roster with `aws`/`azure` (completing the 13 CLAUDE.md
vendor families) and re-run plugin conformance plus the M3 agent/routing
evals; no regression tolerated.

**Exit criteria.**
- [ ] Extended roster passes conformance; routing/agent evals show no regression vs the P4 baseline.
- [ ] Cross-provider normalization asserted in the eval layer (same scenario ⇒ same normalized answer for AWS/Azure estates).
- [ ] One atomic commit.

### W5-T2 — Stitching eval corpus

**Goal.** Build the hybrid derivation eval: synthetic hybrid estates
(on-prem + AWS + Azure fixtures) → expected stitched graph; precision/recall
thresholds; impact-answer correctness; a planted wrong interconnect edge must
fail the eval.

**Exit criteria.**
- [ ] Corpus in CI, deterministic; precision/recall meet ADR-0058 thresholds.
- [ ] **Planted wrong-edge negative control proven red** (red run URL kept), then removed.
- [ ] One atomic commit.

### W5-T3 — Release readiness + exit marker

**Goal.** Audit the P5-scoped §11 gate slice on the release HEAD (per
`P5-PLAN.md` §5 phase-exit list), write `P5-RELEASE-READINESS.md` with cited
run URLs, flip ADRs 0055–0060 → Accepted only on verified green biting
evidence, and record the PRODUCTION.md §1 P5 EXIT marker + GA inheritance
(certified-scale numbers if still open, 30-day soak, pentest, break-glass
cadence, live-lab/live-cloud golden paths).

**Exit criteria.**
- [ ] Every P5-scoped §11 criterion evidenced (CI run URLs at the release HEAD) **or named-deferred with promotion path**.
- [ ] ADRs 0055–0060 flipped Accepted; index updated; PRODUCTION.md marker / P5-PLAN status / readiness doc all agree (no drift).
- [ ] GA inheritance paragraph recorded so nothing silently drops; one atomic commit.

---

## Sequencing (mirrors P5-PLAN.md §4)

- **W0** first — design contract; §0 posture user-ratified there.
- **W1 ∥ W2** after W0 (disjoint files); W1 must land before W4 and W5.
- **W2 before W3-T2**; W3-T1 may start alongside W2 on ADR-0058.
- **W4** after W1 + W3-T1/T2 — certification must include the hybrid layer
  and hardened dispatch, or it certifies a stale architecture.
- **W5** last; release auditor flips ADRs/roadmap only on green.
- **W2/W3/W4 arm the baseline-relative usage guard** at launch.
