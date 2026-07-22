# P5 Build Plan — Vendor Wave 4 (AWS incl. Route53 + Azure) + Hybrid Cloud Topology Stitching + Scale Certification + Dispatch Durability

**Project:** AI Network Operations Platform
**Status:** **CONTRACTED — W0 design gate authored 2026-07-21.** No implementation wave has started. Entry condition is satisfied: **P4 EXIT 2026-07-21** (`docs/roadmap/P4-RELEASE-READINESS.md` — all P4-scoped §11 gates PASS at final PR HEAD `4707f09a`, run `29840145528`; ADRs 0050–0053 Accepted; squash `77d8dd63`).
**Authority:** Bound by `CLAUDE.md`, `docs/architecture/DECISIONS-BRIEF.md` (D1–D16), and `docs/roadmap/PRODUCTION.md` §1 (phase table), §2.5 (Wave 4), §2.6 (per-wave exit criteria), §11 (gates), and the P4 exit marker's **P5 inheritance** paragraph.
**Scope source:** The recorded P5 inheritance (PRODUCTION.md §1 P4-exit marker + `P4-RELEASE-READINESS.md`) — nothing else rides in:

1. **Wave 4 vendors:** AWS (`aws`, boto3, **including Route53** — completes the CLAUDE.md DDI triad) + Azure (`azure`, azure SDK).
2. **Hybrid on-prem/cloud topology stitching** — cloud VPC/VNet subnets joined to the on-prem L3 graph via VPN / Direct Connect / ExpressRoute edges (§2.5).
3. **Scale certification** — the ADR-0047 promotion path, executed as far as this host allows (see §0).
4. **Transactional report outbox + relay/recovery** — deferred from P4-W3/W4 (exact current dispatch guarantee recorded in `P4-RELEASE-READINESS.md`).
5. **Platform-wide bare-`send_task` durable-dispatch sweep** — deferred from P4-W4-T0.
6. **G-OBS reconciliation rows 5/6/9** (§6: scheduled-config-backup completeness, CR-execution→audit completeness, reasoning-trace persistence) — flagged-deferred since P3, drift-guarded, the declined P4-W3-T7 stretch.

**Riding to GA / operational unchanged (NOT P5 scope, named per ADR-0033 §1):** certified-scale G-SCA/G-REL *numbers*, the 30-day calendar soak, external penetration test, recurring six-month break-glass drill, live F5/VMware golden-path promotion (live lab).

---

## 0. Scope discipline — what "validate" means on this host

Same no-hardware posture as M4→P4 (user-ratified each phase; **re-ratify at W0**):

- **No live AWS account or Azure subscription exists on the authoring host.**
  Cloud plugin validation = the plugin **conformance suite over recorded
  fixtures** (raw API payloads stored verbatim — botocore-style stubbed
  responses for AWS, azure-SDK recorded responses for Azure; normalized models
  round-trip), exactly the discipline every prior wave used. The §2.6
  "demonstrated live" criterion is **named deferred-accepted → live cloud
  account**, with golden-path scripts shipped ready-to-run (same posture as the
  F5/VMware live-lab deferral).
- **Scale certification is bounded by the host.** P3 exited G-SCA/G-REL as
  "mechanism PASS at reduced scale + NAMED certified-scale ceiling"
  (ADR-0047, `P3-RELEASE-READINESS.md`). P5's scale-certification track
  delivers: (a) the **certification harness at the §11 G-SCA target numbers**
  (500-device seeded estate, 100-user load profile, 5k-device/100k-interface
  projection fixture, 10× queue burst), shipped ready-to-run; (b) **executed
  certification runs at the maximum feasible reduced scale** on the kind
  harness, with the achieved scale point recorded as evidence; (c) **gate
  re-base** if the Consultant scale-targets answer arrives mid-phase. The
  certified-scale *numbers* remain **named deferred-accepted → GA** unless a
  certified-scale environment is provided during P5 — this is the honest
  reading of "scale certification" on this host and is put to the user for
  ratification at W0 (ADR-0060).
- **No LLM provider on the authoring host.** Agent-facing evals run as the
  deterministic CI layer; real-LLM runs stay the documented opt-in manual gate
  (M3 pattern, unchanged).
- **Everything else in P5 is fully CI-enforceable** — outbox atomicity,
  dispatch ratchet, reconciliation jobs, cloud normalization, stitching
  derivation, projection/rebuild compatibility — and is gated as a true,
  biting PASS with negative controls.
- **Flow-telemetry enrichment (NetFlow/gNMI) stays OUT of scope** until the
  Consultant telemetry item is answered. **Multi-tenancy / NetBox / commercial
  API licensing stay backlog** (§12).

---

## 0a. Lessons carried from P1–P4 — applied here

| Lesson (source) | How P5 applies it |
|---|---|
| **A gate must RUN and BITE** (P1-W4, re-proven every phase) | Every new check ships a negative control proven red at least once (red run URL kept): a planted bare `send_task` site fails the dispatch ratchet; a planted crash between report-state transition and dispatch is recovered by the relay (bite test); a planted wrong hybrid edge fails the stitching eval; a planted missing-backup/orphan-trace fixture fires the row-5/9 reconciliation alerts. |
| **Escalate every secret-surface role to the strong model** (P1-W0) | P5 secret surfaces: **cloud credential model + flows** (W2-T1/T2/T3 — IAM access-key/STS and Azure service-principal material through the D11 vault) and the **report outbox** (W1-T1 — the report-run spine whose artifacts leave the platform, same escalation P4 gave the report engine). Reviewers + fixer on the live strong model; never inline a hard-coded model name. |
| **Parallel-built siblings share bug classes** (P2–P4 recurring) | AWS and Azure plugins are template-siblings (pagination, throttling/retry, fixture handling, empty-region results, credential-expiry paths): a class bug found in one is swept across the other in the same fix commit. Same for the three W1 reconciliation jobs. |
| **SQLite hides PG semantics** (P2 recurring major) | The outbox (row locking, `SELECT … FOR UPDATE SKIP LOCKED`-class semantics, crash recovery), the reconciliation queries, and every stitching idempotency path get `backend/tests/pg/` coverage under the blocking `pg-integration` job — **new `tests/pg/*.py` files MUST carry `pytestmark = pytest.mark.integration`** (proven with `-m integration --collect-only`). |
| **After a kill: trust git, salvage, focused-rerun, never `reset --hard`** | Standing recovery protocol; the atomic commit per task is the save unit. |
| **Arm the baseline-relative usage guard** (`BASELINE = budget.spent()`) | W2 and W3 are the big build waves (4 + 3 tasks); both launches arm the guard: stop near ceiling, commit, summarize. |
| **New deps go through the lockfile** (P3-W0-T8) | `boto3`/`botocore`, `azure-identity`/`azure-mgmt-network`, and `k6`-adjacent tooling land as floor+cap constraints resolved into the uv lockfile in the same commit; drift gate green. |
| **Neo4j is rebuilt from Postgres** (D5) | The hybrid/cloud topology layer is **PG-backed and projected** — never Neo4j-only state. The auto-rebuild path includes the new cloud node/edge kinds and `ci/kind/selftest/neo4j-rebuild-bite.sh` stays green — explicit W3 exit criterion, re-verified at W5. |
| **Verify evidence before trusting promotion commits** (agent-fabricated-bite-proof, PR-green-claims) | W5-T3 (and W4-T3) cite CI run URLs at the release HEAD; every "green" claim re-verified on edit. |
| **Docs-only tip still gets full CI** (P4-W4 finding) | `pull_request` path filtering evaluates the PR's complete diff — do not claim (or plan around) a docs-only CI gap. |
| **Rebase before a new wave; PR-not-mid-run-edit; single combined sonnet reviewer for non-critical** | Standing mechanics (`.claude/workflows/README.md`); dual strong review only on the escalation set. |

---

## 1. Scope

| Track | Deliverables | Source |
|---|---|---|
| Dispatch durability (carried debt) | **Transactional report outbox**: both report request paths commit durable rows atomically with the state transition; relay worker with crash recovery — at-least-once publication with no dropped run and exactly one render/state-transition effect. **Platform-wide `send_task` sweep**: every bare Celery `send_task` site moved onto the hardened dispatch wrapper + a static CI ratchet that fails on any new bare site | P4 exit marker; `P4-RELEASE-READINESS.md` dispatch guarantee; W4-T0 deferral record |
| Observability reconciliation (carried debt) | §6 rows 5/6/9 promoted to backed series: scheduled-config-backup completeness (misses alerted < 15 min), CR-execution→audit completeness (daily reconciliation), reasoning-trace persistence (no orphans) — each with recording rule, burn alert, runbook, and a biting negative control | P3 exit flag; declined P4-W3-T7; PRODUCTION.md §6 |
| Vendor Wave 4 — AWS (`aws`) | boto3 per D7: `CLOUD_NETWORK_INVENTORY` — VPCs, subnets, route tables, TGW/peering, security groups (**→ `FIREWALL_POLICY`-style normalization**), ENIs; **`DDI_DNS` via Route53** (hosted zones + records into the existing DDI framework, completing the BlueCat/Infoblox/Route53 triad); read-only cloud credential model (IAM access key / STS assume-role) via the D11 vault — **designed once, shared with Azure** | §2.5 |
| Vendor Wave 4 — Azure (`azure`) | azure SDK per D7: `CLOUD_NETWORK_INVENTORY` — VNets, subnets, route tables, peerings, NSGs (→ same `FIREWALL_POLICY` normalization), NICs; service-principal credential model mirroring the AWS design; cloud normalization (VNet↔VPC, NSG↔SG) validated across both providers before declared stable | §2.5 |
| Hybrid topology stitching | Cloud network nodes/edges in Postgres (expand-only) projected to Neo4j; stitching derivation joining cloud subnets to the on-prem L3 graph via VPN / Direct Connect / ExpressRoute interconnect edges, deterministic + idempotent + per-source provenance; Route53 zones linked into the DNS-dependency graph; hybrid impact/reachability query surface + Troubleshooting-Agent tool + hybrid topology UI view; rebuild-drill compatibility (D5) | §2.5 platform deliverable |
| Scale certification | Certification harness at the §11 G-SCA target numbers (seeded-estate generator, k6 load profiles, projection-scale fixture, queue-burst profile), ready-to-run; executed reduced-scale certification runs with the achieved scale point recorded; G-SCA re-base on Consultant answers or re-confirmed PROPOSED targets; promotion path to GA kept named | §1, §11 G-SCA, ADR-0047 promotion path |
| Evals + exit | Plugin conformance + cross-vendor/routing re-run (roster extended with `aws`/`azure`, no regression); hybrid-stitching derivation eval corpus (precision/recall, planted wrong-edge negative control); `P5-RELEASE-READINESS.md`; ADRs 0055–0060 flipped on green; PRODUCTION.md P5 EXIT marker + GA inheritance | §2.6, §11 |

**Out of P5 (→ GA / backlog, named):** certified-scale G-SCA/G-REL numbers (unless a certified-scale environment appears mid-phase — ADR-0060 records the trigger), 30-day calendar soak, external pentest, break-glass cadence, live-lab/live-cloud golden-path promotion, flow-telemetry enrichment, Neo4j Enterprise HA, multi-tenancy/NetBox/API licensing.

---

## 2. Agent capability review

Roles + model tiers from `.claude/agents/README.md`. **P5 needs no new agents.** The cloud plugins and stitching are `wf-implementer` shapes; scale certification reuses the P3 SRE roles.

| agentType | Model | P5 use |
|---|---|---|
| `wf-implementer` | strong (inherit) | Novel/security-critical: cloud foundation (capability + normalized models + credential kinds), AWS + Azure plugins, outbox + relay, stitching schema/derivation, hybrid impact tool |
| `wf-implementer-light` | light | Template-following: cloud inventory API/UI pages mirroring existing inventory surfacing, docs pages, golden-path scripts |
| `wf-observability` | strong | W1-T3: rows 5/6/9 reconciliation jobs, recording rules, burn alerts, MTTD-style negative controls |
| `wf-reliability` | strong | W4: certification harness + executed reduced-scale certification runs (drill-as-test: must run AND bite) |
| `wf-eval-designer` | strong | W5: cross-vendor re-run, stitching eval corpus |
| `wf-release-auditor` | strong | W4-T3 gate re-base evidence; W5-T3 readiness doc + ADR/roadmap flips on green |
| `wf-spec-reviewer` / `wf-quality-reviewer` | sonnet* | Spec + quality review per task |
| `wf-fixer` / `wf-verifier` | sonnet* | Apply enumerated findings / confirm resolved |

\* **Escalation rule** (standing): every secret-surface task escalates reviewers +
fixer to the **live strong model** (confirm the model exists in the live
registry before launch — dead-model escalation returns a silently "clean"
review). **P5 secret-surface set: W1-T1** (report outbox — report-run spine,
artifacts leave the platform), **W2-T1** (cloud credential model + vault
kinds), **W2-T2 / W2-T3** (AWS/Azure credential flows: access keys, STS
tokens, service-principal secrets).

---

## 3. Build waves (dependency-ordered)

Per-task pattern, unchanged since P1: **1 implementer → 2 reviewers (spec +
quality) → conditional fixer → verifier → 1 atomic commit.** Sequential tasks
share files; parallelize only within a task. Single combined sonnet reviewer
allowed for non-secret-surface tasks; dual strong review on the escalation set.
ADRs numbered from **0055** (prior max 0054). Per-task goals + exit criteria:
`docs/roadmap/p5-tasks/README.md`; all 16 W1–W5 deep specs use the P4
Metadata/Objective/Scope/Requirements/Contracts/Test-plan/Exit template and
are part of this W0 contract.

| Wave | Tasks | Owner(s) | Review tier | Notes |
|---|---|---|---|---|
| **W0 — ADRs / entry (design gate)** | **T1** ADR-0055 cloud credential + normalization model (shared, designed once: read-only IAM access-key/STS + Azure service-principal kinds in the D11 vault, rotation hooks per ADR-0040; `CLOUD_NETWORK_INVENTORY` capability — name PROPOSED; normalized cloud models + cross-provider equivalence VPC↔VNet / SG↔NSG / TGW-peering↔VNet-peering / ENI↔NIC; SG/NSG→`FIREWALL_POLICY` normalization contract); **T2** ADR-0056 AWS plugin (boto3, session/region handling, pagination + throttling retry, fixture strategy, Route53 `DDI_DNS` into the DDI framework); **T3** ADR-0057 Azure plugin (azure SDK mirror, subscription/RG enumeration); **T4** ADR-0058 hybrid topology stitching (cloud node/edge kinds in PG, interconnect-edge join semantics for VPN/DX/ER, provenance, idempotency, rebuild compatibility, impact-query extension); **T5** ADR-0059 durable dispatch (transactional outbox + relay/recovery on report runs; platform `send_task` wrapper mandate + static ratchet); **T6** ADR-0060 scale certification methodology (targets, harness, reduced-scale execution posture, gate re-base + GA promotion trigger); **T7** `PRODUCTION.md` "P5 in progress" marker + Consultant §12 re-check + per-task deep specs + ADR index | `wf-implementer` | sonnet (**strong** on 0055 whole + credential sections of 0056/0057 + 0059 outbox section) | Design gate; unblocks all waves. §0 posture ratified by user here |
| **W1 — Dispatch durability + observability debt** | **T1** transactional report outbox + relay/recovery: both report request paths commit the outbox row atomically with the state transition; relay dispatches with crash recovery (no drop, no double-dispatch), `tests/pg/` bite coverage (`wf-implementer`, **escalated**); **T2** bare-`send_task` sweep: every platform site onto the hardened dispatch wrapper; static CI ratchet fails on new bare sites, planted-site negative control (`wf-implementer`); **T3** G-OBS rows 5/6/9: reconciliation jobs + recording rules + burn alerts + runbooks for config-backup completeness / CR→audit completeness / trace persistence, each with a biting negative control (`wf-observability`) | `wf-implementer` + `wf-observability` | strong (T1) / sonnet (T2/T3) | T1 ∥ T2 ∥ T3 (disjoint). Debt first so W4 load runs and W5 eval re-runs certify the final dispatch architecture |
| **W2 — Vendor Wave 4 cloud plugins** | **T1** cloud foundation: `CLOUD_NETWORK_INVENTORY` capability interface + normalized cloud models + cloud credential kinds in the D11 vault (`wf-implementer`, **escalated**); **T2** AWS plugin: discovery of VPCs/subnets/route tables/TGW+peering/SGs/ENIs, SG→`FIREWALL_POLICY` normalization, Route53 `DDI_DNS`, conformance fixtures, lockfile (`wf-implementer`, **escalated** credential flow); **T3** Azure plugin: VNets/subnets/route tables/peerings/NSGs/NICs, conformance fixtures, lockfile (`wf-implementer`, **escalated** credential flow); **T4** cloud inventory surfacing: API endpoints + UI pages mirroring existing inventory pages (`wf-implementer-light`) | `wf-implementer` (+ light T4) | strong (T1–T3) / sonnet (T4) | T1 first; then T2 ∥ T3 (disjoint plugin dirs — sibling-class-bug sweep applies); T4 last. **Blocks W3-T2 stitching.** May run ∥ W1 (disjoint files) |
| **W3 — Hybrid topology stitching** | **T1** PG schema + projector: cloud network nodes/edges (expand-only migration), Neo4j projection via `engines/topology/`, **rebuild path includes the new kinds — `neo4j-rebuild-bite.sh` stays green** (`wf-implementer`); **T2** stitching derivation: interconnect edges (VPN gateway / Direct Connect / ExpressRoute) joining cloud subnets to on-prem L3, Route53-zone linkage into the DNS-dependency graph — deterministic, idempotent, per-source provenance (`wf-implementer`); **T3** hybrid impact/reachability: query surface extension + Troubleshooting-Agent tool + hybrid topology UI view with provenance display (`wf-implementer`) | `wf-implementer` | sonnet | T1 can start on ADR-0058 (∥ W2); T2 needs W2-T2/T3 models; T1→T2→T3. Projection-lag SLO must hold |
| **W4 — Scale certification** | **T1** certification harness at target numbers: 500-device seeded-estate generator, 100-user k6 API profile, 5k-device/100k-interface projection fixture, 10× queue-burst profile — ready-to-run, parameterized by scale point (`wf-reliability`); **T2** executed certification runs at maximum feasible reduced scale on the kind harness (all five G-SCA bullets exercised at mechanism level, incl. PgBouncer connection budget and per-queue isolation, with the hybrid/cloud layer present), achieved scale point + results recorded (`wf-reliability`); **T3** G-SCA re-base: Consultant scale-targets re-check → re-base gate numbers or re-confirm PROPOSED; certification evidence doc with named GA promotion path (`wf-release-auditor`) | `wf-reliability` + `wf-release-auditor` | strong | Needs W1 (hardened dispatch under burst) + W3-T1/T2 (hybrid layer present). Drills must run AND bite (planted-regression controls) |
| **W5 — Evals + phase-exit gate** | **T1** plugin conformance + cross-vendor eval re-run: roster extended with `aws`/`azure` (13 vendor families complete), M3 agent evals + routing no-regression (`wf-eval-designer`); **T2** hybrid-stitching derivation eval corpus: synthetic hybrid estates → expected stitched graph, precision/recall thresholds, impact correctness, **planted wrong-edge negative control** (`wf-eval-designer`); **T3** `P5-RELEASE-READINESS.md` G-* evidence; flip ADRs 0055–0060 Accepted on green; `PRODUCTION.md` P5 EXIT marker + GA inheritance recorded (`wf-release-auditor`) | `wf-eval-designer` + `wf-release-auditor` | strong | Phase-exit gate; mirrors P1-W7/P2-W5/P3-W5/P4-W4. Builds the *proof*, not new features. Rebase onto `origin/main` first |

---

## 4. Sequencing

- **W0 first** — the six ADRs are the design contract; credential/normalization/
  join-semantics/outbox/certification decisions are made once there, not
  mid-wave. The user ratifies the §0 posture (incl. what "scale certification"
  means on this host) at W0.
- **W1 ∥ W2 after W0** — dispatch durability + observability debt (report/
  Celery/obs spine) and the cloud plugins (plugin dirs) touch disjoint files.
  W1 lands before W4 so the burst drills exercise the hardened dispatch, and
  before W5 so eval re-runs certify the final architecture.
- **W2 before W3-T2** — stitching derivation consumes the persisted normalized
  cloud rows; building against unstable models is rework. W2-T2 ∥ W2-T3
  (disjoint plugin dirs — sibling-class-bug sweep applies). W3-T1 needs only
  ADR-0058 and can start alongside W2.
- **W4 after W1 + W3-T1/T2** — certification runs must include the hybrid
  layer and the hardened dispatch path, or they certify a stale architecture.
- **W5 last** — evals need both plugins, the stitched graph, and the
  certification evidence in place; the release auditor flips ADRs/roadmap only
  on green. Rebase onto `origin/main` first.
- **W2 and W3 arm the baseline-relative usage guard** (the two big build
  waves); W4 arms it too (drill runs are long).

---

## 5. Per-wave exit criteria

**W0 (design):** ADRs 0055–0060 written (Proposed); ADR-0055 whole + the
credential sections of 0056/0057 + the 0059 outbox section reviewed at the
strong bar; `PRODUCTION.md` carries the "P5 in progress" marker; Consultant
§12 re-check recorded (scale targets, air-gapped operation — now also covering
cloud-SDK egress —, data retention, telemetry re-confirmed or converted; new
question raised: read-only cloud role/least-privilege provisioning);
`docs/roadmap/p5-tasks/` deep specs exist with explicit exit criteria per
task; §0 posture user-ratified. D16 green.

**W1 (dispatch durability + obs debt):** both report request paths commit the
outbox row atomically with the state transition — a planted crash between
transition and publication is recovered by the relay with **no dropped run and
exactly one render/state-transition effect despite permitted redelivery**,
proven under real PG (`backend/tests/pg/`, `pytestmark` integration, collection
proven); zero bare `send_task` sites remain outside
the hardened wrapper and the **static ratchet fails on a planted bare site**
(red run URL kept); rows 5/6/9 have backed series + burn alerts + runbooks and
each reconciliation **negative control fires** (planted missed backup, planted
CR-without-audit, planted orphan trace); no regression in report conformance
evals (P4-W4-T3 suite stays green).

**W2 (cloud plugins):** both plugins pass the conformance suite over recorded
fixtures (raw payloads verbatim; normalized models round-trip); cross-provider
normalization equivalence validated (VPC↔VNet, SG↔NSG produce the same
normalized shapes); SG/NSG rules land in the `FIREWALL_POLICY` normalization
consumed by the Security Agent engine; Route53 zones/records flow through the
existing DDI framework (`DDI_DNS` conformance); credential flows use the D11
vault with zero plaintext leakage (escalated review; credential-leak tests
extended to cloud fixtures); write paths: **none in scope** — both plugins are
read-only this wave, and any future cloud write path is CR-gated by
inheritance; coverage ≥80% (D16); plugin + API docs published; live cloud
golden paths shipped ready-to-run and **named deferred-accepted → live cloud
account**; lockfile updated (`boto3`, `azure-*`), drift gate green.

**W3 (hybrid stitching):** cloud network nodes/edges live in Postgres
(expand-only migration) and project to Neo4j; stitching derivation joins cloud
subnets to on-prem L3 via interconnect edges with per-source provenance,
deterministic and idempotent (re-run ⇒ no dupes, asserted under real PG);
Route53 zones linked into the DNS-dependency graph; **the Neo4j auto-rebuild
path reproduces the hybrid layer from Postgres alone and
`neo4j-rebuild-bite.sh` stays green**; projection-lag SLO recording rule holds
with the new kinds; hybrid impact/reachability answers cite provenance; the
Troubleshooting Agent exposes the hybrid impact tool; UI renders the hybrid
topology view.

**W4 (scale certification):** the harness generates the §11 G-SCA target
loads parameterized by scale point and is ready-to-run at full targets;
certification runs executed at the recorded maximum feasible reduced scale
with the hybrid layer present — autoscale out/in observed, per-queue isolation
held under 10× burst, PgBouncer budget held, projection/UI usable at the
achieved scale point; each drill has a planted-regression negative control
proven to bite; G-SCA re-based on Consultant answers or PROPOSED targets
re-confirmed; certification evidence doc records achieved-vs-target per bullet
with the **named GA promotion path** for every gap.

**Phase exit (W5):** the P5-scoped slice of the §11 gates passes
simultaneously on the release HEAD —
- **G-SEC — PASS (continuous):** P1–P4 controls inherited, no regression;
  credential-leak tests cover cloud credentials (vault-stored, zero plaintext
  in responses/logs/fixtures); cloud plugins read-only; four-eyes + audit
  invariants unbroken.
- **G-MNT — PASS:** D16 green (coverage ≥80% incl. both cloud plugins); ADRs
  0055–0060 Accepted on green implementing evidence; docs + API docs per
  feature; new-plugin onboarding re-validated this wave (§2.6/§11 item);
  lockfile green.
- **G-OBS — PASS (P5 slice):** rows 5/6/9 backed + alerting (the P3 flag
  closed); outbox/relay and stitching-pipeline metrics exist with alerts;
  projection-lag SLO unbroken.
- **G-SCA — mechanism PASS at recorded scale point:** certification evidence
  doc accepted; certified-scale numbers either re-based-and-met (if an
  environment materialized) or **named deferred-accepted → GA** with the
  promotion trigger recorded.
- **G-REL — no regression:** P3 drill suite + `drill-bite-proofs` green with
  the hybrid layer present; rebuild drill explicitly re-verified.
- **Evals:** cross-vendor + routing no-regression with the 13-family roster;
  stitching precision/recall green **and biting** (negative control shown red
  at least once).
- Live cloud golden paths **named deferred-accepted → live cloud account**;
  GA items re-recorded in the exit marker's GA-inheritance paragraph.

---

## 6. Open items (non-blocking, carry forward)

- **Consultant §12 answers** — re-check at W0-T7: *scale targets* (re-bases
  G-SCA at W4-T3), *air-gapped operation* (cloud plugins require egress to
  cloud APIs by nature — record the partial-connectivity posture), *data
  retention*, *telemetry* (stays out), plus the new *cloud read-only
  role/least-privilege provisioning* question (IAM policy / Azure role
  definition shipped as docs for the operator).
- **Live cloud golden paths** — deferred-accepted → live cloud account;
  scripts shipped ready-to-run (same posture as every prior wave).
- **GA inheritance (record at W5-T3 so nothing drops):** certified-scale
  G-SCA/G-REL numbers (unless closed at W4), 30-day calendar soak, external
  pentest, six-month break-glass cadence, live-lab F5/VMware + live-cloud
  AWS/Azure golden-path promotion.
- **Working-tree hygiene note (2026-07-21):** at plan authoring time the
  repo working tree carried uncommitted modifications that *revert* parts of
  the merged PR #167 closeout docs (stale pre-merge file versions, likely
  worktree-salvage residue). W0 must branch from clean `origin/main`
  (`33f24074` or later), not from that tree.
- **Vault status note** — the orchestrator's Obsidian vault P5 status note +
  auto-memory `MEMORY.md` entry are updated outside the in-repo commits
  (flagged so the sync is not silently skipped).
