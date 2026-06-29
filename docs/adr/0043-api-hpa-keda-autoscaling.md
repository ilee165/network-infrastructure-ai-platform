# ADR-0043: api Horizontal Pod Autoscaler + KEDA Per-Queue Worker Autoscaling

**Status:** Proposed | **Date:** 2026-06-29 | **Milestone:** P3 W0

## Context

`PRODUCTION.md` §3 schedules HA/scale-out for **P3-Platform**, and §3.2 fixes the
compute-tier shape: the `api` tier runs at **≥2 replicas always with an HPA on CPU +
request rate** behind a PodDisruptionBudget, and the worker tier runs **one Deployment
per queue, autoscaled via KEDA ScaledObjects on Redis queue length** (fallback: HPA on
celery-exporter metrics), with `acks_late` + idempotent tasks so scale-in / node loss
only re-runs work. §11 **G-SCA** is the gate this design must satisfy — specifically
the **queue-burst** criterion (§329): "10× normal `discovery` queue depth triggers KEDA
scale-out and drains within the SLO **without starving `config`/`packet`/`docs` queues**
(per-queue isolation verified)" — and the **API load** criterion (§327): 2 `api`
replicas hold p95 < 300 ms with a linear improvement at 4 replicas.

This ADR is the **design gate**. It ratifies the autoscaling design the build
implements in **W2-T1** (`api` HPA + PDB — render / policy gates), **W2-T3** (KEDA
ScaledObjects per queue — render / policy gates), and **W2-T4** (worker `acks_late` +
idempotency hardening), and that the live **W4-T6** drill asserts (queue-burst
scale-out/in + per-queue isolation + reduced-scale API load p95 + PgBouncer budget). It
does **not** implement those controls — it fixes the autoscaler choice, the scaling
signals, the min/max replica + PDB bounds, the per-queue-isolation requirement, and the
packet-pool exception.

Bounded by **ADR-0008** (Celery + Redis broker/result, dedicated per-queue Deployments —
the queues this ADR scales), **ADR-0013** (Docker Compose for MVP / Kubernetes via Helm
for production — the deploy target), **ADR-0029** (K8s/Helm GA chart + hardening
baseline — where the HPA/PDB/ScaledObject manifests render), **ADR-0031** (packet
sandbox OS-isolation + tainted node pool — the packet-worker exception below), and
cross-referenced with **ADR-0044** (Redis Sentinel + stateless WebSocket fan-out via
Redis pub/sub — the statelessness this api-HPA design depends on) and **ADR-0042**
(Postgres HA + PgBouncer — the connection budget the scaled-out tiers consume, asserted
together in W4-T6). PRODUCTION.md §3.1/§3.2 and §11 G-SCA §326–§330 are the line-by-line
source.

The §1 (2026-06-25) re-scope moved the live scale/soak drills out of P2-Security into
P3-Platform because they need a real platform stack to validate; this ADR is the
compute-tier half of that move. Per `P3-PLATFORM-PLAN.md` §0, the *mechanism* is proven
to bite at **reduced scale** on an ephemeral HA kind cluster (W4-T1/T6) — scale-out/in
observed, per-queue isolation observed, a 1→2-replica p95 improvement observed; the
**certified-scale** numbers (500-device discovery ≤ 60 min, 100 concurrent users at
p95 < 300 ms, 5,000-device projection) are **named deferred-accepted → GA / customer
cluster**, never silently claimed.

## Decision

**The `api` Deployment runs at a minimum of 2 replicas at all times, autoscaled by a
Horizontal Pod Autoscaler on CPU utilization *and* request rate, guarded by a
PodDisruptionBudget with `minAvailable: 1`; its statelessness is the precondition and
depends on ADR-0044 (WebSocket fan-out via Redis pub/sub). Each Celery work queue runs
as its own Deployment, autoscaled by an independent KEDA ScaledObject on that queue's
Redis list length, so one queue's burst scales only that queue and never consumes
another's capacity (per-queue isolation, G-SCA §329). The packet workers are the
exception: the `packet_capture` and `packet_analysis` Deployments are pinned to the
ADR-0031 tainted, sandboxed node pool and bounded separately, so a `NET_RAW`-capable or
untrusted-parser Pod never scales onto a general node. If KEDA is unavailable in a
customer cluster the named fallback is an HPA on celery-exporter queue-depth metrics —
not a silent default. Worker scale-in / node loss is made safe by Celery `acks_late` +
idempotent tasks (ADR-0008 §5; hardened in W2-T4), so a redelivered task re-runs work
without a duplicate side effect.**

### 1. api tier — ≥2 replicas, HPA on CPU + request rate, PDB

The `api` Deployment (ADR-0013/0029) is the stateless front door (PRODUCTION.md §3.1
`apiTier - stateless`). Autoscaling shape:

- **Floor `minReplicas: 2` (always), ceiling `maxReplicas` PROPOSED (e.g. 10).** The
  floor is a firm §3.2 requirement ("≥2 replicas always") — it survives a single node
  loss and is the substrate the PDB (below) protects; it is **not** an autoscaler
  artifact (an HPA may scale to its floor, so the floor *is* 2, never 1). The ceiling is
  a PROPOSED reference bound pending the Consultant scale-target answer (§12, re-checked
  W0-T9); the §327 "linear improvement at 4 replicas" criterion sets the practical lower
  bound on the ceiling.
- **Dual signal: CPU utilization + request rate.** A `metrics.resource` target on CPU
  utilization (e.g. 70%) catches compute-bound load; a request-rate signal (requests
  per second per pod, exposed by the api `/metrics` per ADR-0015 and read via a
  Prometheus-adapter `metrics.pods`/`metrics.external` target, or the KEDA Prometheus
  scaler if KEDA fronts the api too) catches the connection/throughput-bound load that
  CPU alone misses for an I/O-bound FastAPI tier. CPU-only was rejected (§Alternatives):
  a request flood that blocks on Postgres/Neo4j/LLM I/O drives latency past the §327 p95
  budget while CPU stays low, so it would not trigger. The HPA scales on
  **whichever signal demands more replicas** (HPA max-of-metrics semantics).
- **PodDisruptionBudget `minAvailable: 1`** (PRODUCTION.md §3.2). A voluntary
  disruption (node drain, rolling upgrade, the W4-T8 N-2 rehearsal) can never take the
  api tier below 1 ready replica; combined with the `minReplicas: 2` floor and an
  anti-affinity preference across nodes, an involuntary single-node loss leaves ≥1
  replica serving.
- **Statelessness is the precondition — and it depends on ADR-0044.** An HPA across N
  replicas is only correct if any replica can serve any request. JWT auth (ADR-0010) is
  already stateless, but **WebSocket agent-session streaming is not stateless unless its
  state is externalized**: a session opened on replica A must be served from replica B.
  ADR-0044 (Redis pub/sub fan-out, built in W2-T2) is what makes that true. **This ADR
  and ADR-0044 are deliberately cross-referenced: if WS fan-out slips, the
  stateless-api assumption is silently broken and the HPA can route a session to a
  replica that does not hold it.** W2-T1 must not raise `minReplicas` above 1 in a way
  that exposes WS sessions before W2-T2 lands (sequencing: ADR-0044 / W2-T2 before or
  with the api scale-out), and the §3.1 topology already places Redis pub/sub on the
  critical path for exactly this reason.

### 2. Worker tier — KEDA ScaledObject per queue on Redis list length

ADR-0008 runs **one Celery Deployment per work queue**. The canonical queues in the
running app (`backend/app/workers/celery_app.py`, `WORK_QUEUES`) are **`discovery`,
`config`, `docs`, `topology`, and the ADR-0031 packet split `packet_capture` /
`packet_analysis`** (plus a non-scaled `system` default queue for operational tasks such
as healthcheck and KEK-rotation). The spec's shorthand "discovery/config/packet/docs" is
the §3.2 abstraction; the autoscaling design binds to the **real** queue set, treating
the packet split as two workloads (§3) and `topology` as a first-class scaled queue
(discovery → Neo4j projection bursts with discovery).

- **One ScaledObject per queue, scaling its own Deployment.** Each KEDA `ScaledObject`
  targets one queue's Deployment and uses the KEDA **`redis` scaler on that queue's list
  length** (the Celery broker stores each queue as a Redis list keyed by the queue name;
  the scaler reads `LLEN <queue>` and a `listLength` target). Pending work in the queue
  is the demand signal — the metric that directly reflects backlog, unlike CPU (a worker
  blocked on a slow SSH/SNMP collection is backed up but not CPU-busy).
- **Per-queue scale bounds.** Each ScaledObject sets its own `minReplicaCount` (PROPOSED
  0 or 1 per queue — `topology`/`docs` may idle to 0 between bursts; `discovery`/`config`
  may hold a warm 1), `maxReplicaCount` (PROPOSED per-queue ceiling), and `listLength`
  target (pending tasks per replica). KEDA manages an HPA under the hood; scale-from-zero
  is a KEDA capability the celery-exporter-HPA fallback (§5) lacks, recorded as a reason
  KEDA is primary.
- **Polling + cooldown stated (the burst-drain realism the risk calls out).** KEDA's
  `pollingInterval` (PROPOSED 15–30 s) and `cooldownPeriod` (PROPOSED 300 s before
  scaling a queue back toward its floor) are fixed here because the W4-T6 burst-drain SLO
  depends on them: too long a polling interval and the 10× `discovery` burst (§329)
  drains slowly; too short a cooldown and the tier flaps. These are the numbers the
  drill measures against, named so the drill target is realistic.

### 3. Per-queue isolation — the G-SCA §329 load-bearing requirement

The §329 criterion is **"10× normal `discovery` queue depth … without starving
`config`/`packet`/`docs` queues (per-queue isolation verified)."** Independent
per-queue ScaledObjects + per-queue Deployments are the mechanism:

- A `discovery` burst scales **only** the `discovery` Deployment (its ScaledObject reads
  only `LLEN discovery`); it never consumes `config`/`docs`/`topology`/`packet` replica
  budget because those are separate Deployments with separate ScaledObjects and separate
  (per-queue, not shared) `maxReplicaCount` ceilings.
- **A single shared autoscaler over a combined worker pool is rejected** (§Alternatives):
  it would let a `discovery` flood consume the whole pool and starve `config`/`packet`,
  the exact failure §329 forbids. The isolation is structural (one ScaledObject ⇄ one
  Deployment ⇄ one queue), not a tuning knob.
- This is the assertion **W4-T6** makes bite: under a 10× `discovery` depth, `config` /
  `packet_*` / `docs` / `topology` retain capacity and their own backlogs drain within
  SLO; a **negative control** (a shared/over-broad scaler, or a `discovery` ceiling that
  starves the node) shows the isolation assertion go red (P1-W4: a gate must RUN and
  BITE).

### 4. Packet-worker exception — pinned to the ADR-0031 sandboxed node pool

The packet workers are the one queue family that does **not** autoscale onto general
nodes. Per ADR-0031 §5 the `packet_capture` (NET_RAW, credential-bearing, trusted input)
and `packet_analysis` (zero-capability, untrusted-pcap parser, default-deny egress,
seccomp-confined) Deployments are pinned to a **tainted, dedicated node pool**
(`node-role.netops/packet=true:NoSchedule`) so a raw-socket-capable or untrusted-parser
Pod can never co-schedule with a general platform Pod.

- **Scaling is bounded separately and stays on the pool.** A `packet_capture` /
  `packet_analysis` ScaledObject scales replicas **only within the tainted pool** (the
  Deployments carry the matching toleration + nodeSelector/affinity from ADR-0031 §5);
  the autoscaler must never burst packet Pods onto general nodes. The per-queue
  `maxReplicaCount` for the packet workloads is therefore also bounded by the sandbox
  pool's capacity, separately from the general worker ceilings.
- **No autoscaler change to the privilege posture.** Scaling adds *replicas*, never
  capabilities: every `packet_analysis` replica is still zero-cap / read-only-rootfs /
  seccomp-confined (ADR-0031 §2), every `packet_capture` replica still scopes `NET_RAW`
  to the capture workload on the pool (ADR-0031 §1). Autoscaling is orthogonal to the
  isolation profile and must not relax it.
- The packet workloads may use a list-length signal like the others, but their floor
  and ceiling are governed by the dedicated pool's sizing, not the general worker tier's
  — recorded so an operator sizing the packet pool sizes it independently.

### 5. Fallback named — HPA on celery-exporter metrics if KEDA is unavailable

KEDA is the **primary** autoscaler (PRODUCTION.md §3.2). Some customer clusters cannot
or will not install the KEDA operator (an extra controller + CRDs). The **named
fallback** is a standard Kubernetes **HPA driven by celery-exporter queue-depth metrics**
(celery-exporter exposes per-queue length as a Prometheus metric; the Prometheus adapter
publishes it as a custom/external metric the HPA targets). This is recorded so the
autoscaler choice is **explicit, not a silent default** — switching is a chart-values
decision, and any deviation that changes the design intent is a superseding-ADR change
(G-MNT, no silent drift). The fallback delivers per-queue scale-out on the same
list-length signal, with two stated losses vs. KEDA: **no scale-to-zero** (HPA
`minReplicas` ≥ 1) and a coarser scaling loop (HPA's fixed sync period vs. KEDA's
configurable `pollingInterval`). Functionally per-queue isolation is preserved (one HPA
per queue Deployment), so the §329 guarantee holds under the fallback too.

### 6. Scale-in / node-loss safety — `acks_late` + idempotency (cross-ref W2-T4)

Autoscaling routinely **kills worker Pods** (scale-in, KEDA cooldown, the W4-T5 chaos
drill, node drain). Celery is already configured `task_acks_late=True` +
`task_reject_on_worker_lost=True` + `worker_prefetch_multiplier=1`
(`celery_app.py`, ADR-0008 §5), so a task interrupted by a scaled-in / lost worker is
**redelivered**, not lost. That redelivery is only safe if tasks are **idempotent** — a
re-run produces no duplicate side effect (a second discovery write, a duplicate config
capture, a double audit row). **W2-T4 owns that idempotency hardening and asserts it on
real PG** (`tests/pg/`, `pg-integration` — never SQLite, P2 lesson); this ADR records
that scale-in correctness *depends* on it, so the autoscaling design is not ratified in
isolation from the idempotency guarantee that makes it safe. The W4-T5 worker-kill drill
(Celery success ≥ 99%, no duplicate side effect) is the live proof.

### 7. Build-task contract — the assertions this ADR pins

So the build tasks have a testable contract (the ADR is the design; the gates are the
proof):

- **W2-T1** (`wf-infra`, render/policy): the `api` HPA renders with `minReplicas: 2`,
  dual metrics (CPU + request rate), a PROPOSED ceiling; a PDB with `minAvailable: 1`;
  both pass infra policy gates (`helm lint`, `helm template | kubeconform -strict`,
  kube-linter, conftest) and render-twice stable. The chart wires the request-rate
  metric source (Prometheus adapter or KEDA Prometheus scaler).
- **W2-T3** (`wf-infra`, render/policy): one KEDA `ScaledObject` per **real** work queue
  (`discovery`, `config`, `docs`, `topology`, `packet_capture`, `packet_analysis`),
  each on its own queue's Redis list length, with per-queue min/max + `listLength` +
  `pollingInterval`/`cooldownPeriod` per §2; the packet ScaledObjects target Deployments
  pinned to the ADR-0031 tainted pool (§4); the celery-exporter-HPA fallback is a chart
  toggle (§5). Policy gates green; render-twice stable.
- **W2-T4** (`wf-implementer`): worker tasks are `acks_late` + **idempotent** — a
  redelivered task on scale-in / node loss produces **no duplicate side effect**,
  asserted on real PG (§6).
- **W4-T6** (`wf-reliability`): live on the W4-T1 kind cluster — a **10× `discovery`
  queue depth** triggers KEDA **scale-out then scale-in** and drains within SLO;
  `config` / `packet_*` / `docs` / `topology` are **not starved** (per-queue isolation,
  §3); a reduced-scale API load shows **p95 held and a 1→2-replica improvement** (§327);
  PgBouncer shows **no connection exhaustion** (G-SCA §330, ADR-0042 §4). A **negative
  control** (shared scaler, or async/non-idempotent worker) makes an assertion go red,
  proving the drill bites. Reduced scale, **stated**; the 500-device / 100-user /
  5,000-device **certified-scale** numbers are **named deferred-accepted → GA** (§0). L5
  pipefail + `test -s` on the drill pipeline.

### 8. Scope boundary

**In:** the autoscaler choice (KEDA primary, celery-exporter HPA fallback), the scaling
signals (api: CPU + request rate; workers: per-queue Redis list length), min/max replica
bounds + PDB `minAvailable`, the polling/cooldown values that set the burst-drain SLO,
the per-queue-isolation requirement, the packet-worker tainted-pool exception, and the
scale-in safety dependency on `acks_late` + idempotency. **Out:** the implementation
(W2-T1/T3), the worker idempotency hardening itself (W2-T4), the WebSocket fan-out that
makes the api stateless (ADR-0044 / W2-T2 — cross-referenced, not decided here), the
queue-burst + load **drill** (W4-T6), certified-scale numbers (named deferred-accepted,
§0), and HA of the data tier (ADR-0042 Postgres, ADR-0044 Redis Sentinel). Infra policy
gates stay green on the new manifests (named for W2-T1/T3).

## Consequences

**Positive**
- The api tier survives a single node loss (≥2 replicas + PDB `minAvailable: 1`) and
  scales on the two signals that actually predict latency for an I/O-bound FastAPI
  service (CPU + request rate), meeting the §327 load criterion.
- Per-queue ScaledObjects give **structural** per-queue isolation: a `discovery` burst
  cannot starve `config`/`packet`/`docs`/`topology` (G-SCA §329), because isolation is
  one-ScaledObject-per-Deployment, not a shared-pool tuning knob.
- The KEDA `redis` list-length signal scales on real backlog (and from zero for bursty
  queues), which CPU-based autoscaling cannot do for I/O-bound workers.
- The packet workers scale **only** within the ADR-0031 tainted pool, so autoscaling
  never lands a `NET_RAW` or untrusted-parser Pod on a general node, and never relaxes
  the §2 isolation profile.
- A named celery-exporter-HPA fallback keeps the design deployable where KEDA is not
  permitted — explicit, not silent.
- Scale-in is safe by construction: `acks_late` + idempotency (W2-T4) means a killed
  worker's task is redelivered without a duplicate side effect.

**Negative**
- A request-rate HPA signal needs a metrics source (Prometheus adapter or a KEDA
  Prometheus scaler) — an extra dependency vs. CPU-only autoscaling; recorded as the
  price of catching I/O-bound load CPU misses.
- KEDA is an operational dependency (operator + CRDs); the celery-exporter-HPA fallback
  (§5) is weaker (no scale-to-zero, coarser loop) — the trade is stated so the choice is
  explicit.
- Polling-interval / cooldown lag means a burst drains over seconds-to-minutes, not
  instantly (§2); the values are pinned here so the W4-T6 drain SLO is realistic, but a
  mistuned `pollingInterval` can make the burst drain slowly — the drill is the guard.
- The api-HPA correctness **depends on** ADR-0044 WS fan-out; if that slips, raising
  api replicas silently breaks WebSocket sessions. The two ADRs are cross-referenced and
  W2 sequencing keeps W2-T2 before/with the api scale-out — the stated mitigation.
- Per-queue Deployments + ScaledObjects (six work queues incl. the packet split) are
  more manifests to maintain than one shared worker — accepted as the cost of isolation
  (§3) and the ADR-0031 packet split.
- Certified-scale numbers are **not** proven here (named deferred-accepted → GA, §0);
  the kind drill proves the *mechanism* at reduced scale only — stated, not silent.

## Alternatives considered

1. **CPU-only HPA on the api tier.** Rejected (§1): a request flood that blocks on
   Postgres/Neo4j/LLM I/O drives p95 past the §327 budget while CPU stays low, so a
   CPU-only HPA would not scale out. The dual CPU + request-rate signal catches both
   compute- and I/O-bound load.
2. **CPU-based HPA on the workers (instead of KEDA queue-length).** Rejected: a worker
   blocked on a slow SSH/SNMP collection has deep backlog but low CPU, so CPU-based
   scaling under-provisions exactly when the queue is deepest. Queue list length is the
   demand signal that reflects backlog directly (PRODUCTION.md §3.2 "KEDA ScaledObjects
   on Redis queue length").
3. **A single shared autoscaler over one combined worker pool.** Rejected (§3): it lets
   a `discovery` flood consume the whole pool and starve `config`/`packet`/`docs` — the
   exact failure G-SCA §329 forbids. Per-queue ScaledObjects + per-queue Deployments make
   isolation structural.
4. **KEDA-only with no fallback.** Rejected: a customer cluster that cannot install the
   KEDA operator would have no autoscaling path. The celery-exporter-HPA fallback (§5)
   keeps the design deployable; KEDA stays primary for scale-to-zero + the configurable
   loop.
5. **Autoscale packet workers on the general node pool like the other queues.** Rejected
   (§4, ADR-0031 §5): bursting a `NET_RAW`-capable capture Pod or an untrusted-pcap
   parser onto general nodes re-admits the very co-scheduling adjacency the tainted pool
   exists to prevent. Packet scaling stays bounded to the sandboxed pool.
6. **`minReplicas: 1` on the api HPA (let the autoscaler decide the floor).** Rejected:
   §3.2 requires "≥2 replicas always"; a floor of 1 cannot survive a single node loss and
   defeats the PDB. The floor is fixed at 2; the HPA scales above it.
7. **Vertical Pod Autoscaling instead of horizontal for the api/workers.** Rejected for
   P3: VPA resizes a Pod (and restarts it) but cannot add request-serving / queue-draining
   parallelism, which is what the §327/§329 criteria require; HPA/KEDA horizontal
   scale-out is the design. VPA could complement right-sizing later — not in scope here.
8. **Procure a certified-scale cluster and prove the §11 G-SCA numbers directly.**
   Considered and declined for P3 (§0): same no-hardware posture as M4/M5/P1/P2. The
   mechanism is proven at reduced scale on kind (W4-T6); the certified-scale numbers are
   named deferred-accepted → GA / customer cluster, with the promotion path in ADR-0047
   and the W5 readiness doc.
