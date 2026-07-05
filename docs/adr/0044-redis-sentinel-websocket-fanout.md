# ADR-0044: Redis Sentinel + Stateless WebSocket Agent-Session Fan-Out via Redis Pub/Sub

**Status:** Accepted | **Date:** 2026-06-29 (Accepted 2026-07-05, W5-T3) | **Milestone:** P3 W0 (Accepted P3 W5)

## Context

`PRODUCTION.md` §3 schedules HA/scale-out for **P3-Platform**, and §3.2 fixes two
coupled shapes for the Redis tier and the `api` tier that this ADR ratifies:

- the **`redis`** row: *"Redis Sentinel (3 nodes) for broker/result/cache; AOF
  persistence. Broker loss is tolerable: tasks are idempotent and re-enqueueable;
  scheduled jobs (backups, retention) re-fire on next beat"*; and
- the **`api`** row: *"≥2 replicas always … Stateless by design (JWT auth per D10,
  no server-side sessions). WebSocket agent-session streaming fanned out via Redis
  pub/sub so any replica can serve any session — PROPOSED (required consequence of
  replica >1; brief D8 already places Redis in the stack)."*

Today Redis is a single instance (ADR-0008) and the agent-session trace stream is
served with **in-process session affinity**: `backend/app/api/v1/agents.py`
`stream_session` (the `/{session_id}/stream` WebSocket) authenticates the peer
(short-lived single-use **stream ticket** issued by `create_stream_ticket` and
redeemed by an **in-process** `_consume_ticket`, or the same JWT as a `token` query
param) and then **polls Postgres** for the session's recorded reasoning traces. Two
things break once `api` runs at ≥2 replicas (ADR-0043): (1) the in-process ticket
store lives on one replica, so a ticket issued on replica A cannot be redeemed on
replica B; and (2) even though today's stream reads from the DB, the §3.2 design is
to **fan out live session content via Redis pub/sub** so any replica can serve any
session without affinity. This ADR is the **design gate** for both the Redis HA tier
and that fan-out; it does **not** implement them.

This ADR is the **design gate**. It ratifies the design the build implements in
**W1-T4** (Redis Sentinel ×3 + AOF — render/policy gates) and **W2-T2** (stateless
WebSocket fan-out via Redis pub/sub). It does **not** implement those controls — it
fixes the Sentinel topology + persistence, the pub/sub channel model, the streaming
delivery semantics, the **token-never-on-a-shared-channel** boundary, and how the
session auth + OTel trace context survive the fan-out. Because W2-T2 carries the
WebSocket **session-auth / session tokens** across replicas, the fan-out is a
**secret-surface decision** (the W2-T2 *implementation* is escalated to strong
review).

Bounded by / builds on **ADR-0008** (Celery + Redis broker/result/cache; Redis is
*expendable* infrastructure — durable state lives in Postgres), **ADR-0010** (JWT
stateless auth — already stateless, the half this ADR completes for WebSockets),
**ADR-0003** (LangGraph agent sessions — the run whose steps are streamed), and
**ADR-0015** (observability/trace — the trace/audit-join id that must ride the
fan-out). Cross-referenced with **ADR-0043** (api HPA + KEDA — which names *this* ADR
as the statelessness precondition its HPA correctness depends on) and **ADR-0042**
(Postgres HA — the durable system of record this fan-out does **not** replace).
PRODUCTION.md §3.1/§3.2 and §11 **G-OBS** (agent runs traced end-to-end and joinable
to audit entries) are the line-by-line source.

Per `P3-PLATFORM-PLAN.md` §0, the live cross-replica assertion is proven at
**reduced scale** on the ephemeral HA kind cluster (W4-T1) by the W2-T2 contract test
(session opened on replica A, served by replica B); the **certified-scale** numbers
(100 concurrent users, 5,000-device projection) are **named deferred-accepted → GA /
customer cluster**, never silently claimed.

## Decision

**Redis runs as a Sentinel-monitored single shard — 1 primary + 2 replicas watched
by 3 Sentinels with AOF persistence — fronting the existing broker / result / cache
roles; Sentinel handles primary election so the broker tier stops being a single
point of failure, and broker loss stays tolerable because tasks are idempotent +
re-enqueueable (ADR-0008). The WebSocket agent-session stream is made stateless by
fanning out session content over a Redis pub/sub channel keyed by an opaque session
id, so any `api` replica can serve any session: each `api` replica subscribes to the
channel for the sessions it is currently serving and relays frames to its connected
WebSocket peers, while the producer (the LangGraph run, wherever it executes)
publishes ordered session frames to that channel. The bearer token is verified
per-connection at the serving replica and is NEVER published onto a shared channel —
the channel carries only session content keyed by an opaque session id. The OTel
trace / audit-join id rides each published frame as metadata so the agent run stays
traced end-to-end (G-OBS). Chat-token streaming is best-effort live delivery with
Postgres as the durable replay source of record; Redis Cluster sharding is out of
scope (single-shard Sentinel only).**

### 1. Redis HA — Sentinel ×3 + AOF (the §3.2 `redis` row)

Redis runs as **one shard**: a primary + 2 replicas monitored by **3 Sentinel
processes** (an odd quorum so a single Sentinel loss cannot deadlock the vote), with
**AOF persistence** (`appendonly yes`) so a full-shard restart recovers the last
durable state rather than starting empty. Sentinel performs primary monitoring,
quorum-based failure detection, and automatic primary election/promotion; clients
discover the current primary **via Sentinel** (a Sentinel-aware client), so an `api`
or `worker` Pod re-points to the promoted primary without a config change.

Redis keeps its ADR-0008 roles unchanged — **Celery broker + result backend, cache,
rate-limit store** — and gains the **pub/sub fan-out channel** (§2). It remains
**expendable** in the ADR-0008 sense: durable job/session state lives in Postgres
(`agent_sessions`, `reasoning_traces`, `audit_log`), so a Redis failure loses at most
in-flight queue entries and in-flight pub/sub frames, never committed data.

**Broker-loss tolerance is the explicit posture (§3.2):** a broker loss is tolerable
because Celery tasks are **idempotent + re-enqueueable** (ADR-0008 §5: `acks_late`,
`reject_on_worker_lost`, upsert-style writes) and **scheduled jobs (backups,
retention) re-fire on the next Celery-beat tick** — so Sentinel HA reduces the
*window* of broker unavailability rather than guarding against data loss, which the
idempotency + Postgres-as-record design already covers.

**Single-shard Sentinel, not Redis Cluster.** The platform's Redis working set
(queues, cache, rate-limit counters, transient pub/sub) fits a single primary;
Sentinel HA + AOF meets the §3.2 requirement. **Redis Cluster (hash-slot sharding)
is out of scope** — it adds multi-key/cross-slot constraints and operational surface
for capacity the platform does not need; horizontal Redis sharding is a future
superseding-ADR decision if a working set ever exceeds one node (G-MNT, no silent
drift).

### 2. Stateless WebSocket fan-out — channel-per-session over Redis pub/sub

The §3.2 `api` row requires *"WebSocket agent-session streaming fanned out via Redis
pub/sub so any replica can serve any session."* The mechanism:

- **One pub/sub channel per session, keyed by an opaque session id.** The channel
  name is derived from the existing `agent_sessions` UUID (e.g.
  `netops:agent-session:{session_id}`) — an **opaque** identifier that is already a
  capability-checked handle on the REST surface, **never** a secret. The producer
  (the LangGraph run for that session — ADR-0003, running in the `api` process or a
  worker) **publishes** ordered session frames (reasoning-step / token / terminal
  frames) to that channel; every `api` replica currently serving a WebSocket for
  that session **subscribes** to the channel and relays each frame to its connected
  peer(s). No replica holds session affinity: a session opened on replica A and a
  session opened on replica B both flow through the same Redis channel.
- **Subscribe scoped to served sessions, not a firehose.** A replica subscribes only
  to the channels for the sessions it is actively serving (subscribe on WS accept,
  unsubscribe on disconnect), so a replica never receives content for sessions it is
  not serving — this both bounds fan-out cost and keeps a replica from observing
  unrelated session content.
- **This replaces the in-process affinity that breaks at replica >1.** The
  `create_stream_ticket` / `_consume_ticket` flow (`agents.py`) currently keeps the
  single-use ticket in process; W2-T2 moves that redemption to a **shared store
  (Redis)** so a ticket issued on replica A is redeemable on replica B, and moves the
  stream itself from per-replica DB polling to the shared pub/sub channel. Postgres
  remains the durable record (§4); pub/sub is the live transport.

### 3. Token-never-on-a-shared-channel — the secret-surface boundary (W2-T2)

This is the central security trap the spec calls out, made explicit so W2-T2 builds
it right:

- **Auth happens at the edge, per connection.** The WebSocket peer authenticates at
  the **serving replica** — the JWT subject (ADR-0010) is verified per-connection
  (via the single-use, TTL-bound stream ticket redeemed against the shared store, or
  the equivalent JWT check), exactly as the REST surface does, **before** any frame
  is relayed. Authorization to read a session is enforced at the edge, not on the
  bus.
- **The pub/sub channel carries session *content* keyed by an opaque session id —
  never the bearer token.** The JWT (or any credential) is **never published** onto
  the channel. A frame on the bus contains only the reasoning-step / token / terminal
  content plus the opaque session id and trace metadata (§4); anyone who could read
  the channel still cannot impersonate the user, because the token is not there. The
  session id is **opaque and capability-checked at the edge**, not a bearer secret,
  so its presence on the channel is not a credential leak.
- **Why this matters for the shared bus.** Redis pub/sub has no per-channel ACL in the
  single-shard design, and AOF could otherwise persist anything published; keeping
  the token off the channel means neither a co-tenant subscriber nor the AOF file
  ever sees a credential. This is the boundary the W2-T2 secret-surface review and
  contract test must hold: **session opened on replica A, served by replica B; the
  token never appears on any channel (nor in AOF, logs, or frame payloads).**

### 4. Trace continuity — the OTel / audit-join id rides the fan-out (G-OBS)

§11 **G-OBS** requires *"100% of agent runs traced end-to-end (session → LLM calls →
tool calls) and joinable to audit entries."* Fanning the stream across replicas must
not break that join:

- Each published frame carries the **OTel trace context / audit-join id** for the run
  (the same correlation id ADR-0015 already threads through a run and ADR-0011/0038
  join to `audit_log`) as frame **metadata**, so the relaying replica continues the
  span on the serving side and the streamed frames stay correlated to the producing
  run's trace and to its audit entries — even though producer and consumer are
  different processes/replicas.
- The audit-join id is a **correlation identifier, not a secret** (it is the same id
  already present in traces and audit rows), so carrying it on the channel does not
  violate §3; it is what keeps the run traceable across the fan-out.

### 5. Delivery semantics — best-effort live stream; Postgres is the durable replay

The risk the spec names is *"lost chat tokens on replica handoff"*; the semantics are
chosen and stated rather than left implicit:

- **Live chat-token / step streaming over pub/sub is best-effort (at-most-once on the
  wire).** Redis pub/sub does not persist or redeliver: a frame published while no
  subscriber is attached (a momentary handoff, a replica restart, a brief Sentinel
  failover) is simply not delivered live. This is the correct trade for an
  interactive token stream — the alternative (a per-session durable stream with
  acknowledgement) is heavier than the UX requires.
- **Durability lives in Postgres, the system of record.** The authoritative session
  outcome — the recorded `reasoning_traces` and the final answer — is persisted to
  Postgres exactly as today (ADR-0003/0004), audited (ADR-0011), and is the **durable
  replay source**: a client that reconnects (new WebSocket, possibly a different
  replica) **re-reads the persisted trace from the DB** to recover any frames missed
  on the live wire, then resumes the live pub/sub stream. So a dropped live frame is a
  cosmetic, recoverable gap, never lost session state. This composes with the existing
  ticket-authenticated, DB-backed `stream_session` read path — pub/sub adds liveness,
  the DB guarantees completeness.
- **Broker (Redis) loss does not lose session state**, for the same reason as §1: the
  durable trace is in Postgres; a Redis/Sentinel failover drops only in-flight live
  frames, which the reconnect-and-replay path backfills.

### 6. Build-task contract — the assertions this ADR pins

So the build tasks have a testable contract (the ADR is the design; the gates are the
proof):

- **W1-T4** (`wf-infra`, render/policy): Redis Sentinel ×3 + AOF renders and passes
  infra policy gates (`helm lint`, `helm template | kubeconform -strict`, kube-linter,
  conftest); **render-twice stable** with reuse-or-generate secrets (no regen, P1-W4
  **L4**); a Sentinel-aware client config is wired so `api`/`worker` discover the
  primary via Sentinel; AOF (`appendonly yes`) present.
- **W2-T2** (`wf-implementer`, **escalated — session tokens / secret surface**): a
  session opened on replica **A** is served from replica **B** via the Redis pub/sub
  channel (any-replica-serves-any-session, §2); the bearer **token is never published
  on any channel** (asserted: not in frame payloads, not in AOF, not in logs — §3);
  the **trace/audit-join id rides the fan-out** so the run stays end-to-end traced and
  audit-joinable (§4); the single-use stream ticket is redeemable across replicas via
  the shared store (§2); a reconnect replays missed frames from Postgres (§5). A
  **negative control** — publishing the token onto the channel, or asserting affinity
  by serving only from the originating replica — must make the W2-T2 assertion go red
  (P1-W4: a gate must RUN and BITE).

### 7. Scope boundary

**In:** the Redis Sentinel ×3 + AOF topology and broker-loss-tolerance posture; the
channel-per-session pub/sub fan-out model (opaque-session-id keying,
subscribe-scoped-to-served-sessions, producer-publishes/replica-relays); the
token-never-on-a-shared-channel boundary (auth at the edge); trace/audit-join-id
continuity across the fan-out; and the best-effort-live + Postgres-durable-replay
delivery semantics. **Out:** the implementation (W1-T4 Sentinel, W2-T2 fan-out);
**Redis Cluster (hash-slot) sharding** (single-shard Sentinel only, §1); the live
Redis-failover drill (covered indirectly by W4); Postgres/Neo4j HA (ADR-0042 /
ADR-0044 are tier-disjoint — Postgres is ADR-0042, Neo4j rebuild is W1-T3); and the
api HPA itself (ADR-0043 — which depends on this statelessness). Infra policy gates
stay green on the new Sentinel manifests (named for W1-T4).

## Consequences

**Positive**
- Redis stops being a single point of failure: Sentinel ×3 + AOF gives automatic
  primary promotion and last-durable-state recovery, the §3.2 `redis` HA requirement.
- The `api` tier becomes genuinely stateless for WebSocket streaming — any replica
  serves any session via the shared pub/sub channel — which is the precondition
  ADR-0043's api-HPA correctness depends on (cross-referenced both ways).
- The token never touches the shared bus (auth at the edge, opaque session id on the
  channel), so neither a co-tenant subscriber nor the AOF file ever sees a credential
  — the W2-T2 secret-surface boundary.
- The run stays end-to-end traced and audit-joinable across replicas because the
  trace/audit-join id rides each frame (G-OBS).
- No new stateful infrastructure: pub/sub reuses the Redis already in the ADR-0008
  stack; Postgres remains the durable record, so a dropped live frame is recoverable
  by reconnect-and-replay, not lost state.

**Negative**
- Best-effort live delivery means a frame published during a handoff / brief Sentinel
  failover is not delivered live — mitigated by the Postgres-backed reconnect-and-
  replay (§5); accepted as the right trade for an interactive token stream vs. a
  heavier per-session durable acknowledged stream.
- Sentinel adds operational surface (3 Sentinels + a Sentinel-aware client) and the
  app must discover the primary via Sentinel rather than a fixed host — recorded as
  the price of broker HA.
- Single-shard Sentinel does not scale Redis horizontally; a working set that
  outgrows one node would need a superseding ADR (Redis Cluster) — stated, not silent.
- The fan-out is only correct if the **token is kept off the channel** and **auth is
  enforced at the edge**; a W2-T2 regression that publishes the token or assumes
  affinity silently breaks the security/statelessness guarantee — the W2-T2 negative
  control is the guard.

## Alternatives considered

1. **Sticky sessions / in-process affinity (load-balancer pins a session to its
   replica).** Rejected: it re-introduces the very affinity §3.2 removes — a pinned
   replica's loss drops the session, the HPA cannot freely rebalance, and the
   in-process ticket store (`_consume_ticket`) stays unshared. Stateless fan-out via
   Redis is the §3.2 design.
2. **Token on the pub/sub channel (publish the JWT with the frame so any replica can
   re-auth).** Rejected (§3): it puts a bearer credential on a shared, AOF-persisted
   bus with no per-channel ACL — a co-tenant subscriber or the AOF file would see the
   token. Auth at the edge + opaque session id keeps the secret off the bus.
3. **A durable per-session stream with acknowledged at-least-once delivery (e.g. Redis
   Streams / a message queue per session).** Rejected for P3: heavier than an
   interactive token stream needs, and redundant with Postgres as the durable replay
   source (§5). Best-effort live + DB replay meets the UX with no extra durable tier;
   a future requirement for guaranteed live replay could revisit this (superseding
   ADR).
4. **Redis Cluster (hash-slot sharding) instead of single-shard Sentinel.** Rejected
   (§1): adds cross-slot/multi-key constraints and operational surface for horizontal
   capacity the platform's working set does not need; Sentinel + AOF meets the §3.2 HA
   requirement. Sharding is a future superseding-ADR option if the working set grows.
5. **A dedicated message broker (NATS / RabbitMQ / Kafka) for the fan-out.** Rejected:
   it adds a new stateful component outside the ADR-0008 seven-container model for a
   transport Redis pub/sub already provides; "no new stateful infrastructure" is an
   ADR-0008 / self-hosted-economics constraint. Redis is already on the critical path
   (PRODUCTION.md §3.1) for exactly this fan-out.
6. **Keep the current DB-polling stream and just scale the api tier.** Rejected: the
   in-process single-use ticket store breaks at replica >1 (issued on A, redeemed on
   B fails), and DB-polling every replica for live frames does not deliver the live
   token stream §3.2 specifies. Pub/sub for liveness + DB for completeness is the
   design.
