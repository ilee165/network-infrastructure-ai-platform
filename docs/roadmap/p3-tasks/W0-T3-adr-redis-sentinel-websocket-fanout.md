# W0-T3 — ADR-0044 Redis Sentinel + stateless WebSocket fan-out via Redis pub/sub

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet (note: the *implementation* W2-T2 is secret-surface — session tokens) |
| **Depends on** | — |
| **Builds on** | ADR-0008 (Redis broker/result/cache), ADR-0010 (JWT stateless auth), ADR-0003 (LangGraph agent sessions), ADR-0015 (observability/trace) |
| **PRODUCTION.md** | §3.2 |
| **Status** | Proposed |

## Objective

Ratify two coupled decisions: **Redis Sentinel (3 nodes) + AOF** for
broker/result/cache HA, and **stateless WebSocket agent-session fan-out via Redis
pub/sub** so any `api` replica can serve any agent-session stream (the required
consequence of api replica > 1, PRODUCTION.md §3.2). Fix the pub/sub channel model,
delivery semantics, and how session auth/trace context survives the fan-out.

## Scope

**In** — Sentinel topology + AOF; the pub/sub channel-per-session model;
at-least-once vs. best-effort streaming semantics for chat tokens; how the JWT
subject + OTel trace context ride the fan-out without leaking the token onto a
shared channel; broker-loss tolerance (idempotent re-enqueueable tasks).

**Out** — implementation (W1-T4 Sentinel, W2-T2 fan-out); Redis Cluster sharding
(single-shard Sentinel only); the failover drill (covered indirectly by W4).

## Requirements (grounded in PRODUCTION.md §3.2)

1. **Any-replica-serves-any-session:** session state externalized to Redis pub/sub;
   no in-process session affinity. The §3.2 stateless-api precondition.
2. **No token on a shared channel:** the WebSocket auth (JWT subject) is verified
   per-connection at the serving replica; pub/sub carries session *content* keyed by
   an opaque session id, **never the bearer token** — the secret-surface boundary
   W2-T2 must honour.
3. **Trace continuity:** the OTel trace/audit-join id rides the fan-out so the
   agent run stays traced end-to-end (G-OBS §320).
4. **Sentinel HA:** 3 sentinels + AOF; broker loss tolerable because tasks are
   idempotent + re-enqueueable; scheduled jobs re-fire on next beat.

## Contracts / artifacts

- `docs/adr/0044-redis-sentinel-websocket-pubsub-fanout.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR names the W2-T2 assertion (session opened on replica
  A served by replica B; token never published) and the W1-T4 Sentinel render/policy gates.

## Exit criteria

- [ ] ADR-0044 written: Sentinel+AOF; pub/sub channel model; delivery semantics; **token-never-on-channel** boundary; trace continuity.
- [ ] Cross-referenced from ADR-0043 (stateless-api precondition); ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Token leakage onto a shared pub/sub channel** — the central security trap; the
  ADR must make "opaque session id, auth at the edge" explicit so W2-T2 builds it right.
- **Lost chat tokens on replica handoff** — pick and state the delivery semantics
  rather than leaving it implicit.
