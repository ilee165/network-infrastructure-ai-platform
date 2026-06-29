# W2-T2 — Stateless WebSocket agent-session fan-out via Redis pub/sub

| | |
|---|---|
| **Wave** | P3 W2 — Compute scale-out |
| **Owner** | `wf-implementer` (escalated — session tokens) |
| **Review tier** | **strong** spec + quality (auth / session tokens over pub/sub) |
| **Depends on** | W0-T3 (ADR-0044), **W1-T4** (Sentinel) |
| **ADRs** | ADR-0044 (the contract), ADR-0003 (LangGraph agent sessions), ADR-0010 (JWT auth), ADR-0015 (trace) |
| **PRODUCTION.md** | §3.2 |
| **Status** | Proposed |

## Objective

Implement ADR-0044's fan-out half: make agent-session **WebSocket streaming
stateless** so **any `api` replica can serve any session**, by routing session
content through **Redis pub/sub** keyed by an opaque session id — the required
consequence of api replica > 1 (PRODUCTION.md §3.2). The bearer token is **never**
published to a shared channel; auth is verified per-connection at the serving edge.

## Scope

**In** — a pub/sub channel-per-session; publish agent-stream tokens/events to the
channel; each replica's WebSocket handler subscribes for the sessions it serves;
per-connection JWT verification at the edge (ADR-0010); the OTel trace/audit-join id
carried with the content (ADR-0015) so the run stays traced; the delivery semantics
ADR-0044 fixed.

**Out** — Sentinel infra (W1-T4); the api HPA (W2-T1); the cross-replica drill
assertion at scale (W4-T6 touches load, this task ships the unit/integration proof).

## Requirements (grounded in ADR-0044, ADR-0010, PRODUCTION.md §3.2)

1. **Any-replica-serves-any-session** — no in-process affinity; a session opened on
   replica A is fully served by replica B (asserted with a two-subscriber test).
2. **Token never on a shared channel** — the channel carries content keyed by an
   **opaque session id**; the JWT is verified at the connection edge and never
   published. A test asserts the token/secret is **absent** from any published
   payload (the secret-surface bite).
3. **Trace continuity** — the trace/audit-join id rides the fan-out; the agent run
   stays traced end-to-end (G-OBS §320) — no new untraced path.
4. **Delivery semantics** per ADR-0044 (don't silently drop or unboundedly buffer
   chat tokens).

## Contracts / artifacts

- WebSocket handler + Redis pub/sub publisher/subscriber; per-connection auth;
  trace-context propagation; tests (two-subscriber cross-replica sim +
  token-absent-from-channel).

## Test & gate plan

- Unit/integration: session content published on channel for session X is received
  by a second subscriber (cross-replica sim); **token/secret absent** from every
  published payload; trace id propagates.
- Backend D16 gates green; `include_router` introspection green; mypy/ruff clean.
- Live cross-replica behaviour under load is W4-T6.

## Exit criteria

- [ ] WebSocket session state externalized to Redis pub/sub; cross-replica delivery proven (two-subscriber test).
- [ ] **Token/secret never published** — leak test bites; auth verified at the edge.
- [ ] Trace/audit-join id propagates; delivery semantics per ADR-0044; backend D16 + `include_router` green; one atomic commit.

## Workflow

`wf-implementer` (escalated) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Token published to a shared pub/sub channel** — the central security trap; the
  leak test is the guard and must bite.
- **In-process session state left behind** → replica affinity silently required, api
  not actually stateless, HPA scaling breaks sessions.
- **Lost trace continuity** → agent run no longer joinable to audit (G-OBS regression).
