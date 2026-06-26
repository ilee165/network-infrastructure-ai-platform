# W3-T2 — Security Agent Supervisor Routing + Read-Only RBAC + Tool Allow-List

| | |
|---|---|
| **Wave** | P2 W3 — Security Agent |
| **Owner** | `wf-implementer` (strong — extends the ADR-0033 injection boundary to a new agent) |
| **Review tier** | **strong** spec + **strong** quality (routing + injection-boundary surface) |
| **Depends on** | **W3-T1** (the agent it registers); ADR-0037 (W0-T4) |
| **ADRs** | ADR-0003 (supervisor routing / registry), ADR-0011 (RBAC `min_role`), ADR-0033 (per-agent tool allow-list / injection boundary), ADR-0037 (Troubleshooting-vs-Security split) |
| **PRODUCTION.md** | §2.3, §11 G-SEC |
| **Status** | Done — implemented on `feat/p2-w3-security-agent` (commit `cc4d59c`). Routing-quality re-run over the new roster is W5-T2. |

## Objective

Wire the W3-T1 Security Agent into the platform: **register it with the
`AgentRegistry`** so the supervisor routes to it, scope its tools **read-only via
RBAC `min_role`**, and **extend the ADR-0033 per-agent tool allow-list /
injection boundary** to the new agent. Resolves the ADR-0037 Troubleshooting-vs-
Security firewall-analysis routing split. (The routing-eval re-run is **W5-T2**.)

## Scope

**In** (the agent-registration seam — wherever specialists register at import
time; `app/agents/security/`; the ADR-0033 allow-list config; tests)
- **Registry registration** (ADR-0003): the Security Agent joins the process-wide
  `AgentRegistry`, so it appears in the supervisor roster and
  `build_supervisor_graph` adds its subgraph node. Tune `description` so the
  structured `RoutingDecision` routes security intents here (the roster line is the
  router's only signal).
- **Troubleshooting-vs-Security split** (ADR-0037): implement the routing boundary
  the ADR decided — which firewall-analysis intents go to `security` vs
  `troubleshooting` (CLAUDE.md lists firewall analysis under both). Keep
  descriptions disjoint so the router does not oscillate.
- **Read-only RBAC** (ADR-0011): READ_ONLY analysis tools carry an appropriate
  `min_role` (e.g. `viewer`/`operator` for read); the remediation tool (CR draft)
  carries the change-proposal `min_role` (`engineer`, like DDI mutators). "An agent
  can never do what its user cannot" — the `agent_run_context` role binding applies.
- **Per-agent tool allow-list / injection boundary** (ADR-0033): the Security Agent
  is added to the allow-list mechanism so a routed/injected request cannot reach a
  tool outside its set — the ADR-0033 boundary **explicitly extends** to the new
  agent (an injected "now run a config restore" is unreachable).

**Out**
- Agent core / analyses / findings / remediation tool → **W3-T1**.
- Routing-eval re-run (no regression vs prior matrix) → **W5-T2**.
- Any new analysis capability → out (W3-T1 froze the tool set).

## Requirements (grounded in ADR-0003/0011/0033/0037)

1. **Routed via the supervisor only** (ADR-0003): no entrypoint invokes the agent
   bypassing routing/trace; registration is at the same seam as the other agents.
2. **Disjoint routing** (ADR-0037): the Troubleshooting/Security split is concrete
   in the descriptions; a security-policy intent routes to `security`, a
   routing/BGP/OSPF fault to `troubleshooting` — no overlap that regresses W5-T2.
3. **RBAC enforced** (ADR-0011): `min_role` per tool; the run-context role binding
   gates reachability; read tools ≤ change tool in privilege.
4. **Injection boundary extends** (ADR-0033): the per-agent allow-list includes the
   Security Agent; a tool not on its list is unreachable regardless of prompt —
   asserted by a test (an injected device-write attempt fails closed).
5. **No new behavior** beyond wiring — this task registers + scopes; it does not add
   analyses.

## Contracts / artifacts

- Security Agent registered in the specialist-registration seam (roster + subgraph).
- `description` tuned for routing; Troubleshooting/Security split implemented.
- `min_role` on each Security tool; ADR-0033 allow-list entry for the agent.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff / mypy strict / import-linter / pytest **≥80%** on touched modules.
- **Routing test** (deterministic, scripted fake chat model like the supervisor
  tests): a security-policy intent routes to `security`; a device-fault intent
  routes to `troubleshooting`; the agent is present in the roster.
- **RBAC test**: a viewer reaches read tools but not the change-proposal tool; the
  role binding gates correctly.
- **Injection-boundary test** (ADR-0033): an injected request to a tool outside the
  Security Agent's allow-list (e.g. a config-write) is unreachable / fails closed.
- Full supervisor graph builds with the new agent; existing routing stays green
  (the regression matrix is re-run in W5-T2).

## Exit criteria

- [x] Security Agent registered in `build_default_registry`; appears in the
      supervisor roster + subgraph (ninth routable specialist).
- [x] Troubleshooting-vs-Security split implemented (routing prompt v6 + disjoint
      descriptions); routing test green both ways.
- [x] Read-only RBAC `min_role` per tool (read tools = viewer, remediation =
      engineer); RBAC test green (viewer reaches reads, not the drafter).
- [x] ADR-0033 allow-list extended to the agent; injection-boundary test fails
      closed (out-of-allow-list tools unreachable; only write surface is the
      gate-routed remediation draft).
- [x] Supervisor builds; no existing-routing regression (composition / eight-way /
      P1 injection guardrail updated for the ninth specialist; full quality re-run
      is W5-T2). Full unit suite 2803 passed / 18 skipped.
- [x] D16 gates green; one atomic commit (`cc4d59c`).

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **Routing oscillation** between `security` and `troubleshooting` (both own
  firewall analysis in CLAUDE.md): if descriptions overlap, the router flips and
  W5-T2 regresses. The ADR-0037 split must be concrete and the descriptions disjoint.
- **Injection boundary not actually applied to the new agent** (ADR-0033 false
  extension): the fail-closed test is the guard — an injected out-of-allow-list
  tool call must be unreachable, not merely discouraged by the prompt.
