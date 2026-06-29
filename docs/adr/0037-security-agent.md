# ADR-0037: Security Agent (Read-Only Analysis, Findings, Remediation→ChangeRequest)

**Status:** Accepted | **Date:** 2026-06-25 (Accepted 2026-06-29) | **Milestone:** P2 W0 (Accepted P2 W5)

## Context

The Security Agent is **core agent #9** (CLAUDE.md) and ships in P2
(`PRODUCTION.md` §2.3): "firewall policy analysis (shadowed/redundant/
overly-permissive rules), security posture checks across configs and ACLs, findings
feed compliance reports. It is read-only; remediations it proposes become
ChangeRequests." This ADR is the design gate; the build is **W3-T1** (agent core) +
**W3-T2** (routing / RBAC / allow-list), `P2-SECURITY-PLAN.md` §3.

The decision is bounded by the existing agent and security architecture:

- **LangGraph supervisor routing** (ADR-0003): every specialist is a subgraph the
  supervisor routes to; no direct invocation bypasses routing/audit.
- **RBAC + read-only scoping + append-only audit** (ADR-0011).
- **ChangeRequest four-eyes spine** (ADR-0020): a `STATE_CHANGING` tool call is
  intercepted by the `ChangeRequestGate` *before the tool body runs* and becomes a
  blocked draft `ChangeRequest`; it does not execute.
- **Per-agent typed tool allow-lists + prompt-injection boundary** (ADR-0033): a tool
  an agent never registered cannot be named into existence by any prompt.
- **`FIREWALL_POLICY` normalized models** (ADR-0034): the analysis input.

CLAUDE.md lists firewall analysis under both "Troubleshooting" and the Security
Agent. Left unresolved, W3-T2 routing is ambiguous and the W5-T2 routing eval
regresses. This ADR fixes the split.

The DDI Agent is the structural precedent: a `BaseSpecialistAgent` with READ_ONLY
tools plus gate-routed mutators that create CR drafts (never execute). The Security
Agent follows that shape exactly, minus any device-executing tool.

## Decision

**The Security Agent is a `BaseSpecialistAgent` whose tool registry contains ZERO
device-executing tools. Its analysis is deterministic and rule-based in a service
(the agent narrates; the service decides). Findings are evidence-cited, secret-free
normalized records. The only mutation surface is a four-eyes `ChangeRequest` draft
(ADR-0020). Read-only is a structural (registry/allow-list) property, not a prompt
instruction.**

### 1. Read-only mandate — structural, not prompted

The agent registers **no tool that writes to a device**. The single write path is a
remediation tool classified `STATE_CHANGING`, which the framework
`ChangeRequestGate` intercepts → a blocked CR draft (ADR-0020) for four-eyes
approval — exactly as the DDI mutators create `ddi_record` drafts. A registry-level
test (W3-T1) asserts no device-executing tool is present; this property holds even
against a fully prompt-injected model (ADR-0033 discipline).

> **Wording correction to `P2-SECURITY-PLAN.md` §5 / §2.3.** The plan says "no
> STATE_CHANGING tool registered." The framework-accurate invariant — matching the
> DDI precedent — is **no device-executing tool; the CR draft is the only write
> path**, and a remediation IS a `STATE_CHANGING` gate-routed tool that only ever
> produces a draft. W3-T1 implements the gate pattern; the read-only-invariant test
> is the guard. (Flagged for a §5 wording fix.)

### 2. Analysis tools (the agent's allow-list) — deterministic

READ_ONLY analyses over already-collected normalized data — `FIREWALL_POLICY`
(ADR-0034) plus existing `ACL` / `CONFIG_BACKUP`:

- **Shadowed rules** — an earlier rule fully covers a later rule's match set, so the
  later rule is unreachable.
- **Redundant rules** — same action, subsumed match set (often zero `hit_count`).
- **Overly-permissive rules** — `any` source/destination/service on an `allow`,
  unbounded exposure.
- **Posture checks** — cross-config / ACL checks (e.g. permissive management-plane
  access, missing logging on allow rules).

Following the Configuration-agent "narrate" pattern: the **service computes the
analysis deterministically**; the agent narrates the result. Rule logic is **not**
free-LLM-judgment, so findings are reproducible for the W5-T1 precision/recall
corpus (`PRODUCTION.md` §11).

### 3. Findings model — evidence-cited, secret-free

A normalized finding (frozen Pydantic, `extra="forbid"`, schema home in
`app/schemas/`): `severity`, `category` (shadowed / redundant / overly_permissive /
posture), an **offending-rule reference** + the normalized rule as **evidence**,
`rationale`, and a `suggested_remediation`. It carries **no secret material** (A9
redaction holds at the boundary — any config fragment surfaced to the model is
redacted first, like DDI). Evidence-citing satisfies CLAUDE.md "Explain all AI
decisions": a human audits the offending rule behind every finding.

### 4. Remediation → ChangeRequest (ADR-0020)

A remediation is a `STATE_CHANGING` tool the `ChangeRequestGate` intercepts → a
`ChangeRequest` draft (a new CR **kind**, e.g. `security_remediation`) authored from
verbatim args — never a device write, four-eyes approval required. The model cannot
bypass the gate (framework guarantee, like DDI).

### 5. Supervisor routing + the Troubleshooting split (ADR-0003)

The supervisor routes **security-posture and firewall-audit intents** ("is this rule
shadowed?", "find overly-permissive rules", "audit this firewall") to the **Security
Agent**. **Live, single-flow firewall reachability troubleshooting** ("why is this
flow blocked right now?") stays with the **Troubleshooting Agent**, which gains
read-only firewall tools backed by `FIREWALL_POLICY` (`PRODUCTION.md` §2.3). The
split: **Security = posture/audit over policy as data; Troubleshooting = live path
reachability**. The two may share the READ_ONLY `FIREWALL_POLICY` read tools; only
the Security Agent owns the analysis + remediation-draft tools.

### 6. Per-agent tool allow-list + injection boundary (ADR-0033)

The Security Agent declares a typed allow-list; the ADR-0033 injection boundary
extends to it — a tool not on its allow-list is unreachable regardless of prompt
content, and no prompt can make the read-only agent execute a device write. W3-T2
registers the allow-list; W5-T2 re-runs the routing eval to confirm no regression
and that the boundary holds for the new agent.

## Consequences

**Positive**
- Read-only is a structural guarantee (empty device-write registry + allow-list),
  not a hopeful prompt — survives a fully injected model (ADR-0033).
- Deterministic rule-based analysis makes the W5-T1 precision/recall gate provable;
  the agent narrates but does not decide.
- Reuses the DDI precedent (BaseSpecialistAgent + gate-routed CR drafts) and the
  ChangeRequest spine — no new framework, four-eyes preserved.
- The Troubleshooting/Security split is fixed here, so W3-T2 routing and the W5-T2
  eval have no open question.

**Negative**
- Deterministic analysis is less flexible than LLM judgment; novel misconfig classes
  need a new service rule (and a corpus case), not a prompt tweak — the right
  trade for a reproducible gate.
- The Troubleshooting Agent gaining firewall read tools adds a small routing-overlap
  surface; the §5 split + the W5-T2 no-regression run are the guards.
- A new CR kind touches the ChangeRequest enum/migration (W3-T1 scope).

## Alternatives considered

1. **Register firewall writes directly on the agent (let it remediate).** Rejected:
   violates the read-only mandate (`PRODUCTION.md` §2.3, CLAUDE.md "Human approval
   for changes"); every change must be a four-eyes CR (ADR-0020).
2. **"Read-only" enforced by the system prompt only.** Rejected: the classic
   failure — an injected prompt defeats it. The mandate is a registry/allow-list
   structural property (§1), verified by test.
3. **LLM-judged firewall analysis.** Rejected: non-reproducible, cannot hit a
   deterministic W5-T1 precision/recall gate; analysis is rule-based in the service,
   the agent narrates (Configuration-agent pattern).
4. **Fold all firewall analysis into the Troubleshooting Agent.** Rejected: posture
   audit over policy-as-data is a distinct concern from live path troubleshooting,
   and `PRODUCTION.md` §2.3 / CLAUDE.md name a dedicated Security Agent. The §5 split
   keeps both coherent.
