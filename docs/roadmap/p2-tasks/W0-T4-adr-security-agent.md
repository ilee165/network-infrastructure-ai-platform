# W0-T4 — ADR-0037 Security Agent (read-only analysis, findings, remediation→CR)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** spec + **strong** quality (security-semantic: the ADR defines an agent that reads device configs/credentials and an injection-boundary extension) |
| **Depends on** | W0-T1 (binds to `FIREWALL_POLICY`) |
| **ADRs** | ADR-0003 (LangGraph supervisor routing), ADR-0011 (RBAC / read-only scoping / audit), ADR-0020 (ChangeRequest four-eyes), ADR-0033 (prompt-injection boundary / per-agent tool allow-list), ADR-0034 (the analysis input) |
| **PRODUCTION.md** | §2.3 (Security Agent ships in P2; read-only; remediations→CR), §11 G-SEC |
| **Status** | Proposed |

## Objective

Decision record for **core agent #9** (CLAUDE.md): a **read-only** Security Agent
that analyzes firewall policy + posture and emits remediations **only** as
four-eyes ChangeRequests. Defines the agent's tools, findings model, routing,
RBAC scope, and injection boundary. Design gate; build is **W3-T1/T2**.

## Scope

**In**
- **Read-only mandate** (PRODUCTION.md §2.3, CLAUDE.md "Human approval for
  changes"): **no device-executing tool registered** to this agent; the only write
  path is a gate-routed `ChangeRequest` draft (ADR-0020) for human approval — itself
  a STATE_CHANGING tool the framework `ChangeRequestGate` intercepts into a draft,
  never a device write (the DDI precedent; the remediation tool is **not** banned —
  it is the sole, gated mutation surface). See ADR-0037 §1.
- **Analysis tools** (the agent's allow-list): firewall-policy analysis —
  **shadowed / redundant / overly-permissive** rule detection — and posture
  checks across configs + ACLs, backed by `FIREWALL_POLICY` (ADR-0034) + existing
  `ACL` / `CONFIG_BACKUP` capabilities. Read-only data access only.
- **Findings model**: a normalized finding (severity, category, offending rule
  reference / evidence, rationale, suggested remediation). Decide the schema home
  and that it carries **no secret material**.
- **Remediation → CR** (ADR-0020): a remediation becomes a `ChangeRequestDraft` /
  `ChangeRequest` — never a direct device write; four-eyes approval required.
- **Supervisor routing** (ADR-0003): how the supervisor routes security intents to
  this agent vs the Troubleshooting Agent (CLAUDE.md "Troubleshooting → Firewall
  analysis" is delivered here — decide the split or the shared-tool arrangement).
- **RBAC + injection boundary** (ADR-0011 / ADR-0033): per-agent **tool
  allow-list** confines the agent; the ADR-0033 injection boundary **extends to
  the new agent** (a routed/injected request cannot make it write).
- **Explainability** (CLAUDE.md "Explain all AI decisions"): findings cite the
  evidence (the offending normalized rule) so a human can audit the reasoning.

**Out**
- Implementation (agent graph, tools, findings model, routing registration) →
  **W3-T1 / W3-T2**.
- The deterministic firewall-analysis eval corpus → **W5-T1**.
- The routing-eval re-run → **W5-T2**.

## Requirements (grounded in ADR-0003/0011/0020/0033/0034)

1. **Read-only, structurally** (ADR-0020 / §2.3): the agent's tool registry
   contains zero device-write tools; the *only* mutation surface is a CR draft.
   This is a structural guarantee, not a prompt instruction.
2. **Per-agent tool allow-list** (ADR-0033): the injection boundary that confines
   existing agents extends to the Security Agent; a tool not on its allow-list is
   unreachable regardless of prompt content.
3. **Routes via the supervisor** (ADR-0003): no direct invocation that bypasses
   routing/audit; the security intent set is enumerated.
4. **Findings are evidence-cited and secret-free** (ADR-0011 audit / CLAUDE.md
   explainability): every finding references the normalized rule it flags; no
   credential or raw-secret content in a finding.
5. **Determinism target** (PRODUCTION.md §11): firewall analysis must be
   deterministic enough to hit precision/recall thresholds on the W5-T1 corpus —
   the ADR states the analysis is rule-based/structured, not free-LLM-judgment.

## Contracts / artifacts

- New LangGraph agent registered with the ADR-0003 supervisor; tool allow-list
  declared (ADR-0033 pattern).
- Findings model (normalized Pydantic; schema home decided in the ADR).
- Remediation path: finding → `ChangeRequestDraft` → ChangeRequest (ADR-0020).

## Validation / Test & gate plan (ADR review — strong)

- Repo ADR template; the **read-only structural guarantee** is stated explicitly
  and is testable (no STATE_CHANGING tool in the registry).
- **Consistency with ADR-0033**: the injection-boundary extension is concrete
  (named allow-list), not aspirational.
- **Consistency with ADR-0020**: remediation cannot reach a device except through
  an approved CR.
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0037 written; status **Proposed**.
- [ ] Read-only mandate stated as a structural (registry-level) guarantee.
- [ ] Analysis tool set + findings model schema fixed; evidence-cited, secret-free.
- [ ] Remediation→CR path (ADR-0020) and supervisor routing (ADR-0003) decided.
- [ ] Per-agent tool allow-list + ADR-0033 injection-boundary extension recorded.
- [ ] Troubleshooting-vs-Security firewall-analysis split decided.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` writes ADR → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** in parallel (security-semantic escalation) → `wf-fixer` (strong) if
findings → `wf-verifier` → **one atomic commit**.

## Risks

- **"Read-only" enforced only by prompt** is the classic failure: the ADR must
  make it a registry/allow-list structural property so W3 cannot accidentally
  wire a write tool. Stated here, verified in W3, evidenced in W5.
- **Routing overlap** with the Troubleshooting Agent (firewall analysis lives in
  both CLAUDE.md sections) — leave it unresolved and W3-T2 routing is ambiguous
  and W5-T2 regresses. Decide the split now.
