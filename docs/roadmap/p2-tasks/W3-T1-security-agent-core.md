# W3-T1 — Security Agent Core (rule analysis + posture + findings + remediation→CR)

| | |
|---|---|
| **Wave** | P2 W3 — Security Agent |
| **Owner** | `wf-implementer` (strong — security-semantic; reads device configs/credentials-adjacent data) |
| **Review tier** | **strong** spec + **strong** quality (security-semantic, read-only invariant) |
| **Depends on** | **W1-T1** (`FIREWALL_POLICY` models) + **≥1 of W2** (`panos` or `fortios`, a real policy source); ADR-0037 (W0-T4) |
| **ADRs** | ADR-0037 (the agent decision), ADR-0003 (specialist framework), ADR-0011 (RBAC / read-only), ADR-0020 (ChangeRequest spine), ADR-0033 (per-agent tool allow-list), ADR-0034 (analysis input) |
| **PRODUCTION.md** | §2.3 (Security Agent), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement **core agent #9** per ADR-0037: a `BaseSpecialistAgent` that analyzes
firewall policy + posture and produces **findings**, with remediations emitted as
**four-eyes ChangeRequest drafts** through the framework gate — **no
device-executing tool**. Mirrors the DDI-agent structure (read-only tools +
gate-routed change proposals). Routing/RBAC registration is **W3-T2**.

## Scope

**In** (`backend/app/agents/security/{__init__,agent,tools}.py`, a findings model
in `app/schemas/`, the analysis service the tools call, a new ChangeRequest
**kind** if remediation uses the gate, tests)
- `SecurityAgent(BaseSpecialistAgent)` — `name="security"`, `description` (W3-T2
  tunes for routing), `system_prompt`, `tools`. Default ReAct graph
  (`BaseSpecialistAgent.build_graph`), exactly like `DdiAgent`.
- **READ_ONLY analysis tools** over already-collected normalized data
  (`FIREWALL_POLICY` from W2 + existing `ACL` / `CONFIG_BACKUP`), following the
  **Configuration-agent "narrate" pattern**: the *server/service* computes the
  analysis deterministically; the agent narrates. Analyses:
  **shadowed**, **redundant**, **overly-permissive** firewall rules; posture
  checks across configs + ACLs.
- **Findings model** (`app/schemas/`): severity, category, offending-rule
  reference, evidence (the normalized rule), rationale, suggested remediation;
  **frozen, `extra="forbid"`, secret-free**.
- **Remediation → CR** (ADR-0020): a remediation is a **STATE_CHANGING tool the
  framework `ChangeRequestGate` intercepts → a ChangeRequest *draft*** (never
  executes), exactly as DDI mutators create `ddi_record` drafts. Add a new CR
  **kind** (e.g. `security_remediation` / `config_change`) for these drafts.
- **Read-only invariant** (ADR-0037): the agent registers **no tool that executes
  a device write** — the *only* write path is a gate-created CR draft. (See Risks:
  this tightens the P2-SECURITY-PLAN §5 "no STATE_CHANGING tool" wording.)
- **Determinism** (ADR-0037 / §11): the analysis is rule-based in the service, so
  findings are reproducible for the W5-T1 precision/recall corpus.
- **A9 redaction** at the secret boundary (like DDI): any config/policy fragment
  surfaced to the model is redacted first — no secret reaches a prompt.

**Out**
- Supervisor routing registration + RBAC `min_role` + allow-list/injection
  boundary → **W3-T2**.
- Firewall-analysis eval corpus + thresholds → **W5-T1**.
- Routing-eval re-run → **W5-T2**.

## Requirements (grounded in ADR-0037/0003/0011/0020/0033/0034)

1. **No device-executing tool, structurally** (ADR-0037): the tool registry has
   zero tools that write to a device; the sole mutation surface is a gate-created
   CR draft. A test asserts the tool set contains no executing-write tool.
2. **Remediation is gate-routed** (ADR-0020): remediation tools are STATE_CHANGING
   and the gate authors a CR draft from verbatim args — the model cannot bypass the
   gate (framework guarantee, like DDI).
3. **Findings cite evidence, carry no secret** (ADR-0011 / CLAUDE.md explain): each
   finding references the normalized rule it flags; redaction holds at the boundary.
4. **Deterministic analysis** (ADR-0037): rule logic lives in the service (not
   LLM judgment), so W5-T1 thresholds are reproducible.
5. **Binds to W1-T1 + ≥1 W2 source** (§2.3): analysis runs over real
   `NormalizedFirewallRule` data from `panos`/`fortios`.

## Contracts / artifacts

- `app/agents/security/agent.py` (`SecurityAgent`), `tools.py` (`SECURITY_TOOLS`:
  READ_ONLY analyses + gate-routed remediation tool(s)).
- Findings model in `app/schemas/`.
- Analysis service (deterministic rule logic) the tools call.
- New CR kind for remediation drafts (+ migration if the kind is an enum/DB value).

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff / mypy strict / import-linter / pytest **≥80%** on the agent + service.
- **Read-only invariant test**: the agent's tool set has no device-executing tool;
  every mutation is a gate-created CR draft.
- **Analysis correctness**: deterministic fixtures with known shadowed / redundant /
  overly-permissive rules → expected findings (seeds the W5-T1 corpus).
- **Remediation→CR test**: a remediation call yields a `ChangeRequestCreated`
  (draft), not a device write (mirror the DDI gate test).
- **Redaction test**: a secret-bearing config fragment is redacted before reaching
  the model.
- Live analysis against a real device **deferred-accepted** (no hardware).

## Exit criteria

- [ ] `SecurityAgent` (`name="security"`) on `BaseSpecialistAgent`, DDI-style graph.
- [ ] READ_ONLY analyses (shadowed/redundant/overly-permissive + posture) over
      `FIREWALL_POLICY`/`ACL`/`CONFIG_BACKUP`; deterministic in the service.
- [ ] Findings model: evidence-cited, frozen, secret-free.
- [ ] Remediation = gate-routed CR draft (new kind); **no device-executing tool**;
      invariant test green.
- [ ] Redaction at the secret boundary; analysis fixtures green (W5-T1 seed).
- [ ] D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **§5 wording vs framework reality**: the plan says "no STATE_CHANGING tool
  registered," but the DDI precedent implements remediation→CR *as* a
  STATE_CHANGING gate-routed tool. The real invariant is **no device-executing
  tool; CR-draft is the only write path**. Resolve in ADR-0037/W0-T4; implement
  the gate pattern here; the read-only-invariant test is the guard. **Flag to
  tighten §5 wording** so it matches the framework.
- **LLM-judged analysis** would make W5-T1 thresholds flaky — keep the rule logic
  deterministic in the service (Configuration-agent pattern), agent narrates only.
- **Secret leak into a finding/prompt** — redaction at the boundary + strong review.
