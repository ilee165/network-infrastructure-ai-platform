# ADR-0020: ChangeRequest Workflow and Four-Eyes Approval

**Status:** Accepted | **Date:** 2026-06-18 | **Milestone:** M5 (realizes D11 brief §7 — the persistent write-path spine)

## Context

M5 is the first **write-path** milestone: the platform can now change the network (`CONFIG_RESTORE`/`CONFIG_DEPLOY` per ADR-0021, DDI record add/modify/delete per ADR-0022). CLAUDE.md mandates **"Human approval for changes"** and **"Audit everything"**, and ADR-0011 (D11) §3 already fixed the lifecycle, the four-eyes rule, and the `change_requests` + `approvals` tables *as a decision*. What did **not** yet exist in code: ADR-0011 §3 was a decision; M3/M4 shipped only `agents/framework/approval.py` — an in-process `ApprovalGate`/`DenyAllGate` that **hard-rejects** every state-changing tool with an audit entry, because there was no persistent ChangeRequest to create. M5 must now (a) build the persistent ChangeRequest spine and (b) rewire that gate from hard-reject to CR-creation.

This ADR fixes the concrete state machine, the data-model shape, and — security-critically — **where the four-eyes rule is enforced and why a UI-only check is insufficient**. It binds ADR-0011 §3 to the M5 implementation; ADRs 0021/0022 reference this ADR for "writes only ever run via an approved ChangeRequest."

## Decision

**A persistent ChangeRequest is the single spine for every state-changing action. Its lifecycle is a guarded server-side state machine; the four-eyes rule (approver ≠ requester) is enforced in the ChangeRequest service and a database constraint — never in the UI alone; every transition writes an `audit_log` entry with before/after state and a reasoning-trace link.**

### 1. Lifecycle state machine

```mermaid
stateDiagram-v2
    [*] --> draft
    draft --> pending_approval : submit (requester)
    pending_approval --> draft : reject with comment (returns for edit)
    pending_approval --> approved : approve (MUST be a different user — four-eyes)
    approved --> executing : Automation Agent claims (ADR-0021)
    executing --> completed : apply + post-verify succeed
    executing --> failed : apply or verify error
    failed --> rolled_back : structured rollback applied (ADR-0021 §rollback)
    completed --> [*]
    rolled_back --> [*]
```

- Terminal states: `completed`, `rolled_back`. `failed` is non-terminal — it transitions to `rolled_back` once the structured rollback (ADR-0021) completes; a `failed` CR whose rollback also fails stays `failed` and raises an operator alert (it is never silently closed).
- **Every** edge is a guarded transition implemented in the ChangeRequest service (`backend/app/services/change_requests/`). Guards validate the *from*-state, the actor's RBAC, the four-eyes predicate, and (for `approved → executing`) that the caller is the Automation Agent. No transition is performed by an UPDATE outside the service.
- There is **no auto-approve edge in any environment**. Agents may author and explain a CR (`draft`, then `submit`); only a human performs `pending_approval → approved`.

### 2. Data model — `change_requests` + `approvals`

`change_requests`:
`{ id, state (enum), requester_id (FK users), generating_session_id (FK agent_sessions, nullable for human-authored), reasoning_trace_id (FK reasoning_traces, nullable), kind (config_restore | config_deploy | ddi_record), target_refs (JSONB — device ids / DDI object refs), payload (JSONB — the exact diff/API calls to apply), rollback_plan (JSONB — ADR-0021: snapshot ref or inverse-change spec), four_eyes_required (bool, default true), created_at, updated_at }`.

`approvals` (one row per approve/reject decision — full history, not a mutable column):
`{ id, change_request_id (FK), decision (approved | rejected), actor_id (FK users), comment, created_at }`.

- **Database-level four-eyes backstop:** a `CHECK` / partial-unique constraint enforces that no `approvals` row with `decision = 'approved'` may have `actor_id = change_requests.requester_id` for that CR (enforced via constraint trigger, since it spans two tables). This is defense-in-depth behind the service guard (§3), in the same spirit as ADR-0011 §2's DB-enforced append-only audit.
- The `payload` and `rollback_plan` are captured **at submit time** and are immutable through approval/execution — what an approver reviews is exactly what executes (no TOCTOU between approval and apply). Re-editing requires `reject → draft` and a fresh submit.
- `payload` may carry secret-bearing config/DNS content; any rendering toward an LLM (diff/intent preview, agent explanation) passes the A9 redaction layer (`llm/redaction.py`, ADR-0011/0017). The stored payload itself is verbatim (parity with `config_snapshots`, ADR-0017 §2) so execution replays a real change.

### 3. Four-eyes rule — enforced server-side, on by default

- **Rule:** the approver MUST differ from the requester. `four_eyes_required` defaults to **true** (secure by default) and is configurable per deployment policy; when disabled, the disablement itself is an audited config event and self-approval still produces a distinct `approvals` row attributed to the actor.
- **Enforcement point:** the predicate `actor_id != requester_id` is checked **inside the ChangeRequest service transition guard** for `pending_approval → approved`, before any state write, and is additionally guaranteed by the DB constraint (§2). The API approval endpoint (M5 task #15, `changes` router) is a thin caller of this service.
- **Why UI-only is insufficient (security-critical):** a UI check disables a button but the approval is ultimately an HTTP request to the API. Any client that bypasses the SPA — `curl`, a stale/forged frontend bundle, a scripted client, a future integration, or an XSS-driven request riding the victim's session — reaches the endpoint directly. If four-eyes lived only in React, a requester could self-approve their own firewall change with one API call. Enforcing in the service (every transition path funnels through it) plus a DB constraint (survives an application bug or SQL-injection foothold) makes self-approval **structurally impossible**, not merely hidden. This is exit criterion #2 (self-approval rejected under default config, automated test).

### 4. Audited transitions + reasoning-trace link

- Every transition writes an `audit_log` entry (ADR-0011 §2): actor (user id, plus agent name when an agent authored), action (`change_request.<from>_to_<to>`), target (`change_request` + id and the target devices/DDI refs), **before/after state JSONB**, request id, and the `reasoning_traces` link when the CR originated from an agent run. The full chain (requester → approver → executor → before/after → trace) is reconstructable from `audit_log` + `approvals` alone — this is the audited golden path of exit criterion #1.

### 5. RBAC — who may approve

- Per the ADR-0010 role matrix: **`engineer`+ may approve** (and the four-eyes predicate still applies on top of the role). `operator` may author/draft and submit CRs but cannot approve. `admin` inherits `engineer`. Read-only `viewer` can see CRs and the audit chain but take no lifecycle action. Approval rights are checked in the same service guard as the four-eyes predicate.

## Consequences

**Positive**
- The single most-feared failure mode ("the AI changed my firewall") is structurally impossible: no write path exists that is not a service-guarded transition out of an `approved` CR authored by a *different* user.
- Defense-in-depth four-eyes (service guard + DB constraint) survives a frontend bypass, a scripted client, and an application bug — credible in an enterprise security review.
- Immutable approved-payload eliminates the approve-then-swap (TOCTOU) class of attack and makes the audit chain self-consistent.
- The `approvals`-as-history table (not a column) preserves every decision and comment, including rejections — useful for audit and for re-work context.

**Negative**
- Human approval adds latency to every change and rules out closed-loop auto-remediation (inherited from ADR-0011; a future policy ADR would be required to revisit).
- The cross-table four-eyes constraint needs a constraint trigger (a single-row `CHECK` cannot reference another table), adding a small migration-maintenance surface verified by a dedicated migration test (M5 task #2).
- Capturing full before/after state in `audit_log` duplicates some data also in `change_requests`/`config_snapshots` — accepted for self-contained audit records (same trade-off ADR-0011 already took).

## Alternatives considered

1. **UI-only four-eyes (disable the approve button for the requester).** Rejected, security-critical: the approval is an API call; any non-SPA client reaches the endpoint directly, so a button check is cosmetic. Enforcement must live where every path converges — the service — backed by a DB constraint.
2. **Mutable single `approval` column on `change_requests` instead of an `approvals` history table.** Rejected: loses rejection history and comment trail, and a mutable column is easier to overwrite than an append-only decision log. The history table mirrors the append-only posture of `audit_log`.
3. **Allow editing the payload after approval (re-render at execution).** Rejected: opens an approve-then-swap TOCTOU window — the approver would not be approving what executes. Re-work goes through `reject → draft → submit` so approval always binds to a frozen payload.
4. **Keep the M3 `DenyAllGate` and bolt approval on as a separate side-channel.** Rejected: two parallel notions of "is this change allowed" drift apart. M5 rewires the one gate (ADR-0020 §ref by task #4) to create a CR, so there is exactly one spine.
