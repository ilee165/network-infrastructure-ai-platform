# P2-Security — Task Specs

Per-task decomposition of **P2-SECURITY-PLAN.md §3** waves **W0–W5**. Each task
below is a single atomic-commit unit running the **P2-SECURITY-PLAN.md §3 per-task
pattern**:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two reviews).

Escalation rule (P2-SECURITY-PLAN.md §2, `.claude/agents/README.md`): every
secret-surface task escalates **reviewers + fixer to the live strong model**.
**`fable` is UNAVAILABLE — escalate to `opus`.** A dead-model escalation returns a
silently "clean" review (P1 W0 false-clean root cause); never inline
`model: 'fable'`. In P2 the secret-surface set is large — see the per-wave tables.

## Carry-forward — READ BEFORE STARTING

P1's `docs/roadmap/P1-W4-LESSONS.md` traps recur here. Apply up front:

| Lesson | Rule | Bites which task(s) here |
|---|---|---|
| **L1** new gating CI tool | Run the tool LOCALLY before pushing it as gating; local gate set ≠ CI gate set. | **W4-T3** (kind/k3d-in-CI harness) |
| **L3** exec argv `$(VAR)` | K8s does NOT substitute `$(VAR)` in exec argv — wrap in `sh -c`. | **W4-T1** hash-chain verify CronJob; **W4-T2** rotation Job |
| **L4** helm secret idempotency | Reuse-or-generate dev secrets via `lookup` (empty in CI, reused on upgrade). | **W4-T4** mTLS cert material |
| **L5** CI pipe masks exit code | `set -o pipefail` + `test -s <out>` on any piped CI/job step. | **W4-T3** kind apply/assert pipeline |
| **L7** session windows | One-atomic-commit-per-task survives session-limit kills; discard half-done uncommitted work, resume via `resumeFromRunId`. | any multi-task workflow run |
| **L8** agent registry | Confirm every `agentType` is in the LIVE registry before launch. | any workflow launch (all P2 roles already loaded) |

Plus the P1-specific lessons baked into standing facts: **fastapi pinned** (no
lockfile — verify `include_router` introspection still green after any dep touch),
**deterministic suites pinned to `NullPool` SQLite** (W6 flaky-concurrency lesson)
— applies to **W5-T1** firewall-analysis suite.

---

## W0 — ADRs / re-scope (design gate, PRODUCTION.md §2.3/§5/§9)

Owner: **`wf-implementer`**. One design-gate wave; ADRs are the contract every
later wave implements. The §0 re-scope is recorded in P2-SECURITY-PLAN.md and
amended into `PRODUCTION.md`.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W0-T1](W0-T1-adr-firewall-policy-capability.md) | ADR-0034 `FIREWALL_POLICY` capability + `NormalizedFirewallRule`/`NormalizedNatRule` | `wf-implementer` | sonnet | — |
| [W0-T2](W0-T2-adr-panos-plugin.md) | ADR-0035 Palo Alto PAN-OS plugin (XML API) | `wf-implementer` | sonnet | W0-T1 |
| [W0-T3](W0-T3-adr-fortios-plugin.md) | ADR-0036 Fortinet FortiOS plugin (REST + SSH fallback) | `wf-implementer` | sonnet | W0-T1 |
| [W0-T4](W0-T4-adr-security-agent.md) | ADR-0037 Security Agent (read-only analysis, findings, remediation→CR) | `wf-implementer` | **strong** (security-semantic) | W0-T1 |
| [W0-T5](W0-T5-adr-audit-hash-chaining.md) | ADR-0038 Audit-log hash chaining + daily verification | `wf-implementer` | **strong** (audit spine) | — |
| [W0-T6](W0-T6-adr-mtls-between-containers.md) | ADR-0039 mTLS between containers (cert-manager/SPIFFE) | `wf-implementer` | **strong** | — |
| [W0-T7](W0-T7-adr-device-credential-rotation.md) | ADR-0040 Device credential rotation + per-credential scoping | `wf-implementer` | **strong** (credential vault) | — |
| [W0-T8](W0-T8-adr-collector-network-segmentation.md) | ADR-0041 Collector network segmentation (NetworkPolicy egress) | `wf-implementer` | **strong** | — |
| [W0-T9](W0-T9-production-md-rescope-amendment.md) | `PRODUCTION.md` §1 re-scope amendment (HA/scale-out + SIEM + obs-SLO → P3-Platform; dated rationale) | `wf-implementer` | sonnet | W0-T1..T8 |

## W1 — `FIREWALL_POLICY` capability (ADR-0034, PRODUCTION.md §2.3, ADR-0006)

Owner: **`wf-implementer`** (strong — novel cross-vendor normalized model).
**Blocks W2 + W3.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W1-T1](W1-T1-firewall-policy-capability.md) | `FIREWALL_POLICY` interface + `NormalizedFirewallRule`/`NormalizedNatRule` models + conformance-suite additions | `wf-implementer` (strong) | sonnet spec + quality | W0 |

## W2 — Vendor Wave 2 (ADR-0035/0036, PRODUCTION.md §2.3/§2.6)

Owner: **`wf-implementer-light`** ×2, parallel, disjoint files. Two independent
firewalls must validate `FIREWALL_POLICY` before the interface is declared stable.
**Strong quality review** (credential hygiene / leak).

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W2-T1](W2-T1-panos-plugin.md) | `panos` plugin — XML API; DISCOVERY_API, interfaces, routes, FIREWALL_POLICY, config backup, HA_STATUS | `wf-implementer-light` | sonnet spec + **strong** quality | W1-T1 |
| [W2-T2](W2-T2-fortios-plugin.md) | `fortios` plugin — REST + SSH fallback; same capability set | `wf-implementer-light` | sonnet spec + **strong** quality | W1-T1 |

## W3 — Security Agent (ADR-0037, PRODUCTION.md §2.3, ADR-0003/0011/0020)

Owner: **`wf-implementer`** (strong — reads device configs/credentials,
security-semantic). Read-only: no STATE_CHANGING tool registered; remediations
emit a four-eyes ChangeRequest only. Needs W1 + ≥1 W2 plugin.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W3-T1](W3-T1-security-agent-core.md) | Security Agent core — shadowed/redundant/overly-permissive rule analysis + posture checks + findings model + remediation→CR | `wf-implementer` (strong) | **strong** spec + quality | W1-T1, ≥1 of W2 |
| [W3-T2](W3-T2-supervisor-routing-rbac-allowlist.md) | Supervisor routing registration + read-only RBAC scoping + per-agent tool allow-list (extend ADR-0033 injection boundary) | `wf-implementer` (strong) | **strong** spec + quality | W3-T1 |

## W4 — Security hardening + kind validation (ADR-0038/0039/0040/0041, PRODUCTION.md §5/§9, gate G-SEC)

Three concurrent streams across owners — **audit** (Python), **credential**
(Python), **network** (infra + kind). All secret-surface → reviewers escalated to
strong. kind/k3d harness is **confined to this wave**: it asserts mTLS handshake +
NetworkPolicy deny only; expensive HA/scale/soak drills are P3-Platform.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W4-T1](W4-T1-audit-hash-chaining.md) | Audit-log hash chaining (predecessor-hash per entry) + daily verification job + tamper-detection test | `wf-implementer` (strong) | **strong** spec + quality | W0-T5 |
| [W4-T2](W4-T2-device-credential-rotation.md) | Device-credential rotation job + per-credential (site/role) scoping for blast-radius bounding | `wf-implementer` (strong) | **strong** spec + quality | W0-T7 |
| [W4-T3](W4-T3-kind-cluster-harness.md) | Ephemeral in-CI kind/k3d cluster harness (apply manifests, run enforcement assertions) | `wf-infra` (strong) | **strong** quality | W0-T6/T8 |
| [W4-T4](W4-T4-mtls-postgres-links.md) | mTLS api↔postgres / worker↔postgres (cert-manager/SPIFFE); handshake asserted on kind, plaintext refused | `wf-infra` (strong) | **strong** spec + quality | W4-T3 |
| [W4-T5](W4-T5-collector-network-segmentation.md) | Collector network segmentation — default-deny egress NetworkPolicy, mgmt-subnet allow only; deny asserted on kind | `wf-infra` (strong) | **strong** spec + quality | W4-T3 |

## W5 — Evals + phase-exit gate (PRODUCTION.md §2.6/§11, gates G-SEC/G-MNT/G-OBS)

Owner: **`wf-eval-designer`** (suites) + **`wf-release-auditor`** (gate evidence) +
**`wf-implementer`** (PG test harness). The LAST P2 wave and the phase-exit gate.
Builds the *proof*, not new controls. **W5-T0 added 2026-06-28** (build decision):
fold the Postgres-backed test layer in so the gate flip rests on PG-accurate tests,
not the SQLite-only suite that hid every W4 review major.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W5-T0](W5-T0-postgres-testcontainers.md) | Postgres-backed test harness — re-assert W4 audit hash-chain + credential rotation under real PG (closes the SQLite-hides-PG-semantics class) | `wf-implementer` (strong) | **strong** spec + quality | W4 |
| [W5-T1](W5-T1-firewall-analysis-eval-corpus.md) | Firewall-policy-analysis eval corpus + deterministic suite (precision/recall thresholds; `NullPool` SQLite) | `wf-eval-designer` (strong) | **strong** spec + quality | W3 |
| [W5-T2](W5-T2-cross-vendor-routing-rerun.md) | Cross-vendor + Security-Agent routing re-run (panos/fortios + new agent; no regression vs prior matrix) | `wf-eval-designer` (strong) | sonnet spec + quality | W2, W3 |
| [W5-T3](W5-T3-gate-evidence-readiness.md) | G-* gate evidence doc + P2-Security readiness; flip ADRs 0034–0041 → Accepted; record G-SCA/G-REL-live deferred → P3-Platform | `wf-release-auditor` (strong) | **strong** quality | W5-T0, W5-T1, W5-T2, W4 |

---

## Sequencing (within P2-SECURITY-PLAN.md §4)

- **W0** first (ADRs + re-scope amendment). T1 blocks T2/T3/T4 (they cite the model); T5–T8 independent; T9 last (cites all).
- **W1-T1** before W2 + W3 (the normalized model is the contract both bind to).
- **W2:** T1 ‖ T2 (disjoint plugin dirs). Can run **concurrent with W4** (disjoint files).
- **W3:** after W1-T1 + at least one W2 plugin; T1 → T2 (routing imports the agent).
- **W4 streams concurrent:** audit (T1) ‖ credential (T2) ‖ network (T3 → T4, T5). T3 (kind harness) lands before the two enforcement tasks that assert against it.
- **W5** last (needs both plugins + Security Agent + hardening). T0 ‖ T1 ‖ T2 (disjoint: PG test layer / firewall corpus / routing cases); T3 last (cites T0/T1/T2 + W4, flips ADRs + roadmap on green). **Rebase the W5 branch onto `origin/main` first.** Executed sequentially as atomic-commit-per-task within the build workflow even where files are disjoint.

## Spec template

Every per-task spec uses the same sections: **Metadata · Objective · Scope (In/Out)
· Deliverables · Requirements · Contracts · Test & gate plan · Exit criteria ·
Workflow · Risks.** Requirements are grounded line-by-line in the cited
ADR/PRODUCTION.md §; nothing here re-decides an ADR — these specs *implement* the
W0 design gate (ADR-0034…0041). Detailed task specs are authored per-wave at build
kickoff (same cadence as P1's W5/W6/W7 specs).
