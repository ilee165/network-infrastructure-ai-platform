# P2-Security Build Plan — Vendor Wave 2 + Security Agent + Security Hardening

**Project:** AI Network Operations Platform
**Status:** PLANNED — design complete (this doc + `docs/roadmap/p2-tasks/README.md`); W0 not started. Entry condition satisfied: **P1 complete** (`docs/roadmap/P1-RELEASE-READINESS.md` — all five §11 gates PASS on the P1-scoped slice; ADR-0033 Accepted).
**Authority:** Bound by `CLAUDE.md`, `docs/architecture/DECISIONS-BRIEF.md` (D1–D16), and `docs/roadmap/PRODUCTION.md` §1–§11.
**Scope source:** `PRODUCTION.md` Phase **P2** = Vendor Wave 2 (PAN-OS, FortiOS) + **Security Agent** + the P2 slice of the §5 security-hardening checklist. **Re-scoped (2026-06-25):** the HA/scale-out platform track, audit→SIEM export, and observability SLO enforcement are **resequenced out of this phase to P3-Platform** — see §0.

---

## 0. Re-scope decision (2026-06-25) — recorded, not silent

`PRODUCTION.md` §1 bundles three tracks under "P2": (a) Vendor Wave 2 + Security
Agent, (b) HA + scale-out (api HPA, KEDA workers, CloudNativePG, Redis Sentinel,
PgBouncer), (c) audit→SIEM export. This build splits that row:

- **This phase (P2-Security)** keeps the **buildable-and-validatable-now** half:
  Vendor Wave 2, the Security Agent, and the security-hardening controls that are
  pure code or kind-validatable infra (audit hash-chain, credential rotation,
  mTLS, collector segmentation).
- **HA + scale-out, audit→SIEM export, and obs SLO enforcement move to a new
  P3-Platform phase.** They require a live, long-running, certified-scale cluster
  to *validate* (failover, 30-day soak, 100-user load, 500–5,000-device scale,
  KEDA queue-burst, export-lag SLO). On this no-hardware host they would be
  ~entirely deferred-accepted — quarantining them keeps P2-Security's gates
  honest and biting instead of mostly-deferred.

**Why this is allowed and how drift is prevented:** moving roadmap scope is a
sequencing change, not a reversal of a binding D1–D16 decision, so it needs a
**`PRODUCTION.md` §1 amendment with dated rationale** (W0-T9), not a superseding
ADR. G-MNT §308 ("no silent drift") is satisfied because the move is recorded
here, amended in `PRODUCTION.md`, and the deferred gates are named explicitly in
§5. Downstream renumber (Wave-3/app-topology/compliance and cloud) follows in the
same `PRODUCTION.md` amendment.

---

## 1. Scope

| Track | Deliverables | PRODUCTION.md ref |
|---|---|---|
| New capability | `FIREWALL_POLICY` interface + `NormalizedFirewallRule` / `NormalizedNatRule` (PROPOSED names per §2.3) + conformance-suite additions | §2.3, ADR-0006 |
| Vendor Wave 2 | `panos` (XML API), `fortios` (REST + SSH fallback) plugins | §2.3 |
| Security Agent | Read-only firewall-policy analysis (shadowed / redundant / overly-permissive rules), posture checks across configs + ACLs; findings model; remediations emitted as ChangeRequests; supervisor routing integration | §2.3, ADR-0003/0011/0020 |
| Security hardening (P2 subset) | Audit-log hash-chaining + daily verification; device-credential rotation + per-credential scoping; mTLS (api↔postgres, worker↔postgres); collector network segmentation | §5, §9 |
| Validation infra | Ephemeral in-CI kind/k3d cluster harness — bites mTLS handshake + NetworkPolicy enforcement (the "kind for cheap" half) | §9 |
| Gates | G-SEC re-eval on P2 slice; G-MNT continuous; G-OBS continuous slice (no new SLO enforcement). **G-SCA + G-REL-live drills deferred → P3-Platform** | §11 |

**Out of P2-Security (→ P3-Platform):** HA + scale-out (§3), audit→SIEM export
(§5/§6), obs SLO recording-rules/alerts/dashboards + fault-injection MTTD (§6),
N-2 upgrade rehearsal (§10). **Out entirely until later waves:** Wave-3/4 vendors,
application-dependency topology, compliance reporting suite, hybrid-cloud topology.

---

## 2. Agent capability review

Roles + model tiers from `.claude/agents/README.md` (reuse the P1 roster; no new
agent type needed — `wf-infra` and `wf-release-auditor` already exist).

| agentType | Model | P2-Security use |
|---|---|---|
| `wf-implementer` | strong (inherit) | Novel / security-critical **Python**: `FIREWALL_POLICY` normalized model, Security Agent, audit hash-chain + verify job, device-credential rotation + scoping |
| `wf-implementer-light` | sonnet | Template-following plugins: `panos`, `fortios` (mirror Wave-0/1 netmiko + httpx capability pattern) |
| `wf-infra` | strong (inherit) | Declarative infra: mTLS certs (cert-manager/SPIFFE), collector NetworkPolicy, ephemeral in-CI kind harness. Infra gates, not Python-TDD |
| `wf-eval-designer` | strong | AI-output evals: firewall-policy-analysis corpus, cross-vendor + Security-Agent routing re-run |
| `wf-release-auditor` | strong | Phase-exit G-* gate evidence + readiness doc; flips ADRs 0034–0041 + roadmap on green |
| `wf-spec-reviewer` | sonnet* | Spec-compliance review per task |
| `wf-quality-reviewer` | sonnet* | Correctness / secret-leak / convention review per task |
| `wf-fixer` | sonnet* | Apply enumerated review findings |
| `wf-verifier` | sonnet | Confirm fix commit resolves findings |

\* **Escalation rule** (`.claude/agents/README.md`, P1 W0 false-clean root cause):
every secret-surface task escalates **reviewers + fixer to the live strong model
(`opus`)**. `fable` is UNAVAILABLE — never inline `model: 'fable'`; a dead-model
escalation returns a silently "clean" review. In P2 the secret-surface set is
large: **Security Agent** (reads device configs/credentials), **audit hash-chain**
(audit spine), **credential rotation** (credential vault), **mTLS** (cert
material), **collector segmentation** (security-semantic NetworkPolicy), and the
firewall plugins' **credential hygiene**. All escalate.

---

## 3. Build waves (dependency-ordered)

Per-task pattern, unchanged from P1: **1 implementer → 2 parallel reviewers
(spec + quality) → conditional fixer → verifier → 1 atomic commit.** Sequential
tasks share files; parallelize only within a task (the two reviews). ADRs
numbered from **0034** (current max is 0033). Full per-task specs:
`docs/roadmap/p2-tasks/README.md`.

| Wave | Tasks | Implementer | Review tier | Notes |
|---|---|---|---|---|
| **W0 — ADRs / re-scope** | ADR-0034 (`FIREWALL_POLICY` model) · 0035 (PAN-OS) · 0036 (FortiOS) · 0037 (Security Agent) · 0038 (audit hash-chain) · 0039 (mTLS) · 0040 (cred rotation) · 0041 (collector segmentation); + `PRODUCTION.md` §1 re-scope amendment | `wf-implementer` | sonnet | Design gate; unblocks all waves. §0 recorded here |
| **W1 — `FIREWALL_POLICY` capability** | Interface + `NormalizedFirewallRule` / `NormalizedNatRule` + conformance additions | `wf-implementer` (strong) | sonnet spec + quality | Novel cross-vendor model; **blocks W2 + W3** |
| **W2 — Vendor Wave 2** | `panos` (XML API); `fortios` (REST + SSH fallback) | `wf-implementer-light` ×2 (parallel, disjoint files) | sonnet spec + **strong quality** (credential hygiene) | Two independent firewalls validate `FIREWALL_POLICY` before it is declared stable (§2.3). Conformance + ≥80% cov + normalized round-trip (§2.6). Live golden-path **deferred-accepted** (no hardware) |
| **W3 — Security Agent** | Agent core (rule analysis + posture + findings model + remediation→CR); supervisor routing + read-only RBAC scoping | `wf-implementer` (strong) | **strong** spec + quality (security-semantic, reads credentials) | Needs W1 + ≥1 W2 plugin. CLAUDE.md "Troubleshooting → Firewall analysis" delivered here |
| **W4 — Security hardening + kind validation** | Audit hash-chain + daily verify; cred rotation + scoping (Python); mTLS + collector NetworkPolicy (infra) validated on an **ephemeral in-CI kind cluster** | `wf-implementer` (Python streams) + `wf-infra` (cert/network + kind harness) | **strong** spec + quality (all secret-surface) | kind confined to this wave: bites mTLS handshake + NetworkPolicy deny only. Expensive HA/scale/soak drills are P3-Platform |
| **W5 — Evals + gate exit** | Postgres-backed test harness (re-assert W4 controls under real PG — added 2026-06-28); firewall-analysis eval corpus; cross-vendor + Security-Agent routing re-run (no regression); G-* evidence doc + P2-Security readiness; flip ADRs 0034–0041 → Accepted | `wf-implementer` (strong, PG harness) + `wf-eval-designer` (strong) + `wf-release-auditor` (strong) | **strong** quality | Phase-exit gate; mirrors P1-W7 / M5 T20. Builds the *proof*, not new controls. **W5-T0 PG harness folds in the SQLite-hides-PG-semantics carry-forward so the gate flip rests on PG-accurate tests** |

---

## 4. Sequencing

- **W0 first** — blocks all (ADRs are the design contract; the §0 re-scope is recorded here).
- **W1 first among build waves** — the `FIREWALL_POLICY` model blocks both plugins (W2) and the Security Agent (W3).
- **W2** (2 plugins, internal parallel) can run **concurrent with W4** (hardening streams) — disjoint files.
- **W3** after W1 + at least one W2 plugin (the agent needs a real `FIREWALL_POLICY` source to analyze); W3 agent-core → W3 routing.
- **W4 streams run concurrently** across owners: audit hash-chain (Python), credential rotation (Python), and the network stream (kind harness → mTLS → collector NetworkPolicy). The kind harness lands before the two enforcement tasks that assert against it.
- **W5 last** — needs both plugins + the Security Agent + the hardening controls in place to evaluate.

---

## 5. Per-wave exit criteria

**Vendor (W2):** PRODUCTION.md §2.6 — conformance suite green, raw artifacts
stored verbatim, normalized models (incl. `FIREWALL_POLICY`) round-trip, write
paths via ChangeRequest, docs + API docs published, ≥80% cov, **no cross-vendor
eval regression** (re-run in W5). Live-lab golden-path deferred-accepted (no hardware).

**Security Agent (W3):** read-only — **no device-executing tool registered**; the
only write path is a gate-routed four-eyes `ChangeRequest` draft (ADR-0020), itself a
STATE_CHANGING tool the `ChangeRequestGate` intercepts (never a device write), per
ADR-0037 §1; findings deterministic on the
W5 labelled corpus (precision/recall thresholds met); routing eval re-run with the
new agent passes; per-agent tool allow-list confines it (the ADR-0033 injection
boundary extends to the new agent).

**Hardening (W4):** G-SEC §5 slice — hash-chain verification job green and
tamper-detection test bites; credential rotation re-issues + re-scopes without
plaintext leak; **mTLS handshake asserted on the kind cluster** (api↔pg /
worker↔pg mutual auth, plaintext refused); **collector NetworkPolicy enforced on
the kind cluster** (default-deny egress, mgmt-subnet allow only). Manifest-policy
gates (kubeconform/conftest/kube-linter) stay green.

**Phase exit (W5):** the P2-scoped slice of all five §11 gates passes
simultaneously on the release HEAD —
- **G-SEC PASS** (P2 scope): firewall analysis + injection boundary on the new
  agent, hash-chain verify, cred-rotation no-leak, mTLS + collector segmentation
  enforced on kind. Inherits all P1 G-SEC controls.
- **G-MNT PASS** (continuous): D16 green, ADR currency (0034–0041 Accepted),
  plugin onboarding validated (Wave 2 from template), `PRODUCTION.md` amended.
- **G-OBS PASS** (continuous slice): `/metrics` + probes + trace correlation
  unchanged; **no new SLO enforcement claimed** (that is P3-Platform).
- **G-SCA — DEFERRED-ACCEPTED → P3-Platform** (HA/scale-out moved out, §0). Named.
- **G-REL — P1 baseline holds; live failover/soak/scale drills DEFERRED → P3-Platform.** Named.

Every later-phase criterion is named deferred-accepted, none silent (ADR-0033 §1
discipline, carried from P1).

---

## 6. Open items (non-blocking, carry forward)

- **Consultant §12 answers** — re-check `docs/consultant/QUESTIONS.md` at W0:
  *compliance regimes* (Security Agent findings feed compliance evidence; SOC 2
  CC-series default holds), *data retention* (audit hash-chain window), *air-gapped
  operation* (no new external dependency in P2). PROPOSED defaults hold.
- **Live-lab deferred-accepted** (no hardware): Wave-2 device golden-paths (W2),
  Security Agent against live firewall policy (W3) — same posture as M4/M5/P1;
  code paths fixture/mock-verified in the green eval suites.
- **`FIREWALL_POLICY` model names** — **ratified by ADR-0034** (W0):
  `NormalizedFirewallRule` / `NormalizedNatRule`, lowest-common-denominator fields,
  **raw-first-only** vendor-richness escape hatch (ADR-0034 §6, no `vendor_attributes`
  map). Both plugins (W2) and the Security Agent (W3) bind field-for-field to these.
- **P3-Platform** inherits the resequenced HA/scale-out + SIEM export + obs SLO
  enforcement; its own plan is authored when P2-Security exits.
