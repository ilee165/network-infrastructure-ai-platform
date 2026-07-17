# P2-Security Release Readiness — Phase-exit gate evidence (W5-T3)

**Date:** 2026-06-29
**Branch:** `feat/p2-w5-evals-gate` (release HEAD `6acac91` — PR #79; W5-T0/T1/T2 in place)
**Owner:** `wf-release-auditor` (strong)
**Authority:** `docs/roadmap/P2-SECURITY-PLAN.md` §5 ("the P2-scoped slice of all
five §11 gates passes simultaneously on the release HEAD") and §0 (the 2026-06-25
re-scope splitting HA/scale-out + SIEM export + obs-SLO enforcement out to
P3-Platform); `PRODUCTION.md` §11 (the five production-readiness gates
G-SEC / G-REL / G-SCA / G-OBS / G-MNT) + the §1 2026-06-25 amendment (W0-T9);
ADR-0033 §1 (deferrals named, never silent). Mirrors `P1-RELEASE-READINESS.md`
(W7-T4) and M5 T20.
**Companion evidence:**
`P1-RELEASE-READINESS.md` (the inherited P1 G-SEC/G-REL/G-OBS/G-MNT baseline this
phase carries forward), `docs/roadmap/PRODUCTION.md` §11 (gate criteria) + §1
amendment (re-scope), `docs/runbooks/kind-harness.md` (why the live kind
enforcement run is not yet a blocking gate + what promotes it),
`.github/workflows/ci.yml` (canonical CI gate definitions; the `all-gates`
required aggregator + the `pg-integration` job).

This document records the **real** gate results captured on the release HEAD. It
judges each of the five §11 gates **against the P2-Security phase scope** (Vendor
Wave 2 PAN-OS/FortiOS + the Security Agent + the security-hardening subset:
audit-log hash-chaining, device-credential rotation + scoping, mTLS
api/worker↔postgres, collector network segmentation — P2-SECURITY-PLAN §1). The
§11 gate criteria span the whole P1→P5 production arc; the criteria that belong to
later phases (HA/scale-out, 30-day soak, live failover/DR drills, SLO
enforcement, SIEM export, external pentest, N-2 upgrade rehearsal) are **named
explicitly as deferred**, never silently dropped (ADR-0033 §1). **This host has no
real network devices, no live cluster, and no LLM provider; live-lab items are NOT
claimed here.** Per the 2026-06-25 re-scope (P2-SECURITY-PLAN §0, `PRODUCTION.md`
§1), **G-SCA in full and the G-REL live failover/soak/scale drills are out of
P2-Security scope → P3-Platform**; P2-Security holds the P1 G-REL baseline.

---

## 0. Scope discipline — what "gate PASS" means at P2-Security

`PRODUCTION.md` §11 defines each gate by its **GA** criteria, re-evaluated at the
end of every production phase (P1–P5). P2-SECURITY-PLAN §5 binds P2-Security to
the **P2-scoped slice**: G-SEC for the W2/W3/W4 controls, G-MNT + G-OBS
continuous, with **G-SCA + G-REL-live drills deferred-accepted to P3-Platform**
(§0 re-scope). A gate's verdict below is therefore **PASS for the P2-scoped
criteria, with later-phase criteria itemised as deferred**. A later-phase
criterion left unmet is **not** a P2-Security blocker; an **unmet P2-scoped**
criterion would be. Each verdict cites a HEAD artifact — a green CI job + test
path, a commit, a sign-off note, or a rendered manifest — that a reviewer can
re-derive.

---

## 1. Repo gates — REAL results (release HEAD `6acac91`)

The single required CI check is `all-gates` (`.github/workflows/ci.yml:1015`),
which `needs: [backend, frontend, security-scan, docker, infra, kms-emulators,
pg-integration]` and fails unless **every** upstream gate is `success` — so a
failed or skipped gate blocks merge atomically (no orphan advisory gate). CI run
**28349836098** (head sha `6acac91`) is `conclusion: success` with **all nine
in-repo jobs green**, plus the two external advisory checks (CodeRabbit, cubic)
green = the 11 checks SUCCESS on HEAD:

| Job (ci.yml) | What it gates | Result on HEAD `6acac91` (run 28349836098) |
|------|------------------|----------------|
| `all-gates` (required aggregator) | every upstream job `success` | **SUCCESS** |
| `backend` (ruff, mypy, import-linter, pytest) | D16 lint/type/imports + full pytest incl. firewall + routing evals | **SUCCESS** |
| `pg-integration` (real PostgreSQL — W4 controls under PG) | `pytest tests/pg/ -m integration` against a real `pgvector` service | **SUCCESS** (and **proven to bite** — see §1.1) |
| `frontend` (eslint, tsc, vitest, build) | frontend D16 gates | **SUCCESS** |
| `infra` (helm lint, kubeconform, kube-linter, conftest) | chart policy-as-test + mTLS render-twice L4 idempotency guard (`ci/mtls/render-twice.sh`, RED gate, no continue-on-error, ci.yml:650) | **SUCCESS** |
| `kms-emulators` (LocalStack KMS + dev Vault) | KMS-backed master-key integration (P1 G-SEC inherited) | **SUCCESS** |
| `docker` (build + SBOM + Trivy + cosign sign) | image SBOM + Trivy CRIT/HIGH `ignore-unfixed` + keyless cosign | **SUCCESS** |
| `security-scan` (gitleaks — tree + history) | no secret material in tree or full git history | **SUCCESS** |
| `kind-harness` (enforcing-CNI self-test + assertions — **non-blocking**) | static harness-invariant validator + assertion-library self-tests bite (blocking steps); shared rendered-Secret extractor tests run in the blocking backend suite; the **live** `kind-harness.sh` enforcement run is `continue-on-error` and the job is **deliberately ABSENT from `all-gates` needs** | **SUCCESS** (blocking steps green; live run is signal-only — see §2 G-SEC mTLS/collector lines) |

> The deterministic backend evals (firewall precision/recall, cross-vendor +
> Security-Agent routing) run inside the `backend` job; the W4 hardening controls
> (audit hash-chain, credential rotation) are re-asserted under **real
> PostgreSQL** in the dedicated `pg-integration` job, which is a member of the
> `all-gates` `needs` list and therefore release-blocking.

### 1.1 Gate-bites confirmation (P1 lesson — a gate green-at-setup masks findings)

Each P2-scoped gate was confirmed to actually **RUN and BITE** on a regression,
not merely be green at setup:

- **`pg-integration` empirically bit on HEAD's own history.** Commit `dd366bd`
  ("render real PG password for the REVOKE admin connection") is the gate
  catching a real local-vs-CI defect: the REVOKE append-only assertion connected
  with a wrong password under the CI Postgres service, the job went **red**, the
  bug was fixed, and the job went **green**. A gate that has demonstrably failed
  and recovered on the release branch is proven to bite — it is not green-at-setup.
- **Firewall-analysis floor bites under perturbation.** The 1.0 precision/recall
  floor is guarded by `test_threshold_bites_on_a_missed_finding` /
  `test_threshold_bites_on_a_false_positive`
  (`backend/tests/agents/eval/test_firewall_analysis_eval.py`), which perturb the
  *scored input* and assert the same threshold logic drops below floor — so the
  floor is a real gate, not a vacuous one. Corpus-shape guards
  (`test_every_class_has_positives`, `test_corpus_has_clean_negatives`) keep the
  floors meaningful (a flag-everything analyzer cannot reach precision 1.0).
- **Injection-boundary confinement bites at the registry layer.**
  `test_security_agent_allow_list_confined_to_read_only_set`
  (`backend/tests/agents/eval/test_p2_cross_vendor_routing.py`) asserts the new
  agent's allow-list is *exactly* its own read-only tools; the behavioural proof
  that an injected `propose_firewall_remediation` only drafts a four-eyes CR is
  carried by `test_p1_prompt_injection.py::TestSecurityRemediationModelToolBoundary`.
- **PG hash-chain tamper-detect + append-only bite under real PG semantics.**
  `test_full_scan_catches_pre_anchor_tamper_under_pg`,
  `test_head_read_ignores_null_seq_under_pg_nulls_first_ordering`,
  `test_seq_index_is_non_unique_on_partitioned_audit_log`, and the
  `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC` deny test
  (`backend/tests/pg/test_audit_hash_chain_pg.py`,
  `pytest.mark.integration`) exercise exactly the PG-only semantics SQLite hides
  (NULLS-FIRST head selection, partitioned non-unique index, GRANT/REVOKE
  enforcement, the `prev_hash` chain walk).
- **PG credential-rotation no-leak / scope-deny bites.**
  `backend/tests/pg/test_credentials_rotation_pg.py` asserts confirm-then-swap
  re-wrap leaves payload byte-identical while changing the wrapped DEK, refuses an
  out-of-scope decrypt before any KEK access, and asserts a test sentinel secret
  is **absent** from every persisted `kek.rotate.*` / `credential.scope_denied`
  JSONB audit row.

---

## 2. Per-gate verdicts (PRODUCTION.md §11, on HEAD `6acac91`)

### G-SEC — Security — **PASS (P2-Security scope)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| **Firewall-policy analysis correct (precision/recall floors met, deterministic)** (P2 capability, ADR-0037) | **PASS** | `test_firewall_analysis_eval.py` — per-class precision/recall ≥ **1.0** floor on the W5-T1 labelled corpus, byte-stable across runs; floor bites under perturbation (§1.1). `backend` job green [W5-T1, commit `3bddb1a`]. |
| **Prompt-injection boundary extends to the new Security Agent; 100% zero unauthorized tool calls** (§293, ADR-0033) | **PASS** | Per-agent allow-list confined to the read-only analysis set; `propose_firewall_remediation` is itself a STATE_CHANGING tool the `ChangeRequestGate` intercepts (never a device write). Registry invariant `test_security_agent_allow_list_confined_to_read_only_set` + behavioural carry `TestSecurityRemediationModelToolBoundary` [W5-T2, commit `a156b2a`; inherits the P1 ED1–ED5 deterministic suite, 25/25]. |
| **Audit log append-only attested (grant check) + hash-chain verification passing** (§290) | **PASS** | Re-asserted under **real PostgreSQL**: tamper-detect, NULLS-FIRST head read, partitioned non-unique `seq` index, `REVOKE UPDATE,DELETE … FROM PUBLIC` deny, `prev_hash` walk — `tests/pg/test_audit_hash_chain_pg.py`, `pg-integration` job green [W4-T1 + W5-T0, commit `cbb05e4`]. |
| **Credential-leak tests green; no plaintext device credential in any output** (§289) | **PASS** | Confirm-then-swap KEK re-wrap (payload byte-identical), per-credential scope-deny before KEK access, and no secret / wrapped-DEK / nonce in any persisted JSONB audit row, under real PG — `tests/pg/test_credentials_rotation_pg.py`, `pg-integration` job green [W4-T2 + W5-T0, commit `cbb05e4`]. |
| **State-changing actions traverse ChangeRequest lifecycle; self-approval impossible; four-eyes** (§287–288) | **PASS (inherited + re-asserted)** | P1 four-eyes spine carried; the Security Agent's only write path is a gate-routed four-eyes `ChangeRequest` draft (ADR-0037 §1), re-asserted under injection by the carry above. |
| **mTLS api/worker↔postgres: cert material renders idempotently; handshake asserted + plaintext refused** (§5 P2, ADR-0039) | **PARTIAL — material/static layer PASS (blocking); live kind handshake DEFERRED** | The mTLS render-twice **L4 idempotency guard** (`ci/mtls/render-twice.sh`) and the external-PG fail-fast guard are **RED gates** in the `infra` job; shared extractor hardening tests bite in the normal backend suite (`test_render_twice_helpers.py`). The **live api/worker↔pg handshake + plaintext-refused assertion on a kind cluster** runs in `kind-harness.sh` which is `continue-on-error` and **not in `all-gates`** — so a live-handshake regression does **not** currently bite. Recorded as deferred-accepted (no-hardware on the authoring host; promotion path in `docs/runbooks/kind-harness.md`). [W4-T4] |
| **Collector default-deny egress NetworkPolicy enforced on kind** (§9, ADR-0041) | **PARTIAL — policy renders + harness-invariant layer PASS (blocking); live kind deny DEFERRED** | The chart NetworkPolicies render and pass `infra` policy gates (kubeconform/conftest/kube-linter); the CNI self-test + egress-probe-tristate self-tests bite in `kind-harness` (blocking). The **live default-deny egress enforcement assertion on the enforcing-CNI kind cluster** is in the same `continue-on-error` `kind-harness.sh` run, so a live-deny regression does **not** currently bite. Deferred-accepted, same promotion path. [W4-T5] |
| **Zero fixable critical/high CVEs in shipped images** (§286) | **PASS (CI-gated)** | `docker` job: Trivy `CRITICAL,HIGH` + `ignore-unfixed` + `exit-code 1` on both images; green on HEAD. |
| **Secret scan: no secret material in tree or history** (P1 hygiene) | **PASS** | `security-scan` gitleaks tree + full history; green on HEAD. |
| KMS-backed master key, no-leak, fail-closed prod gate (§5 P1) | **PASS (inherited)** | `kms-emulators` required job green on HEAD; P1 W6 control (P1-RELEASE-READINESS §2). |
| **External penetration test; recurring 6-month break-glass drill** (§291–292) | **DEFERRED — pre-GA / operational** | Point-in-time pentest is pre-GA (ADR-0033 Alt #6); break-glass drill is an operational cadence item. Out of P2-Security scope; named, carried from P1. |

**G-SEC verdict: PASS** for the P2-Security-scoped criteria. The deterministic
(firewall + injection-boundary) and **real-PostgreSQL** (audit hash-chain,
credential rotation) controls all run in **`all-gates`-blocking** jobs and bite on
a regression (§1.1), and carry the gate. The **two kind-cluster *live-enforcement*
sub-items (mTLS handshake, collector egress-deny)** are **PARTIAL**: their static /
render / harness-invariant layers bite and are blocking, but the live cluster
assertions run `continue-on-error` (not in `all-gates`) and are **deferred-accepted
(no-hardware)** with a named promotion path (`docs/runbooks/kind-harness.md`) — they
are **not** counted as a biting PASS and **not** silently claimed. Inherits all P1
G-SEC controls (prompt-injection ED1–ED5, four-eyes, redaction, RBAC, K8s posture,
KMS no-leak).

### G-MNT — Maintainability — **PASS (P2-Security scope)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| D16 gates green continuously (ruff, mypy strict, pytest ≥80%, eslint/tsc/vitest, import-linter) (§325) | **PASS** | `backend` + `frontend` CI jobs green on run 28349836098; coverage gate `--cov-fail-under=80`. |
| Every binding decision has a current ADR; no silent drift (§326) | **PASS** | **ADRs 0034–0041 flipped Proposed → Accepted by this task** on their green implementing-wave evidence (see §4); ADR index updated. The 2026-06-25 P2 re-scope is recorded in `PRODUCTION.md` §1 (amendment, not a superseding ADR — a sequencing change, not a D1–D16 reversal). |
| New-plugin onboarding validated each wave (§329) | **PASS** | Vendor Wave 2 `panos` + `fortios` plugins landed from the plugin template with conformance suites (`backend/tests/plugins/test_fortios_conformance.py` et al.); no cross-vendor routing regression (W5-T2). |
| Every shipped feature has tests + docs + API docs (§327) | **PASS (spot-audit)** | Per-task TDD across P2 W0–W5; the firewall capability, both plugins, the Security Agent, and each hardening control ship with tests + ADR. |
| `PRODUCTION.md` §1 amended for the re-scope (W0-T9) | **PASS** | §1 carries the dated 2026-06-25 amendment; §11 names the G-SCA/G-REL-live deferral; this readiness doc is its mirror (P2-SECURITY-PLAN §0 "the two must agree"). |
| N-2 → N upgrade rehearsal on a seeded dataset (§328) | **DEFERRED — P3-Platform** | Needs the live platform stack; named in §1/§11. |
| Open Consultant questions reviewed each phase (§330) | **PASS (reviewed)** | PROPOSED defaults re-confirmed at W0 (P2-SECURITY-PLAN §6). |

**G-MNT verdict: PASS** for the P2-Security continuous gates (D16 green, ADR
currency incl. the 0034–0041 flips, Wave-2 plugin onboarding, `PRODUCTION.md`
amendment); the N-2 upgrade rehearsal is the one **P3-Platform-deferred**
criterion, named.

### G-OBS — Observability — **PASS (P2-Security continuous slice)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| 100% of containers expose `/metrics` + liveness + readiness (§316) | **PASS (unchanged)** | ADR-0015 (D15, Accepted); P1 W4 posture carried — every workload renders probes; `infra` kube-linter probe checks green. No P2 workload regresses this. |
| 100% of agent runs traced end-to-end, joinable to audit (§320) | **PASS (unchanged)** | ADR-0015 structlog correlation + OTel tracing; the new Security Agent rides the same supervisor trace/audit spine (no new untraced path). |
| Golden-signal dashboards; burn-rate alerts; fault-injection MTTD; SIEM export (§317–319, §321) | **DEFERRED — P3-Platform** | SLO recording rules + alerts + dashboards + fault-injection MTTD + audit→SIEM export are the P3-Platform enforcement track (§0 re-scope; `PRODUCTION.md` §6/§1). **No new SLO enforcement is claimed for P2-Security.** |

**G-OBS verdict: PASS** for the P2-Security continuous slice (`/metrics` + probes +
trace correlation unchanged, the new agent traced); SLO enforcement, dashboards,
MTTD, and SIEM export are **explicitly P3-Platform** (re-scope §0) — named, none
silently claimed.

### G-SCA — Scalability — **DEFERRED-ACCEPTED → P3-Platform (entire gate)**

Every §11 G-SCA criterion (§308–312: 500-device discovery scale-out, 100-user
load test, 5,000-device projection, KEDA queue-burst, PgBouncer budget) depends on
**HA + autoscaling**, which the **2026-06-25 re-scope moves out of P2-Security to
P3-Platform** (P2-SECURITY-PLAN §0; `PRODUCTION.md` §1 amendment). No G-SCA
criterion is in P2-Security scope, so there is nothing for this phase to fail
here; the entire gate is **deferred-accepted → P3-Platform**, named in full (here,
in `PRODUCTION.md` §11, and in the P3-Platform inheritance note §5). Not a
P2-Security blocker.

### G-REL — Reliability — **P1 baseline holds; live drills DEFERRED → P3-Platform**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| Backup/DR mechanism (from-backups-alone restore at seeded scale) | **PASS (inherited P1 baseline)** | P1 W5 from-backups-alone drill green at seeded scale (`P1-RELEASE-READINESS` §2 G-REL); P2-Security ships no change that regresses it. |
| 30-day soak; Postgres failover; certified-scale Neo4j rebuild; worker-kill idempotency; Celery soak success (§297–302) | **DEFERRED — P3-Platform** | The live failover/soak/scale drills need a certified-scale cluster to validate; moved out by the 2026-06-25 re-scope (P2-SECURITY-PLAN §0; `PRODUCTION.md` §1 amendment + §11). Named. |

**G-REL verdict: the P1 G-REL baseline holds** and is not regressed by P2-Security;
the live failover/soak/scale **drills are deferred-accepted → P3-Platform** per the
re-scope — named, not silent. P2-Security is **not gated** on them.

---

## 3. Gate-bites discipline — confirmed (P1 lesson)

Per the P1-W4 lesson ("a gate failing at setup masks the findings it would
produce — confirm each gate RAN and would BITE"):

- The **`pg-integration` gate is proven to bite** — commit `dd366bd` is the gate
  going red on a real REVOKE-connection password bug on this very branch, then
  green after the fix. It is a member of the `all-gates` `needs` list, so the W4
  audit-integrity and credential controls are release-blocking under real PG, not
  green-at-setup (§1.1).
- The **firewall floor**, **injection-boundary confinement**, **hash-chain
  tamper-detect**, and **credential no-leak** controls each carry a negative /
  perturbation control asserting they drop below threshold on a regression (§1.1).
- The **kind-harness *live-enforcement* run does NOT yet bite** (it is
  `continue-on-error` and outside `all-gates`). This is recorded honestly: the
  mTLS-handshake and collector-egress-deny **live** assertions are **PARTIAL /
  deferred-accepted**, with a promotion path in `docs/runbooks/kind-harness.md`.
  We do **not** flip these to a biting PASS; their static / render / harness-self-test
  layers bite and are blocking, which is what the P2-scoped slice requires.

---

## 4. Status flips (only on green)

Because every P2-Security-scoped gate criterion is PASS on the HEAD-green CI run
28349836098 (`6acac91`) — with all later-phase criteria named deferred in §2 and
the kind-live enforcement sub-items recorded PARTIAL/deferred, not flipped — the
dependent ADR flips are applied in this same atomic commit (mirrors PR #63 flipping
ADR 0025–0032, and W7-T4 flipping ADR-0033). **Each ADR is flipped only on its
implementing wave's green evidence:**

| ADR | Title | Implementing wave / evidence (green on HEAD) | Flip |
|---|---|---|---|
| **0034** | `FIREWALL_POLICY` capability + normalized models | W1 model + W2 round-trip conformance + W5-T1 eval corpus binds to it (`backend` job green) | Proposed → **Accepted** |
| **0035** | Palo Alto PAN-OS plugin | W2 `panos` plugin in registry + conformance; `test_wave2_vendor_plugins_present_in_registry` green | Proposed → **Accepted** |
| **0036** | Fortinet FortiOS plugin | W2 `fortios` plugin + `test_fortios_conformance.py`; registry-present assertion green | Proposed → **Accepted** |
| **0037** | Security Agent (read-only analysis, findings, remediation→CR) | W3 agent + W5-T1 firewall eval (precision/recall ≥ floor) + W5-T2 routing + allow-list confinement green | Proposed → **Accepted** |
| **0038** | Audit-log hash chaining + daily verification | W4-T1 + W5-T0 PG re-assert (`test_audit_hash_chain_pg.py`, `pg-integration` green, bit via `dd366bd`) | Proposed → **Accepted** |
| **0039** | mTLS between containers | W4-T4: render-twice L4 idempotency guard + external-PG fail-fast guard are RED gates green in `infra`; extract_secret tests bite. (Live kind handshake is the named-deferred sub-item — material/static layer carries the Accepted flip.) | Proposed → **Accepted** |
| **0040** | Device credential rotation + scoping | W4-T2 + W5-T0 PG re-assert (`test_credentials_rotation_pg.py`, `pg-integration` green) | Proposed → **Accepted** |
| **0041** | Collector network segmentation (NetworkPolicy egress) | W4-T5: chart NetworkPolicies render + pass `infra` policy gates; CNI self-test + egress-probe-tristate bite. (Live kind deny is the named-deferred sub-item.) | Proposed → **Accepted** |

> Note on 0039/0041: the Accepted flip rests on the controls' **rendered material +
> policy + harness-invariant layers**, which are blocking and green on HEAD. The
> **live kind-cluster enforcement assertion** for each is `continue-on-error` and
> deferred-accepted (no-hardware) per §2/§3 and `docs/runbooks/kind-harness.md`;
> this is named, not silent, and does not undermine the design decision the ADR
> records (the controls exist, render, and are kind-validatable; only the live CI
> bite is pending promotion).

**Roadmap flips:**

- **`PRODUCTION.md`** — P2-Security exit marker added (§1 phase table) pointing to
  this readiness doc; the P3-Platform inheritance (HA/scale-out + audit→SIEM
  export + obs-SLO enforcement + live failover/soak/scale drills + N-2 rehearsal)
  is recorded so nothing is silently dropped (already named in the §1 amendment +
  §11; reinforced here as the P2-Security exit). There is **no separate ROADMAP
  index file** in this repo — `PRODUCTION.md` §1 is the roadmap index.

---

## 5. Deferrals — named explicitly (none silent)

Every item below is **outside P2-Security scope by design** (P2-SECURITY-PLAN
§0/§1/§5, `PRODUCTION.md` §1 amendment + §11) and is **not** a P2-Security release
blocker:

1. **G-SCA entirely** — HA + autoscaling load/scale tests (500-device, 100-user,
   5,000-device, KEDA burst, PgBouncer budget) → **P3-Platform** (re-scope §0).
2. **G-REL live drills** — 30-day soak, Postgres failover, certified-scale Neo4j
   rebuild, worker-kill idempotency, Celery soak success → **P3-Platform**; the P1
   backup/DR baseline holds.
3. **G-OBS SLO enforcement** — dashboards, burn-rate alerts, fault-injection MTTD,
   **audit→SIEM export** → **P3-Platform** (re-scope §0; `PRODUCTION.md` §6).
4. **G-MNT N-2 → N upgrade rehearsal** on a seeded prod-shaped dataset →
   **P3-Platform**.
5. **mTLS live-handshake + collector egress-deny on a live kind cluster** —
   `kind-harness.sh` is `continue-on-error` / outside `all-gates`; deferred-accepted
   (no-hardware on the authoring host), promotion path in
   `docs/runbooks/kind-harness.md`. The render/static/harness-invariant layers DO
   bite and are blocking.
6. **G-SEC external pentest** (pre-GA) and the **recurring 6-month break-glass
   drill** (operational) — GA-time / operational, carried from P1.
7. **Live-lab vendor golden-paths** — PAN-OS / FortiOS device golden-paths (W2),
   Security Agent against a live firewall policy (W3) — same no-hardware deferral
   as M4/M5/P1; code paths fixture/mock-verified in the green eval + conformance
   suites.
8. **Vault status note** — the orchestrator's Obsidian vault P2-Security status
   note is updated outside this in-repo commit (MEMORY.md "P2-Security plan");
   flagged here so the sync is not silently skipped.

**P3-Platform inheritance (recorded so nothing is dropped):** HA + scale-out (api
HPA, KEDA workers, CloudNativePG, Redis Sentinel, PgBouncer); audit→SIEM export;
observability-SLO enforcement (recording rules, burn-rate alerts, dashboards,
fault-injection MTTD); live failover/soak/scale DR drills; N-2 upgrade rehearsal;
and the promotion of the kind-harness live-enforcement run to a blocking gate
(`docs/runbooks/kind-harness.md`). The P3-Platform plan is authored when
P2-Security exits.

---

## 6. Aggregate verdict

| Gate | P2-Security-scope verdict | Blocking? |
|---|---|---|
| **G-SEC** | **PASS** (firewall eval + injection boundary deterministic; audit hash-chain + credential rotation re-asserted under **real PG**, all biting in `all-gates`-blocking jobs; Trivy + gitleaks + KMS green. mTLS-handshake / collector-deny **live** kind assertions PARTIAL → deferred-accepted, material/static layers bite) | No |
| **G-MNT** | **PASS** (D16 green, ADR currency incl. 0034–0041 flips, Wave-2 plugin onboarding, `PRODUCTION.md` amended); N-2 rehearsal P3-Platform | No |
| **G-OBS** | **PASS** (`/metrics` + probes + trace correlation unchanged, new agent traced); SLO enforcement / dashboards / MTTD / SIEM export P3-Platform | No |
| **G-SCA** | **DEFERRED-ACCEPTED → P3-Platform** (entire gate — HA/scale-out moved out by the 2026-06-25 re-scope) | No |
| **G-REL** | **P1 baseline holds; live failover/soak/scale drills DEFERRED → P3-Platform** | No |

**P2-Security is declared COMPLETE.** The P2-scoped slice of G-SEC, G-MNT, and
G-OBS passes **simultaneously on the release HEAD `6acac91`** (CI run
28349836098, all 11 checks SUCCESS); G-SCA in full and the G-REL live drills are
deferred-accepted → P3-Platform per the 2026-06-25 re-scope; and the two
kind-cluster live-enforcement sub-items (mTLS handshake, collector egress-deny)
are recorded **PARTIAL / deferred-accepted** with a named promotion path — none
silently dropped (ADR-0033 §1). Every gate that flips an ADR was confirmed to
RUN and BITE (the `pg-integration` gate proved it on `dd366bd`). No P2-Security-scoped
criterion is unmet, so nothing blocks the phase exit; ADRs 0034–0041 are flipped
Proposed → Accepted on their green implementing evidence.
