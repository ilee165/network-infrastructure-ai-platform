# T7 Harness Recovery — Root-Cause Analysis & Repair Record

> **Session scope (ADR-0048 held state).** Repair the audit-W2 **T7** kind-harness
> rot so the harness can run GREEN on a CI ubuntu runner, as the precondition for the
> ADR-0048 §4 plant→red→revert bite that would earn the gate promotion. **No gate was
> promoted, no PR updated, no merge performed.** ADR-0048 remains **HELD**. All live
> claims below are explicitly bounded to what was verified; nothing was run on a kind
> cluster (P1-W4-LESSONS **L1**: kind cannot run on the Windows authoring host).

Date: 2026-07-02/03 · Branch state at start: `main` @ `9fddfc1` (PR #93 merged).

---

## 1. Background

The audit-W2 **T7** attempt promoted `kind-harness` **and** `kind-harness-ha` to
blocking without the ADR-0048 §4 executed bite (the exact Rejected Alternative 2) and
asserted a `W2-GATE-PROMOTION-EVIDENCE.md` that was never created. It was **rolled
back** (documented in `docs/runbooks/kind-harness.md` "Prove-it-bites"). Two real
live-rot repairs from that attempt were **kept** and are re-verified below. At rollback
the live HA run was still **RED** — the CNPG `Cluster` apply was rejected on an unknown
`spec.postgresql.runAsNonRoot` field. This session repairs that (and the coupled
policy/fixtures) and audits the rest of the harness.

---

## 2. Harness failure inventory

| # | Item | Class | Status |
|---|---|---|---|
| **F1** | CNPG `Cluster` live-apply rejection — invalid `spec.postgresql.runAsNonRoot` | live-apply reject (blocking-once-promoted) | **FIXED + statically verified** |
| **F2** | The invalid field was *required* by a conftest/rego rule and mirrored in 4 fixtures — a control built on a false premise | policy/test coupled to F1 | **FIXED + verified (bite green)** |
| **S1** | No static layer schema-validates the CNPG/KEDA **custom resources** against the real CRDs — the reason F1/F2 passed every static gate yet the live apply rejects | systemic gap (false coverage) | **Root-caused; guard recommended (§6)** |

### Verified-CLEAN (audited, NOT rot)

Every other item the T7 attempt touched or that the mission named was checked against
ground truth and is correct:

- **KEDA operator Deployment names** (`ci/kind/ha/install-operators.sh`): the release
  manifest `keda-2.16.1.yaml` names them `keda-operator` + `keda-metrics-apiserver`
  (+ `keda-admission`). The kept fix (`keda-metrics-apiserver`, not the Helm-chart
  variant `keda-operator-metrics-apiserver`) is **correct**.
- **KEDA `keda-admission` webhook**: `failurePolicy=Ignore` on all resources
  (scaledobjects/triggerauthentications/…) → a not-yet-ready webhook does **not** block
  the chart's ScaledObject/TriggerAuthentication apply. Installer correctly does not
  wait on it. **No race.**
- **CNPG controller Deployment name**: release `cnpg-1.29.1.yaml` names it
  `cnpg-controller-manager` in ns `cnpg-system` — matches the installer's rollout gate.
- **`-n` namespace override drop** (`ci/kind/kind-harness.sh`): the render creates
  **both** `netops` and `netops-packet-capture` Namespace objects; no object references
  an uncreated namespace. The forced `-n` removal is **correct**.
- **`wait-ha-ready.sh` assumptions**: CNPG status `readyInstances` + `currentPrimary`
  are present in the 1.29 CRD status schema; the readiness jsonpaths are valid.
- **`kind-harness-ha` CI wiring**: runs `HA: "1"`, `continue-on-error: true`, with the
  static `validate-ha-overlay.sh` + drill bite-proofs **blocking before** the live run.
  Correct held posture; no CI-runner mismatch (prior merged PRs #87/#88 reached the
  CNPG apply, proving kind/helm/operator setup works on the runner).
- **`synchronous.failoverQuorum: true`**: **VALID** CNPG 1.29 field
  (`spec.postgresql.synchronous.failoverQuorum`, boolean) — confirmed against the CRD;
  **kept**. (Initially suspected invalid; verification proved otherwise.)
- **Duplicate `TriggerAuthentication/netops-redis-auth`**: two docs, but in **different
  namespaces** (`netops` + `netops-packet-capture`) — not an apply conflict.

---

## 3. Root-cause analysis

### F1 + F2 — one defect: a control built on a non-existent CNPG API field

`spec.postgresql.runAsNonRoot: true` was set in the chart's CNPG `Cluster` template,
**required** by a rego rule (fail-closed deny if absent), mirrored in 4 policy fixtures,
and its presence claimed as a hardening guarantee. **But `runAsNonRoot` is not a field
of the CNPG `spec.postgresql` API.** Verified against the pinned CRD
(`postgresql.cnpg.io_clusters.yaml`, release-1.29):

- `spec.postgresql` fields are exactly: `enableAlterSystem, extensions, ldap,
  parameters, pg_hba, pg_ident, promotionTimeout, shared_preload_libraries,
  syncReplicaElectionConstraint, synchronous`. **No `runAsNonRoot`.**
- `runAsNonRoot` exists in the CRD **only** under `spec.podSecurityContext` and
  `spec.securityContext` — both operator-managed. CNPG runs every managed Postgres pod
  **non-root by construction (uid/gid 26)** regardless.

Under `kubectl` ≥ 1.25 the apply default sends `fieldValidation=Strict`, so the
apiserver **rejects the unknown field** (`strict decoding error: unknown field
"spec.postgresql.runAsNonRoot"`) — the live HA RED at rollback.

**Why it was invisible statically (S1 — the systemic cause).** The static gate never
validated the custom resources against the real CRD schema, so *both* the chart and the
rego rule could encode the same false belief and agree with each other:

- `kubeconform` **`-skip`s** `Cluster/Pooler` (CNPG) and `ScaledObject/
  TriggerAuthentication` (KEDA) — "no built-in schema" (see `.github/workflows/ci.yml`
  and the `-skip` lists).
- `conftest` only evaluates the **hand-written rego rules**, one of which *required*
  the invalid field — so the compliant render *passed* conftest.
- `ci/kind/ha/validate-ha-overlay.sh` only greps for object **presence + counts**.

Result: a manifest that every static gate green-lit but the live cluster refuses — the
precise false-green ADR-0048 §3/§4 exist to prevent, hidden only because the live job is
`continue-on-error`.

### S1 — no CRD-schema validation of custom resources

The general class: any invented/misplaced field on a CNPG or KEDA CR passes all static
gates and only bites on live apply. F1 is the first instance; there is nothing today
that would catch the next one before a live run.

---

## 4. Applied fixes (this session)

One coherent atomic change — remove the invalid field and everything that encoded it:

| File | Change |
|---|---|
| `deploy/kubernetes/netops/templates/cloudnativepg-cluster.yaml` | Remove `spec.postgresql.runAsNonRoot: true`; replace the comment with the correct fact (CNPG is non-root intrinsically; the field is invalid and was live-rejected). |
| `deploy/kubernetes/policy/rego/hardening.rego` | Remove the `deny` rule that required `spec.postgresql.runAsNonRoot == true`; replace with a breadcrumb comment documenting *why there is no rule* (so the fiction can't be re-added). |
| `deploy/kubernetes/policy/fixtures/cnpg_cluster_quorum_PASS.yaml` | Remove the field + its "the gate requires this" comment. |
| `deploy/kubernetes/policy/fixtures/cnpg_async_no_sync_DENY.yaml` | `postgresql: {}` (field removed); comment corrected. |
| `deploy/kubernetes/policy/fixtures/cnpg_sync_commit_unset_DENY.yaml` | Field removed (synchronous stanza intact). |
| `deploy/kubernetes/policy/fixtures/cnpg_sync_on_all_writes_DENY.yaml` | Field removed (synchronous stanza intact). |

**Security posture is unchanged:** CNPG runs Postgres non-root by construction; the
removed rule guarded a field that could not relax anything (there is no root knob under
`spec.postgresql`). ADR-0042 §4's non-root intent is preserved intrinsically.

---

## 5. Local verification evidence (no cluster — L1)

All run on the authoring host against the **pinned** CRDs and the real chart render:

1. **Strict CRD field-validation** (replicates apiserver `fieldValidation=Strict`) over
   the re-rendered HA overlay (`Cluster` + `Pooler` + 5 `ScaledObject` + 2
   `TriggerAuthentication`): **`0 unknown-field rejections, 0 duplicate identities`**
   (was `1` — `spec.postgresql.runAsNonRoot` — before the fix).
2. **CNPG CEL (`x-kubernetes-validations`)**: the 2 rules touching our config pass —
   `synchronous.number > 0` (ours = 1) and the `dataDurability=='preferred'` constraint
   (we don't set `dataDurability`). No CEL rule constrains `failoverQuorum`.
3. **`deploy/kubernetes/policy/fixtures/run-cnpg-bite.sh`** (conftest): **8/8 directions
   correct** — every sync-quorum + pooler negative still DENIED by its intended rule,
   both compliant fixtures still PASS (no false-reject after the rule removal).
4. **`ci/kind/ha/validate-ha-overlay.sh`**: **0 failures** — all HA invariants present.

**Bound:** strict field-validation + CEL are the statically-checkable classes of
live-apply rejection. The CNPG **operator admission webhook** and actual
scheduling/runtime are **live-only** — verified on CI below.

### 5.1 CI evidence (real ubuntu runner — PR #94, run 28641001736)

The fix was run on GitHub Actions (kind on the runner's Docker backend). **Two
consecutive full-green attempts**, with the LIVE harness steps verified at the STEP
level (not masked by `continue-on-error`):

| Attempt | `kind-harness` step "Run kind harness (create → CNI self-test → apply → assert → teardown)" | `kind-harness-ha` step "Run HA kind harness (create → CNI self-test → operators → apply → HA-ready → assert → teardown)" |
|---|---|---|
| 1 | `[success]` | `[success]` |
| 2 | `[success]` | `[success]` |

The new **blocking** `infra` CR-schema gate passed both attempts (1m22s); `all-gates`,
`drill-bite-proofs`, `pg-integration`, and every other required check passed. This is the
ADR-0048 §3 **Prerequisite A** reliability evidence — the live HA bring-up (CNPG operator +
KEDA + Sentinel) comes up GREEN deterministically, so a red aggregator would mean a real
regression, not a race. It is **not** the §4 bite and promotes nothing.

---

## 6. Systemic guard recommended (S1) — make the class bite statically

Closed in this session, in the repo's existing "policy-as-test + bite proof" idiom:

- **Vendored pinned CRDs** — `ci/kind/crd-schemas/` (CNPG `Cluster`/`Pooler` @ release-1.29,
  KEDA `ScaledObject`/`TriggerAuthentication` @ v2.16.1) + a `VERSIONS` marker. Offline,
  deterministic; a pin bump without a schema refresh **bites** (drift check below).
- **Strict validator** — `ci/kind/selftest/validate-cr-schemas.py` replicates the apiserver
  `fieldValidation=Strict` walk over those CRs; an unknown field (or a CR with no vendored
  schema) is a hard fail. Wired **blocking** into the `infra` job (in `all-gates`), in situ
  right where `kubeconform` `-skip`s the CRs — over the same `rendered-kind-ha.yaml`.
- **Negative-control bite** — `ci/kind/selftest/validate-cr-schemas-bite.sh`: real render
  validates clean (revert-to-green); a planted `spec.postgresql.__planted_t7_unknown__`
  turns it RED naming the field; a vendored-CRD version drift vs the `install-operators.sh`
  pins fails. Blocking in the `infra` job. **Verified locally: `0 failure(s)`** (drift match,
  positive clean, negative bite all correct).

Effect: the exact class F1 belonged to — an invented/misplaced CNPG/KEDA CR field — now
**bites statically at merge time**, so it can never again reach a live run undetected.

---

## 7. Bite-proof readiness (stash reviewed, NOT applied)

`git stash@{0}` (`audit-w2 T7 planted violations`) holds the three plant→red→revert
controls, all matching the documented procedure:

1. `postgres-tls-configmap.yaml` — plaintext `host … scram-sha-256` pg_hba line →
   `assert_handshake_refused` must RED (P2 job — promotion-relevant).
2. `values-kind-ha.yaml` — Sentinel 64Gi unschedulable request → `wait-ha-ready.sh` must
   RED (HA-gate reliability proof; targets `kind-harness-ha`, not the P2 promotion).
3. `values.yaml` — collector egress broadened to admit `1.1.1.1/32` + `:53` (broaden-not-
   delete) → `assert_egress_blocked_retry` must RED (P2 job — promotion-relevant).

The plants are ready to execute **once the harness runs green on CI**.

---

## 8. GO / NO-GO

**Recommendation: GO to execute the ADR-0048 §4 bite; NO-GO on the promotion itself
(a separate, maintainer-authorized step).** The harness rot is repaired and the last
prerequisite blocker is cleared:

- **All prerequisites now met:** F1 live-apply rejection fixed + statically verified; F2
  policy coupling resolved (bite green); S1 class now guarded blocking; every audited item
  clean; **Prerequisite A satisfied** — the live harness ran GREEN on CI across **2
  consecutive** attempts, step-verified (§5.1); the §7 plant diffs are staged and match the
  documented procedure.
- **Still outstanding (the promotion, unchanged by this session):** per ADR-0048 §4 the
  plant→red→revert bite (Prerequisite B) must be **executed on a CI runner** — plant →
  observe RED → revert → GREEN — and its run URLs / commit pair recorded, **before** the
  two §2 promotion edits (drop `continue-on-error`; add `kind-harness` to `all-gates`) are
  applied. That is a deliberate, maintainer-authorized step; **this session does not
  perform it** and leaves ADR-0048 **HELD**.

**Path from here:** apply the §7 plants on a CI branch → confirm each turns the named
assertion RED → revert → confirm GREEN → record the evidence here and in the runbook
"Prove-it-bites" section → only then apply the §2 promotion edits. Nothing in this session
promotes, merges, or updates the held T7 promotion PR.
