# T7 — Next-Session Handoff (resume the kind-harness gate promotion)

> **SUPERSEDED — DO NOT RESUME (2026-07-03, audit-W2 T7).** The kind-harness gate
> promotion is **REJECTED** (ADR-0048 Status: Rejected). The live harness cannot reach
> green without booting a slice of the whole platform in kind, and the two controls are
> already protected by BLOCKING static gates; the live `kind-harness` / `kind-harness-ha`
> jobs are now **opt-in** (label `ci-kind` / manual dispatch). The F4/F5 fixes + failure
> diagnostics this doc scoped WERE applied (they harden the opt-in signal-only harness);
> the §4 bite and the §2 promotion described below are **not to be executed**. Retained
> only as historical context — see ADR-0048 "Rejection" + `docs/runbooks/kind-harness.md`
> "Gate status".

Single source of truth for resuming the audit-W2 **T7** work. Full analysis:
`docs/production-audit-2026-07-01/T7-HARNESS-RECOVERY.md`. Memory: `[[t7-harness-recovery]]`.

## Where things stand

- **Branch:** `fix/t7-harness-recovery` · **PR #94** (open, NOT merged, NOT a promotion).
- **ADR-0048: HELD** (Status `Proposed`). Nothing promoted/merged.
- **Done + real:**
  - **F1** — removed invalid `spec.postgresql.runAsNonRoot` from the CNPG Cluster template +
    the `hardening.rego` rule that required it + 4 `cnpg_*` fixtures (`2390e88`). Verified.
  - **S1** — static CR-schema guard: vendored pinned CRDs (`ci/kind/crd-schemas/`) +
    `ci/kind/selftest/validate-cr-schemas{,-bite}.sh`, blocking in the `infra` job (`ed78e23`).
    Genuinely green (a required, non-continue-on-error job).
  - **F3** — `ci/kind/kind-harness.sh` residue check now tolerates `^Warning:` (`f9be281`).
    Verified: the P2 apply is tolerated and the harness reaches its assertions for the first time.
- **Open (harness NOT green — the live path has never passed end-to-end):**
  - **F4** — P2 `kind-harness` `outcome=failure`: the *positive* assertions fail (valid-cert
    mTLS handshake to `netops-postgres` fails; worker→`netops-postgres:5432` in-cluster egress
    is BLOCKED but should be allowed). Deny paths all pass. Likely NO readiness gate on the P2
    path (HA has `wait-ha-ready.sh`; P2 doesn't) → postgres not up when the positive probes run.
  - **F5** — HA `kind-harness-ha` still `chart apply FAILED`: the N6.1 good-apply grep pattern
    in `kind-harness.sh` omits the CNPG/KEDA CR kinds, so `cluster.postgresql.cnpg.io/…`,
    `pooler.postgresql.cnpg.io/…`, `scaledobject.keda.sh/…`, `triggerauthentication.keda.sh/…`
    (all successful applies) are counted as residue → fail-closed before the HA readiness gate.

## CRITICAL gotchas (do not repeat the earlier mistakes)

1. **Verify the report-step `outcome`, NEVER the step `conclusion`.** The harness live step is
   `continue-on-error`, so its REST `conclusion` is ALWAYS `success`. The real result is
   `outcome` (in the "Report kind harness outcome" step log: `outcome='…'`, or the
   `harness complete — all assertions passed` line). Checking `conclusion` caused a false-green
   this session. Also confirm the assertions actually **RAN** (not `SKIP:` — checks skip loudly
   when their control object is absent).
2. **kind CANNOT run on the Windows authoring host (L1).** The live harness is CI-only. Local
   tooling present: `helm`, `conftest`, `kube-linter`, `python3+PyYAML`, `curl`, `kubectl`. You
   CAN: render (`helm template`), strict-validate CRs (`ci/kind/selftest/validate-cr-schemas.py`),
   run `run-cnpg-bite.sh` / `validate-ha-overlay.sh`, and simulate the residue pipeline locally.
3. **CI triggers = `push:[main]` + `pull_request` only (no `workflow_dispatch`).** A branch
   needs the PR (#94) to run CI. `gh run rerun --job <id>` re-runs a job; a single-job rerun may
   advance the whole run's attempt.
4. **The §4 bite plants are security-weakening** (plaintext pg_hba + broadened egress). Pushing
   them is blocked by the safety classifier → needs explicit user authorization each time.
5. **`git ls-files --eol`** for blob line endings, NOT `git show | grep $'\r'` (unreliable on
   Git-for-Windows; autocrlf=true normalizes to LF in the blob → Linux CI is fine).

## Remaining work, in order

1. **F5 (easy).** Add the CNPG/KEDA CR kinds to the good-apply grep pattern in
   `ci/kind/kind-harness.sh` (the `residue="$(... | grep -vE '^(configmap|…)…')"` line):
   `cluster.postgresql.cnpg.io`, `pooler.postgresql.cnpg.io`, `scaledobject.keda.sh`,
   `triggerauthentication.keda.sh`. (Watch the `[^ ]* (created|configured|unchanged|
   serverside-applied)$` suffix — CR names have no dot before `/`, so the existing shape works.)
   Confirm `validate-harness.sh` still passes (it asserts *presence* of the subtractive/residue
   patterns, not exact count).
2. **F4 (needs diagnosis).** Root-cause the P2 positive-assertion failures. First hypothesis:
   the P2 path applies the chart then runs assertions with no wait — add a readiness wait for
   postgres (and the api/worker) before the assertion-runner on the P2 path, mirroring
   `wait-ha-ready.sh` but for the single-instance tier. Rule out cert-material (dev-fallback
   mTLS secret) + the in-cluster-egress NetworkPolicy actually permitting worker→postgres.
   Confirm the fix by reading the assertion output (valid handshake PASS, in-cluster egress PASS).
3. **Verify green (via `outcome`).** Re-run CI. Confirm BOTH `kind-harness` and `kind-harness-ha`
   report `outcome=success` AND the mtls + collector assertions PASSED (not skipped), across
   ≥2 consecutive runs. Only a genuine green here satisfies ADR-0048 §3 Prerequisite A.
4. **§4 bite (needs user auth to push the plants).** Plant the two P2 controls — pg_hba plaintext
   `host all all 0.0.0.0/0 scram-sha-256` line (`postgres-tls-configmap.yaml`) + collector egress
   `1.1.1.1/32` + port `53` (`values.yaml`) — from `git stash@{0}` ("audit-w2 T7 planted
   violations") or recreate. Confirm the **ASSERTION** goes RED (`assert_handshake_refused` /
   `assert_egress_blocked` fail in the harness log — NOT the apply), revert, confirm GREEN.
   Record the two run URLs / planted→reverted commit pair.
5. **Promote (ADR-0048 §2 — two edits).** In `.github/workflows/ci.yml`: (a) drop
   `continue-on-error: true` on the "Run kind harness" step (`id: harness`, ~ln 1198); (b) add
   `kind-harness` to the `all-gates` `needs:` list (~ln 2109) + update the PROMOTION-HELD comment
   block (~ln 2078). Then flip ADR-0048 (`docs/adr/0048-…`) Status → `Accepted` + record the bite;
   update `docs/runbooks/kind-harness.md` "Gate status" + "Prove-it-bites" to past tense with the
   run URLs; update RCA §8. Re-run CI; confirm all-gates green WITH kind-harness now blocking.

## Note

The plant (`8d20ca4`) + its revert (`b42b407`) are in the branch history (net-zero; safe on
squash-merge). The stash `stash@{0}` also has a 3rd plant (64Gi Sentinel → `wait-ha-ready` RED)
for the HA-readiness gate — NOT part of the ADR-0048 §2 promotion scope (P2 mTLS + egress only).
