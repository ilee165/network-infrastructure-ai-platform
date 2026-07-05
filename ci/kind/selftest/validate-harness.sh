#!/usr/bin/env bash
# Static validator for the W4-T3 kind harness (the policy-as-test "bite").
#
# This is the exit-criteria guard that does NOT need a live cluster: it asserts
# the harness ARTIFACTS carry every load-bearing invariant ADR-0039 §6 /
# ADR-0041 §2/§3 + P1-W4-LESSONS L1/L3/L5 mandate. Removing any invariant (the
# enforcing CNI install, disableDefaultCNI, the self-test failure-on-no-block,
# pipefail on pipes, the teardown trap, the runner's non-zero-on-failure
# contract) makes a check below FAIL — so this validator BITES if the harness is
# silently weakened.
#
# Run: ci/kind/selftest/validate-harness.sh   (exits non-zero on any violation)
# CI:  the `kind-harness` job runs this on every push (it needs no cluster).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"

CONFIG="${KIND_DIR}/kind-config.yaml"
HARNESS="${KIND_DIR}/kind-harness.sh"
RUNNER="${KIND_DIR}/assertions/run-assertions.sh"
LIB="${KIND_DIR}/assertions/lib.sh"
DENY="${KIND_DIR}/cni-selftest/default-deny.yaml"
PROBE="${KIND_DIR}/cni-selftest/probe.yaml"
CHECKS_DIR="${KIND_DIR}/assertions/checks"
# P3 W4-T1 HA add-on artifacts (the reduced-scale HA topology the W4 drills run on).
HA_DIR="${KIND_DIR}/ha"
HA_INSTALL="${HA_DIR}/install-operators.sh"
HA_WAIT="${HA_DIR}/wait-ha-ready.sh"
HA_VALIDATE="${HA_DIR}/validate-ha-overlay.sh"
HA_OVERLAY="$(cd "${KIND_DIR}/../.." && pwd)/deploy/kubernetes/netops/values-kind-ha.yaml"

fails=0
ok()   { echo "PASS: $*"; }
bad()  { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

# require_file <path> <description>
require_file() {
  if [ -f "$1" ]; then ok "$2 present ($1)"; else bad "$2 MISSING ($1)"; fi
}

# grep_must <file> <regex> <description>
grep_must() {
  if grep -Eq "$2" "$1"; then ok "$3"; else bad "$3 — pattern not found: $2"; fi
}

# grep_must_not <file> <regex> <description>
grep_must_not() {
  if grep -Eq "$2" "$1"; then bad "$3 — forbidden pattern found: $2"; else ok "$3"; fi
}

echo "== validating W4-T3 kind harness artifacts =="

# --- all artifacts exist -----------------------------------------------------
require_file "${CONFIG}"  "kind config"
require_file "${HARNESS}" "harness script"
require_file "${RUNNER}"  "assertion-runner"
require_file "${LIB}"     "assertion helper lib"
require_file "${DENY}"    "CNI self-test default-deny policy"
require_file "${PROBE}"   "CNI self-test probe pod"
if [ -d "${CHECKS_DIR}" ]; then ok "assertion checks dir present (T4/T5 plug-in)"; \
  else bad "assertion checks dir MISSING (${CHECKS_DIR})"; fi

# --- ADR-0041 §2: enforcing CNI, default CNI disabled ------------------------
grep_must "${CONFIG}" "disableDefaultCNI:[[:space:]]*true" \
  "kind config disables the default (non-enforcing) CNI (ADR-0041 §2)"
grep_must "${HARNESS}" "calico" \
  "harness installs an enforcing CNI — Calico (ADR-0041 §2)"
grep_must "${HARNESS}" "rollout status daemonset/calico-node" \
  "harness WAITS for the enforcing CNI to be Ready before proceeding"

# --- ADR-0041 §2: the CNI self-test BITES (default-deny must block) ----------
# The default-deny policy must be a real deny: Egress policyType with NO egress
# allow rules (an `egress:` rule list would punch a hole and make it not a deny).
grep_must "${DENY}" "policyTypes" \
  "self-test default-deny declares policyTypes (it is a real policy)"
grep_must "${DENY}" "Egress" \
  "self-test default-deny denies Egress (the W4-T5 control under test)"
grep_must_not "${DENY}" "^[[:space:]]*egress:" \
  "self-test default-deny carries NO egress allow rule (it is a true deny floor)"
# The harness must FAIL the run when the post-deny egress is NOT blocked — the
# load-bearing enforcement bite (kindnet would leave it reachable).
grep_must "${HARNESS}" "CNI SELF-TEST FAILED" \
  "harness FAILS the run if default-deny does not block egress (ADR-0041 §2 / L1)"
grep_must "${HARNESS}" 'blocked.*-ne 1' \
  "harness gates on the egress being BLOCKED, not merely on the policy applying"
# The self-test must run BEFORE the assertion-runner (assertions never trust an
# unproven CNI). Verify ordering by source position.
# N8: make the grep pipelines NON-FATAL. Under `set -e` a no-match grep exits 1
# and (via the `$( … | head | cut )` substitution) would abort the validator early
# instead of recording a violation via the `fails` accumulator. `|| true` lets the
# explicit `if` below decide pass/fail on the (possibly empty) captured values.
selftest_line="$(grep -n 'CNI self-test PASSED' "${HARNESS}" | head -1 | cut -d: -f1 || true)"
runner_line="$(grep -n 'bash "${ASSERT_RUNNER}"' "${HARNESS}" | head -1 | cut -d: -f1 || true)"
if [ -n "${selftest_line}" ] && [ -n "${runner_line}" ] && \
   [ "${selftest_line}" -lt "${runner_line}" ]; then
  ok "CNI self-test runs BEFORE the assertion-runner (assertions never trust an unproven CNI)"
else
  bad "CNI self-test must precede the assertion-runner (self-test=${selftest_line:-?} runner=${runner_line:-?})"
fi

# --- N6: chart apply fails on UNEXPECTED errors, only downgrades missing CRDs --
# A blanket `kubectl apply … || { warning }` lets a broken Deployment/Secret/
# NetworkPolicy apply slide and runs assertions against an incomplete chart
# (false-green). The harness must (a) match the specific optional-CRD-missing
# error text and (b) have a HARD `exit 1` for anything else.
grep_must "${HARNESS}" 'no matches for kind|unable to recognize' \
  "harness only tolerates the SPECIFIC optional-CRD-missing apply error text (N6)"
grep_must "${HARNESS}" 'refusing to run assertions against it' \
  "harness HARD-FAILS the run on a non-CRD chart-apply error (incomplete chart = false-green) (N6)"
# It must NOT swallow every apply failure into a bare warning-only block.
grep_must_not "${HARNESS}" 'kubectl apply -n "\$\{CHART_NS\}" -f "\$\{RENDERED\}" \|\| \{' \
  "harness does NOT blanket-catch ALL chart-apply failures into a warning (N6)"

# --- N6.1 (#15): the apply-failed else branch is FAIL-CLOSED ------------------
# The prior else branch grepped FOR a fixed set of error patterns and only failed
# on a POSITIVELY identified "unexpected" line; an apply error matching NONE of
# those patterns left the match empty and FELL THROUGH to the warning + assertions
# (fail-open). The fix inverts the logic: it SUBTRACTS the accountable lines
# (successful-apply object outputs + the tolerated CRD-missing class) from the
# WHOLE log and HARD-FAILS on ANY residue. Assert that inversion is in place so a
# regression back to the positive-grep (fail-open) form trips this validator.
#
# (a) the residue is computed from the WHOLE apply log via a SUBTRACTIVE pipeline
#     that strips successful-apply object lines, NOT a positive `grep -E` FOR error
#     patterns. The successful-apply allow-list line is the load-bearing marker.
grep_must "${HARNESS}" 'created\|configured\|unchanged\|serverside-applied' \
  "harness else branch SUBTRACTS successful-apply lines from the whole log (fail-closed residue), not a positive grep FOR errors (N6.1/#15)"
grep_must "${HARNESS}" 'residue=' \
  "harness computes a fail-closed 'residue' of unaccounted-for apply-log lines (N6.1/#15)"
# (b) a NON-EMPTY residue HARD-FAILS — the only fall-through to the warning is an
#     EMPTY residue (every line accounted for). Assert the residue gates exit 1.
grep_must "${HARNESS}" 'if \[ -n "\$\{residue\}" \]; then' \
  "harness HARD-FAILS when the residue is non-empty (fail-closed; an unmatched apply error cannot fall through) (N6.1/#15)"
# (c) the OLD fail-open form (collecting err_lines then testing 'unexpected') must
#     be GONE — its presence would mean the positive-grep fall-through is back.
grep_must_not "${HARNESS}" 'unexpected="\$\(printf' \
  "harness no longer uses the positive-grep 'unexpected' collection that fell through on an unmatched error (N6.1/#15)"

# --- ephemerality: teardown on ANY exit (trap / always) ----------------------
grep_must "${HARNESS}" "trap teardown EXIT" \
  "harness tears down the cluster on EVERY exit via a trap (no leaked clusters)"
grep_must "${HARNESS}" "kind delete cluster" \
  "teardown actually deletes the kind cluster"

# --- L5: pipefail + test -s on the render/assert pipes -----------------------
grep_must "${HARNESS}" "set -o pipefail" \
  "harness sets pipefail so a piped render/exec exit is not masked (L5)"
grep_must "${HARNESS}" 'test -s "\$\{RENDERED\}"' \
  "harness guards an empty chart render with test -s (L5)"
grep_must "${RUNNER}" "set -euo pipefail" \
  "assertion-runner sets pipefail (L5)"
# N7: a SINGLE strict pattern for the negated form `[ ! -s "${log}" ]`. The old
# 3-way alternation also matched a bare `-s "${log}"` (e.g. a POSITIVE `test -s`
# doing the opposite check), so it was too permissive — a runner that dropped the
# empty-log guard but kept some other `-s "${log}"` would still pass. Pin the
# negated test exactly.
grep_must "${RUNNER}" '\[ ! -s "\$\{log\}" \]' \
  "assertion-runner guards an empty (silent no-op) check log via [ ! -s \"\${log}\" ] (L5)"

# --- L3: no $(VAR) interpolated into an in-pod exec argv ----------------------
# The harness drives exec via `sh -c '… "$1" …' _ "${VAR}"` — assert it uses the
# sh -c positional-arg form and never an exec with a bare $(VAR) substitution.
grep_must "${HARNESS}" "sh -c 'nc -z" \
  "harness probes egress via sh -c with positional args, not \$(VAR) in argv (L3)"

# --- runner contract: NON-ZERO exit on any failed check ----------------------
grep_must "${RUNNER}" 'run_failures.*-ne 0' \
  "assertion-runner exits non-zero when any check fails (the bite)"
grep_must "${RUNNER}" "exit 1" \
  "assertion-runner has a non-zero exit path"

# --- assert_failures path BITES: lib.sh trap + runner opt-out -----------------
# A check runs in its own subprocess, so the runner can only see its EXIT status.
# lib.sh must install an EXIT trap that turns a recorded ASSERT_FAIL into a
# non-zero exit (otherwise the documented "leave a non-zero assert_failures" path
# is a false contract and a conforming T5 deny check would ship false-green).
grep_must "${LIB}" "trap _assert_exit_trap EXIT" \
  "lib.sh installs an EXIT trap so a recorded assert_failures bites (no false-green)"
grep_must "${LIB}" 'exit "\$\{ASSERT_FAIL\}"' \
  "lib.sh's trap exits with the accumulated assert-failure count"
# The runner sources lib.sh but owns its OWN exit code, so it must opt OUT of the
# trap; assert the opt-out is wired so the runner's run_failures stays authoritative.
grep_must "${RUNNER}" "ASSERT_LIB_NO_TRAP=1" \
  "assertion-runner opts out of lib.sh's EXIT trap (runner owns its exit code)"
# N5: the opt-out is the RUNNER's alone — it must NOT leak into the per-check
# subprocesses (a child inheriting it would be disarmed → false-green). The runner
# must (a) never `export` the opt-out and (b) strip it from the child env with
# `env -u ASSERT_LIB_NO_TRAP` when invoking each check.
grep_must_not "${RUNNER}" "export[[:space:]]+ASSERT_LIB_NO_TRAP" \
  "assertion-runner does NOT export ASSERT_LIB_NO_TRAP (it must not leak into child checks) (N5)"
grep_must "${RUNNER}" 'env -u ASSERT_LIB_NO_TRAP bash "\$\{check\}"' \
  "assertion-runner strips ASSERT_LIB_NO_TRAP from each child check so its bite stays armed (N5)"
grep_must "${LIB}" 'ASSERT_LIB_NO_TRAP' \
  "lib.sh honours the ASSERT_LIB_NO_TRAP opt-out (so the runner can suppress the trap)"

# --- N1: cleanup must COMPOSE with the trap, never CLOBBER it ------------------
# lib.sh must provide register_cleanup AND its assert-exit trap must run the
# registered cleanups (otherwise a check needing teardown is forced back to a bare
# `trap cleanup EXIT`, which bash makes the ONLY EXIT trap — clobbering the
# assert-fail bite → false-green). The empirical proof is assert-trap-bite.sh; this
# static guard keeps the wiring from silently regressing.
grep_must "${LIB}" 'register_cleanup\(\)' \
  "lib.sh provides register_cleanup so checks compose teardown with the assert-exit trap (N1)"
grep_must "${LIB}" '_run_registered_cleanups' \
  "lib.sh's assert-exit trap runs the registered cleanups before deciding the exit status (N1)"
# No check under checks/ may install its OWN `trap … EXIT` — that clobbers lib.sh's
# assert-exit trap (bash keeps only the last EXIT trap). Checks MUST use
# register_cleanup. Scan every check; a single offender is a false-green hazard.
if [ -d "${CHECKS_DIR}" ]; then
  # Match an ACTUAL `trap <fn> EXIT` statement, not a comment mentioning one.
  # `grep -v '^[[:space:]]*#'` drops comment lines before the trap match; -l lists
  # files that still have a real offender.
  trap_offenders=""
  for _chk in "${CHECKS_DIR}"/*.sh; do
    [ -f "${_chk}" ] || continue
    if grep -v '^[[:space:]]*#' "${_chk}" | grep -Eq 'trap[[:space:]]+([^[:space:]#]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT'; then
      trap_offenders="${trap_offenders} ${_chk}"
    fi
  done
  trap_offenders="${trap_offenders# }"
  if [ -z "${trap_offenders}" ]; then
    ok "no check installs its own 'trap … EXIT' (would clobber lib.sh's assert-exit trap; use register_cleanup) (N1)"
  else
    bad "check(s) install a bare 'trap … EXIT' which clobbers lib.sh's assert-fail bite — use register_cleanup: ${trap_offenders//$'\n'/ } (N1)"
  fi
fi
# The two teardown-needing checks must register their cleanup (positive assertion).
for chk in "${CHECKS_DIR}/collector-egress.sh" "${CHECKS_DIR}/mtls-postgres.sh"; do
  if [ -f "${chk}" ]; then
    grep_must "${chk}" 'register_cleanup' \
      "${chk##*/} registers its probe-pod teardown via register_cleanup (not a clobbering EXIT trap) (N1)"
  fi
done

# --- lib provides the T4 + T5 primitives -------------------------------------
grep_must "${LIB}" "assert_egress_blocked" \
  "lib provides assert_egress_blocked (W4-T5 deny bite)"
grep_must "${LIB}" "assert_handshake_refused" \
  "lib provides assert_handshake_refused (W4-T4 plaintext-refusal bite)"

# --- W4-T4 mTLS check is present + carries the refusal bite -------------------
# The T4 handshake/refusal assertion plugs into this runner. Assert the check +
# its probe pod exist and that the check proves the REFUSAL (plaintext + wrong-CA),
# not merely a working TLS path — so deleting the bite fails this static validator.
MTLS_CHECK="${CHECKS_DIR}/mtls-postgres.sh"
MTLS_PROBE="${CHECKS_DIR}/mtls-postgres-probe.yaml"
require_file "${MTLS_CHECK}" "W4-T4 mTLS handshake assertion check"
require_file "${MTLS_PROBE}" "W4-T4 mTLS probe pod manifest"
grep_must "${MTLS_CHECK}" "assert_handshake_ok" \
  "mTLS check asserts the valid-cert client HANDSHAKES (ADR-0039 §6)"
grep_must "${MTLS_CHECK}" "assert_handshake_refused .*plaintext" \
  "mTLS check asserts a PLAINTEXT client is REFUSED (ADR-0039 §3/§6 bite)"
grep_must "${MTLS_CHECK}" "assert_handshake_refused .*wrong-CA" \
  "mTLS check asserts a WRONG-CA client is REFUSED (ADR-0039 §3/§6 bite)"
grep_must "${MTLS_CHECK}" "sslmode=disable" \
  "mTLS plaintext case actually disables TLS (sslmode=disable) so the refusal is real"
# N11: the DB password must be fed over STDIN (`kubectl exec -i` + `read … PGPASSWORD`),
# never as a positional `sh -c` argv arg (argv is visible in the pod process list).
grep_must "${MTLS_CHECK}" 'exec -i' \
  "mTLS check feeds the DB password over stdin (kubectl exec -i), not argv (N11)"
grep_must "${MTLS_CHECK}" 'read -r PGPASSWORD' \
  "mTLS check reads PGPASSWORD from stdin inside the pod (not a visible argv arg) (N11)"
grep_must_not "${MTLS_CHECK}" '_ "\$\{PG_HOST\}".*"\$\{PGPASSWORD_VALUE\}"' \
  "mTLS check does NOT pass PGPASSWORD_VALUE as a positional sh -c argv arg (process-list leak) (N11)"
# L3: the in-pod psql params are positional `sh -c` args, never \$(VAR) in argv.
grep_must "${MTLS_CHECK}" "sh -c" \
  "mTLS check drives in-pod psql via sh -c positional args, not \$(VAR) in argv (L3)"
# The probe pod must be restricted-PSA admissible (non-root) and mount the client
# cert read-only (ADR-0039 §5) — never a :latest image (admission rejects it).
grep_must "${MTLS_PROBE}" "runAsNonRoot: true" \
  "mTLS probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must "${MTLS_PROBE}" "readOnly: true" \
  "mTLS probe pod mounts the client cert read-only (ADR-0039 §5)"
grep_must_not "${MTLS_PROBE}" "image:.*:latest" \
  "no :latest image tag in the mTLS probe pod (admission would reject)"

# --- W4-T5 collector egress check is present + carries the allow/deny bite -----
# The T5 deny assertion plugs into this runner. Assert the check + its probe pod
# exist and that the check proves BOTH polarities — an allowed (named-service)
# egress SUCCEEDS and an arbitrary external egress is BLOCKED (the deterministic
# deny bite, ADR-0041 §3) — so deleting the bite fails this static validator.
COLLECTOR_CHECK="${CHECKS_DIR}/collector-egress.sh"
COLLECTOR_PROBE="${CHECKS_DIR}/collector-egress-probe.yaml"
require_file "${COLLECTOR_CHECK}" "W4-T5 collector egress assertion check"
require_file "${COLLECTOR_PROBE}" "W4-T5 collector egress probe pod manifest"
grep_must "${COLLECTOR_CHECK}" "assert_egress_allowed" \
  "collector check asserts an allowed (named-service) egress SUCCEEDS (ADR-0041 §3)"
grep_must "${COLLECTOR_CHECK}" "assert_egress_blocked" \
  "collector check asserts an arbitrary external egress is BLOCKED (ADR-0041 §3 deny bite)"
# The deny target must be an EXTERNAL destination (not the mgmt subnet / a named
# service), or the "blocked" assertion proves nothing. The harness probe target
# (1.1.1.1) is the same external class the CNI self-test proved is blockable.
grep_must "${COLLECTOR_CHECK}" "DENY_HOST" \
  "collector check denies an external destination distinct from the allowed target"
# The check must SKIP loudly (never silently pass) if the collector policy is
# absent — a missing control read as a pass is a false-green.
grep_must "${COLLECTOR_CHECK}" "SKIP:" \
  "collector check SKIPS loudly (not false-green) when the mgmt-egress policy is absent"
# L3: the in-pod probe is driven via lib.sh's sh -c positional-arg helper, never a
# \$(VAR) exec argv — assert the check uses the assert_* helpers (which do this).
grep_must "${COLLECTOR_CHECK}" 'lib\.sh' \
  "collector check sources lib.sh (uses the pipe-safe, L3-safe assert_* helpers)"
# The probe pod must carry the WORKER labels so the default-deny floor + the §2
# worker-egress allow + the W4-T5 collector mgmt-egress policy all select it.
grep_must "${COLLECTOR_PROBE}" "app.kubernetes.io/component: worker" \
  "collector probe pod carries the worker labels (every worker policy selects it; ADR-0041 §1)"
grep_must "${COLLECTOR_PROBE}" "runAsNonRoot: true" \
  "collector probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must_not "${COLLECTOR_PROBE}" "image:.*:latest" \
  "no :latest image tag in the collector probe pod (admission would reject)"

# --- no `latest` image anywhere (admission would reject; chart parity) -------
for f in "${PROBE}"; do
  grep_must_not "${f}" "image:.*:latest" "no :latest image tag in ${f##*/} (admission would reject)"
done

# --- N12: probe images pinned by sha256 digest (a bare tag is mutable) --------
# Every probe pod image must carry an @sha256: digest so a re-push of the tag
# cannot silently swap the probe image out from under the harness.
for f in "${PROBE}" "${MTLS_PROBE}" "${COLLECTOR_PROBE}"; do
  if [ -f "${f}" ]; then
    grep_must "${f}" 'image:.*@sha256:[0-9a-f]{64}' \
      "${f##*/} pins its probe image by sha256 digest, not a mutable tag (N12)"
  fi
done

# --- P3 W4-T1: ephemeral HA topology add-on invariants (ADR-0047 / ADR-0048 §3) --
# The HA path (HA=1) EXTENDS this same harness with the CNPG operator + KEDA + the
# reduced-scale HA overlay, WITHOUT disturbing the P2 CNI self-test / mTLS /
# collector assertions above. These static checks assert the HA artifacts exist
# and carry every load-bearing property (pinned operators, idempotent+retried
# install, readiness gating so a half-up cluster is not "ready" (L5), and the P2
# assertions stay composed). Removing any makes a check FAIL — this validator
# BITES on a silently weakened HA path just as it does on the P2 path.
echo "== validating W4-T1 HA topology add-on artifacts =="

require_file "${HA_INSTALL}"   "HA operator installer (CNPG + KEDA)"
require_file "${HA_WAIT}"       "HA readiness gate"
require_file "${HA_VALIDATE}"   "HA overlay static validator"
require_file "${HA_OVERLAY}"    "reduced-scale HA values overlay"

# The harness must expose an HA=1 path that COMPOSES the operators + overlay onto
# the existing P2 run (not a fork). Assert the harness references each HA piece.
grep_must "${HARNESS}" 'HA="\$\{HA:-0\}"' \
  "harness gates the HA add-on behind HA=1 (default OFF — P2 behaviour unchanged when off)"
grep_must "${HARNESS}" 'bash "\$\{HA_INSTALL_OPERATORS\}"' \
  "harness installs the HA operators (CNPG + KEDA) when HA=1, before the chart apply"
grep_must "${HARNESS}" 'bash "\$\{HA_WAIT_READY\}"' \
  "harness gates on HA readiness when HA=1, before running assertions (L5 — no half-up ready)"
grep_must "${HARNESS}" '\-f "\$\{HA_VALUES\}"' \
  "harness layers the reduced-scale HA overlay via helm -f when HA=1"

# --- audit-W2 T7 F4: non-HA readiness gate + deterministic drill tier gate --------
# The promotion-scope P2 (non-HA) assertions dial netops-postgres:5432 (the W4-T4
# mTLS handshake + the W4-T5 worker->pg ALLOW-egress) and MUST run against a READY
# Postgres; and the HA-only reliability/scale drills MUST skip on the P2 run
# DETERMINISTICALLY (not by pod-timing luck). Both regressed the live harness to red
# before F4; lock them — this gate is being promoted to blocking (ADR-0048 §2).
grep_must "${HARNESS}" 'if \[ "\$\{HA\}" != "1" \]; then' \
  "harness runs the non-HA readiness branch only when HA!=1 (the HA path uses wait-ha-ready) (F4)"
grep_must "${HARNESS}" 'rollout status "statefulset/\$\{PG_STS\}"' \
  "harness gates the NON-HA path on Postgres StatefulSet readiness BEFORE the G-SEC assertions (F4)"
grep_must "${HARNESS}" 'export ASSERT_LOG_DIR CHART_NS SELFTEST_NS PROBE_HOST PROBE_PORT HA' \
  "harness EXPORTS HA to the assertion-runner so the HA-only drills gate on it deterministically (F4)"
# Every HA-only drill SKIPS unless HA=1 — a uniform, timing-independent tier gate (a
# check that keyed off incidental workload PRESENCE fell through on the P2 tier).
for _ha_drill in pg-failover neo4j-rebuild worker-kill-idempotency queue-burst-load compressed-soak n2-upgrade-rehearsal; do
  grep_must "${CHECKS_DIR}/${_ha_drill}.sh" 'if \[ "\$\{HA:-0\}" != "1" \]; then' \
    "HA-only drill ${_ha_drill}.sh SKIPS unless HA=1 (deterministic tier gate, F4)"
done
# The 2 G-SEC checks assert on BOTH tiers (P2 + HA) and must NOT carry the HA gate.
grep_must_not "${CHECKS_DIR}/mtls-postgres.sh" 'HA:-0' \
  "the W4-T4 mTLS G-SEC check is NOT HA-gated (it asserts on BOTH the P2 and HA tiers) (F4)"
grep_must_not "${CHECKS_DIR}/collector-egress.sh" 'HA:-0' \
  "the W4-T5 collector-egress G-SEC check is NOT HA-gated (it asserts on BOTH tiers) (F4)"
# The HA operator install must run AFTER the CNI self-test passes (HA does not
# weaken the enforcing-CNI guarantee) and BEFORE the chart apply (CRDs first).
selftest_pass_line="$(grep -n 'CNI self-test PASSED' "${HARNESS}" | head -1 | cut -d: -f1 || true)"
ha_install_line="$(grep -n 'bash "${HA_INSTALL_OPERATORS}"' "${HARNESS}" | head -1 | cut -d: -f1 || true)"
apply_line="$(grep -n 'rendering netops chart' "${HARNESS}" | head -1 | cut -d: -f1 || true)"
if [ -n "${selftest_pass_line}" ] && [ -n "${ha_install_line}" ] && [ -n "${apply_line}" ] && \
   [ "${selftest_pass_line}" -lt "${ha_install_line}" ] && [ "${ha_install_line}" -lt "${apply_line}" ]; then
  ok "HA operator install runs AFTER the CNI self-test and BEFORE the chart render (CRDs-first ordering)"
else
  bad "HA operator install must be between the CNI self-test and the chart render (selftest=${selftest_pass_line:-?} install=${ha_install_line:-?} render=${apply_line:-?})"
fi

# --- pinned operators, NEVER `latest` (matches the Calico pin discipline) ------
grep_must "${HA_INSTALL}" 'CNPG_VERSION="\$\{CNPG_VERSION:-[0-9]' \
  "HA installer pins the CloudNativePG operator version (never latest)"
grep_must "${HA_INSTALL}" 'KEDA_VERSION="\$\{KEDA_VERSION:-[0-9]' \
  "HA installer pins the KEDA version (never latest)"
grep_must_not "${HA_INSTALL}" 'cnpg-latest\.yaml|keda-latest\.yaml|:latest' \
  "HA installer references NO :latest / -latest operator manifest"

# --- idempotent + retried + fail-closed operator install (L5) -----------------
grep_must "${HA_INSTALL}" 'apply --server-side --force-conflicts' \
  "HA installer applies operators server-side (idempotent + re-appliable, --force-conflicts)"
grep_must "${HA_INSTALL}" 'set -euo pipefail' \
  "HA installer sets pipefail (a masked fetch/apply exit cannot read green) (L5)"
grep_must "${HA_INSTALL}" 'test -s "\$\{manifest\}"' \
  "HA installer guards an EMPTY/truncated operator manifest with test -s (L5 fail-closed)"
grep_must "${HA_INSTALL}" 'wait --for=condition=Established' \
  "HA installer waits for the operator CRDs to be Established before any CR is applied (no CRD race)"
grep_must "${HA_INSTALL}" 'rollout status deployment/cnpg-controller-manager' \
  "HA installer gates on the CNPG controller being Ready (webhook up) before Cluster apply"
grep_must "${HA_INSTALL}" 'rollout status deployment/keda-operator' \
  "HA installer gates on the KEDA operator being Ready before ScaledObject apply"

# --- HA readiness gate: a HALF-UP topology must NOT read ready (L5) ------------
grep_must "${HA_WAIT}" 'set -euo pipefail' \
  "HA readiness gate sets pipefail (a masked kubectl read cannot read green) (L5)"
grep_must "${HA_WAIT}" 'readyInstances' \
  "HA readiness gate asserts the FULL CNPG instance count is ready (not primary-only) (ADR-0042 §1)"
grep_must "${HA_WAIT}" 'currentPrimary' \
  "HA readiness gate requires a CNPG primary to be elected (a writable primary exists)"
grep_must "${HA_WAIT}" 'rollout status "\$\{sts\}"' \
  "HA readiness gate waits for the Redis+Sentinel StatefulSets to be fully rolled out"
grep_must "${HA_WAIT}" 'type=="Ready"' \
  "HA readiness gate asserts each KEDA ScaledObject reconciled Ready (not a vacuous per-queue substrate)"
grep_must "${HA_WAIT}" 'must not read ready' \
  "HA readiness gate HARD-FAILS a half-up topology (the ADR-0048 §3 reliability prerequisite)"

# --- L3: no $(VAR) in an exec argv in the HA scripts (they drive kubectl/helm) --
# The HA scripts do not exec into pods; assert they contain no `$(VAR)` inside an
# `sh -c` argv (the L3 hazard). A plain grep for the dangerous form.
grep_must_not "${HA_INSTALL}" "sh -c '.*\\\$\\(" \
  "HA installer has no \$(VAR) interpolated into an sh -c exec argv (L3)"
grep_must_not "${HA_WAIT}" "sh -c '.*\\\$\\(" \
  "HA readiness gate has no \$(VAR) interpolated into an sh -c exec argv (L3)"

# --- reduced-scale COUNTS are STATED in the overlay (a scale drift BITES) ------
# The HA overlay must carry the ADR-0047 §1 posture: the reduced counts are named.
# CNPG 1+2 (instances: 3), Redis+Sentinel 3, api HPA floor 2.
grep_must "${HA_OVERLAY}" 'instances: 3' \
  "HA overlay declares CNPG instances: 3 (1 primary + 2 replicas — quorum minimum, ADR-0042 §1)"
grep_must "${HA_OVERLAY}" 'minReplicas: 2' \
  "HA overlay keeps the api HPA floor at 2 (HA floor never reduced, ADR-0043 §1)"
grep_must "${HA_OVERLAY}" 'replicas: 3' \
  "HA overlay declares Redis/Sentinel replicas: 3 (Sentinel quorum minimum, ADR-0044 §1)"
# MUTUAL EXCLUSION: the SINGLE-INSTANCE postgres/redis tiers are disabled. Scope to
# `services.<tier>.enabled` SPECIFICALLY — a bare `grep 'enabled: false'` false-greens
# on ANY unrelated disabled flag in the overlay (e.g.
# services.api.autoscaling.requestRate.enabled: false). Match a 2-space `<tier>:`
# header immediately followed (within 2 lines) by a 4-space `enabled: false`.
for _tier in postgres redis; do
  if grep -E "^  ${_tier}:$" -A2 "${HA_OVERLAY}" | grep -Eq '^    enabled: false$'; then
    ok "HA overlay disables the single-instance ${_tier} tier (services.${_tier}.enabled: false — mutual exclusion)"
  else
    bad "HA overlay does NOT set services.${_tier}.enabled: false (mutual exclusion NOT verified)"
  fi
done

# --- P3 W4-T3: Postgres failover drill invariants (G-REL §316, ADR-0042/0047) --
# The failover drill (pg-failover.sh) plugs into the HA assertion-runner. This
# validator BITES if the drill is silently weakened: it must (a) actually KILL the
# primary and measure the RTO FROM THE KILL (not from detection), (b) assert the
# ≤60s automated-promotion RTO, (c) assert ZERO committed-audit loss on the
# promoted primary (COUNT + specific last row + no seq gap + hash-chain valid),
# (d) SKIP loudly on a non-HA run (never false-green), (e) ship + wire the
# negative-control bite, and (f) keep the L3/L5 CI-plumbing guards. Removing any
# makes a check below FAIL.
echo "== validating W4-T3 Postgres failover drill artifacts =="

PG_FAILOVER_CHECK="${CHECKS_DIR}/pg-failover.sh"
PG_FAILOVER_PROBE="${CHECKS_DIR}/pg-failover-drill-probe.yaml"
PG_FAILOVER_BITE="${HERE}/pg-failover-bite.sh"
require_file "${PG_FAILOVER_CHECK}" "W4-T3 Postgres failover drill check"
require_file "${PG_FAILOVER_PROBE}" "W4-T3 failover drill probe pod manifest"
require_file "${PG_FAILOVER_BITE}"  "W4-T3 failover drill negative-control bite proof (self-test)"

# (a) it actually KILLS the primary + starts the RTO clock AT the kill (§316: RTO
#     from kill, not from detection — the risk the spec calls out).
grep_must "${PG_FAILOVER_CHECK}" 'delete pod .*--force .*--grace-period=0' \
  "failover drill force-KILLS the current primary (not a graceful drain) — a real failover trigger"
grep_must "${PG_FAILOVER_CHECK}" 'KILL_EPOCH=' \
  "failover drill starts the RTO clock (KILL_EPOCH) — the measurement anchor"
grep_must "${PG_FAILOVER_CHECK}" 'KILL_EPOCH="\$\(date \+%s\)"' \
  "failover drill measures RTO FROM THE KILL, not from detection (§316 risk the spec names)"
grep_must "${PG_FAILOVER_CHECK}" 'currentPrimary' \
  "failover drill reads the CNPG currentPrimary (targets the real primary; detects promotion)"
# (b) the ≤60s automated-promotion RTO assertion.
grep_must "${PG_FAILOVER_CHECK}" 'RTO_BUDGET_S' \
  "failover drill asserts the write-restore RTO against a budget (≤60s, G-REL §316)"
grep_must "${PG_FAILOVER_CHECK}" 'RTO_S.*-le.*RTO_BUDGET_S|RTO_S" -le "\$\{RTO_BUDGET_S' \
  "failover drill PASSES only when RTO <= budget and FAILS when it exceeds it (the RTO bite)"
grep_must "${PG_FAILOVER_CHECK}" 'now_primary.*!=.*PRIMARY_BEFORE|!= "\$\{PRIMARY_BEFORE' \
  "failover drill requires an AUTOMATED promotion (new primary differs from the killed pod), not the old one answering"
# (c) ZERO committed-audit loss on the promoted primary — all four sub-assertions.
grep_must "${PG_FAILOVER_CHECK}" 'zero-loss VIOLATED|committed-audit LOSS' \
  "failover drill asserts ZERO committed-audit loss on the promoted primary (G-REL §316)"
grep_must "${PG_FAILOVER_CHECK}" 'seq GAP' \
  "failover drill asserts NO seq gap on the promoted primary (no mid-chain committed row lost, ADR-0038 §3)"
grep_must "${PG_FAILOVER_CHECK}" 'hash-chain BREAK|hash-chain VALID' \
  "failover drill asserts the surviving audit hash-chain is intact (ADR-0038 §1)"
grep_must "${PG_FAILOVER_CHECK}" 'last-before-kill' \
  "failover drill commits + then checks the specific last-before-kill row (the row the negative control loses)"
# (d) real-PG only + SKIP loudly on a non-HA run (never false-green).
grep_must "${PG_FAILOVER_CHECK}" 'SKIP:' \
  "failover drill SKIPS LOUDLY when no CNPG Cluster is present (a missing cluster is never a false-green pass)"
# Guard against a real SQLite CODE path (a driver / connection string / db file),
# not the header comment that EXPLAINS why there is none. Match the driver/URL
# forms an actual SQLite fallback would use, so the ADR-0047 §5 rationale comment
# (which names "SQLite") does not false-trip this invariant.
grep_must_not "${PG_FAILOVER_CHECK}" 'sqlite://|aiosqlite|\.sqlite|:memory:|sqlite3 ' \
  "failover drill has NO SQLite code path — the audit-survival check runs on real PG only (ADR-0047 §5)"
# (e) the negative control is SHIPPED + wired, and PROVEN to bite by the self-test.
grep_must "${PG_FAILOVER_CHECK}" 'PG_FAILOVER_DRILL_NEGATIVE_CONTROL' \
  "failover drill ships the negative control (async/non-quorum commit) as a toggle (ADR-0047 §2)"
grep_must "${PG_FAILOVER_CHECK}" 'synchronous_commit = off|synchronous_commit=off' \
  "failover drill's negative control commits the last row ASYNC (synchronous_commit=off) so it can be lost (ADR-0047 §2)"
grep_must "${PG_FAILOVER_CHECK}" 'synchronous_commit = remote_apply|remote_apply' \
  "failover drill's positive path commits the audit row QUORUM-SYNC (remote_apply, ADR-0042 §2)"
grep_must "${PG_FAILOVER_BITE}" 'PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1' \
  "failover bite proof runs the drill WITH the negative control and asserts it goes RED"
grep_must "${PG_FAILOVER_BITE}" 'FALSE-GREEN' \
  "failover bite proof fails if the negative control does NOT turn the drill red (the anti-false-green guard)"
# (f) secret hygiene + L3/L5 plumbing (audit spine + DB superuser is secret surface).
grep_must "${PG_FAILOVER_CHECK}" 'exec -i' \
  "failover drill feeds the DB password over stdin (kubectl exec -i), not argv (secret hygiene / N11)"
grep_must "${PG_FAILOVER_CHECK}" 'read -r PGPASSWORD|read -r PGPASSWORD' \
  "failover drill reads PGPASSWORD from stdin inside the pod (never a visible argv arg)"
grep_must "${PG_FAILOVER_CHECK}" 'sh -c' \
  "failover drill drives in-pod psql via sh -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${PG_FAILOVER_CHECK}" 'set -euo pipefail' \
  "failover drill sets pipefail so a masked in-pod psql exit cannot read green (L5)"
grep_must "${PG_FAILOVER_CHECK}" 'register_cleanup' \
  "failover drill registers its probe-pod + drill-table teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${PG_FAILOVER_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "failover drill installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must "${PG_FAILOVER_CHECK}" 'reduced scale|deferred-accepted' \
  "failover drill STATES its reduced scale + names the deferred certified-scale ceiling (ADR-0047 §1/§4)"
# probe pod hygiene: non-root, digest-pinned, no :latest, no API token.
grep_must "${PG_FAILOVER_PROBE}" 'runAsNonRoot: true' \
  "failover drill probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must "${PG_FAILOVER_PROBE}" 'image:.*@sha256:[0-9a-f]{64}' \
  "failover drill probe pod pins its image by sha256 digest, not a mutable tag (N12)"
grep_must_not "${PG_FAILOVER_PROBE}" 'image:.*:latest' \
  "no :latest image tag in the failover drill probe pod (admission would reject)"
grep_must "${PG_FAILOVER_PROBE}" 'automountServiceAccountToken: false' \
  "failover drill probe pod drops its API token (least privilege, ADR-0029 §5)"

# --- P3 W4-T4: Neo4j destroy-and-rebuild drill invariants (G-REL §317, -----------
# --- ADR-0005 D5, ADR-0030 §1, ADR-0047 §2/§3) ----------------------------------
# The rebuild drill (neo4j-rebuild.sh) plugs into the HA assertion-runner. This
# validator BITES if the drill is silently weakened: it must (a) actually DESTROY
# Neo4j (pod + data PVC) and time the rebuild FROM the destroy, (b) rebuild FROM
# POSTGRES via the W1-T3 auto-rebuild path (NOT a Neo4j dump — the D5 guarantee),
# (c) assert COMPLETENESS (rebuilt counts == the Postgres source of record) and the
# MEASURED topology-RTO budget, (d) SKIP loudly on a no-Neo4j run (never
# false-green), (e) ship + wire the negative-control bite (disabled rebuild →
# mismatch → red), proven by the self-test, and (f) keep the L3/L5 + secret-hygiene
# guards. Removing any makes a check below FAIL.
echo "== validating W4-T4 Neo4j rebuild drill artifacts =="

NEO4J_REBUILD_CHECK="${CHECKS_DIR}/neo4j-rebuild.sh"
NEO4J_REBUILD_HELPER="${CHECKS_DIR}/topology_counts.py"
NEO4J_REBUILD_BITE="${HERE}/neo4j-rebuild-bite.sh"
require_file "${NEO4J_REBUILD_CHECK}"  "W4-T4 Neo4j rebuild drill check"
require_file "${NEO4J_REBUILD_HELPER}" "W4-T4 topology count helper (pg-source / neo4j-graph / seed)"
require_file "${NEO4J_REBUILD_BITE}"   "W4-T4 Neo4j rebuild drill negative-control bite proof (self-test)"

# (a) it actually DESTROYS Neo4j (data PVC + pod) and times the rebuild FROM destroy.
grep_must "${NEO4J_REBUILD_CHECK}" 'delete pvc' \
  "rebuild drill DESTROYS the Neo4j data PVC (a real projection loss, not a graceful restart)"
grep_must "${NEO4J_REBUILD_CHECK}" 'delete pod .*--force .*--grace-period=0' \
  "rebuild drill force-deletes the Neo4j pod so the StatefulSet recreates it EMPTY"
grep_must "${NEO4J_REBUILD_CHECK}" 'DESTROY_EPOCH=' \
  "rebuild drill starts the topology-RTO clock at the destroy (the measurement anchor)"
# (b) it rebuilds FROM POSTGRES via the W1-T3 auto-rebuild path — NOT a Neo4j dump.
grep_must "${NEO4J_REBUILD_CHECK}" 'app\.engines\.topology\.auto_rebuild' \
  "rebuild drill re-projects via the W1-T3 auto-rebuild path (app.engines.topology.auto_rebuild → full_rebuild)"
grep_must "${NEO4J_REBUILD_CHECK}" 'source of record' \
  "rebuild drill rebuilds FROM the Postgres source of record (D5), not a Neo4j dump"
grep_must_not "${NEO4J_REBUILD_CHECK}" 'neo4j-admin (dump|restore|load)|\.dump' \
  "rebuild drill does NOT restore a Neo4j dump — DR is a re-projection from Postgres (ADR-0005 D5)"
# (c) COMPLETENESS (counts == Postgres source) + the MEASURED topology-RTO budget.
grep_must "${NEO4J_REBUILD_CHECK}" 'pg-source' \
  "rebuild drill computes the Postgres source-of-record counts (the completeness obligation, D5)"
grep_must "${NEO4J_REBUILD_CHECK}" 'neo4j-graph' \
  "rebuild drill counts the LIVE re-projected Neo4j graph (what the rebuild actually wrote)"
grep_must "${NEO4J_REBUILD_CHECK}" 'does NOT match the Postgres source|MATCHES the Postgres source' \
  "rebuild drill asserts the rebuilt counts MATCH the Postgres source (a partial rebuild FAILS — G-REL §317)"
grep_must "${NEO4J_REBUILD_CHECK}" 'RTO_BUDGET_S' \
  "rebuild drill asserts the rebuild wall-clock against the (reduced-scale) topology-RTO budget"
grep_must "${NEO4J_REBUILD_CHECK}" 'RTO_S.*-le.*RTO_BUDGET_S|RTO_S" -le "\$\{RTO_BUDGET_S' \
  "rebuild drill PASSES only when RTO <= budget and FAILS when it exceeds it (the RTO bite)"
grep_must "${NEO4J_REBUILD_CHECK}" '\$\(date \+%s\) - DESTROY_EPOCH' \
  "rebuild drill records the MEASURED reduced-scale rebuild time (it becomes the topology-RTO, ADR-0047 §3)"
# The completeness helper must be REAL-PG only (ADR-0047 §5) — no SQLite path.
grep_must "${NEO4J_REBUILD_HELPER}" 'requires real PostgreSQL' \
  "topology count helper HARD-FAILS on a non-postgresql URL (real-PG only, ADR-0047 §5)"
grep_must_not "${NEO4J_REBUILD_HELPER}" 'sqlite://|aiosqlite|:memory:|\.sqlite' \
  "topology count helper has NO SQLite code path (the rebuild-from-relational-source semantics need real PG, ADR-0047 §5)"
grep_must "${NEO4J_REBUILD_HELPER}" 'derive_topology' \
  "topology count helper derives the source counts from Postgres via the real projection derivation (D5)"
grep_must "${NEO4J_REBUILD_HELPER}" 'PROJECTED_NODE_LABELS' \
  "topology count helper scopes the live Neo4j count to the projector's label set (comparable to the source)"
# (d) SKIP loudly on a no-Neo4j run (never false-green).
grep_must "${NEO4J_REBUILD_CHECK}" 'SKIP:' \
  "rebuild drill SKIPS LOUDLY when no Neo4j StatefulSet is present (a missing store is never a false-green pass)"
# (e) the negative control is SHIPPED + wired, and PROVEN to bite by the self-test.
grep_must "${NEO4J_REBUILD_CHECK}" 'NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL' \
  "rebuild drill ships the negative control (disabled rebuild) as a toggle (ADR-0047 §2)"
grep_must "${NEO4J_REBUILD_CHECK}" 'rebuild is DISABLED|the reconcile step is skipped|reconcile skipped' \
  "rebuild drill's negative control DISABLES the rebuild so the graph is not re-projected (ADR-0047 §2)"
grep_must "${NEO4J_REBUILD_BITE}" 'NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL=1' \
  "rebuild bite proof runs the drill WITH the negative control and asserts it goes RED"
grep_must "${NEO4J_REBUILD_BITE}" 'FALSE-GREEN' \
  "rebuild bite proof fails if the negative control does NOT turn the drill red (the anti-false-green guard)"
# (f) secret hygiene + L3/L5 plumbing (topology projection touches DB + Neo4j creds).
grep_must "${NEO4J_REBUILD_CHECK}" 'sh -c' \
  "rebuild drill drives in-pod python via sh -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${NEO4J_REBUILD_CHECK}" 'set -euo pipefail' \
  "rebuild drill sets pipefail so a masked in-pod exit cannot read green (L5)"
grep_must "${NEO4J_REBUILD_CHECK}" 'register_cleanup' \
  "rebuild drill registers its teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${NEO4J_REBUILD_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "rebuild drill installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must_not "${NEO4J_REBUILD_CHECK}" 'NETOPS_NEO4J_PASSWORD=.*echo|echo.*NETOPS_NEO4J_PASSWORD|echo.*NETOPS_POSTGRES_PASSWORD' \
  "rebuild drill never echoes the Neo4j / Postgres password (secret hygiene)"
grep_must "${NEO4J_REBUILD_CHECK}" 'reduced scale|deferred-accepted' \
  "rebuild drill STATES its reduced scale + names the deferred certified-scale ceiling (ADR-0047 §1/§4)"

# --- P3 W4-T5: worker-kill idempotency + Celery ≥99% drill invariants -----------
# --- (G-REL §319/§320, ADR-0008 acks_late, ADR-0020 four-eyes, ADR-0047 §2/§3/§5) -
# The worker-kill drill (worker-kill-idempotency.sh) plugs into the HA assertion-
# runner. This validator BITES if the drill is silently weakened: it must (a)
# actually KILL a worker pod mid-run (a real node-loss trigger, not a graceful
# drain), (b) assert EXACTLY-ONCE side effects on the redelivery (1 snapshot / 1
# audit row / 1 CR execution transition — no duplicate), (c) assert Celery success
# ≥ 99% over the window AND that the CR four-eyes gate (ADR-0020) is not bypassed on
# retry, (d) assert on REAL PG only (no SQLite path — ADR-0047 §5), (e) SKIP loudly
# on a no-worker run (never false-green), (f) ship + wire the negative-control bite
# (idempotency guard off → double-write → red), proven by the self-test, and (g)
# keep the L3/L5 + secret-hygiene guards. Removing any makes a check below FAIL.
echo "== validating W4-T5 worker-kill idempotency drill artifacts =="

WORKER_KILL_CHECK="${CHECKS_DIR}/worker-kill-idempotency.sh"
WORKER_KILL_HELPER="${CHECKS_DIR}/worker_idem_probe.py"
WORKER_KILL_BITE="${HERE}/worker-kill-idempotency-bite.sh"
require_file "${WORKER_KILL_CHECK}"  "W4-T5 worker-kill idempotency drill check"
require_file "${WORKER_KILL_HELPER}" "W4-T5 worker idempotency probe helper (capture / cr-retry / backup / rate)"
require_file "${WORKER_KILL_BITE}"   "W4-T5 worker-kill drill negative-control bite proof (self-test)"

# (a) it actually KILLS a worker pod MID-RUN (a real node-loss trigger — acks_late
#     redelivery, ADR-0008 §5 — not a graceful drain).
grep_must "${WORKER_KILL_CHECK}" 'delete pod .*--force .*--grace-period=0' \
  "worker-kill drill force-KILLS a worker pod mid-run (a real node-loss trigger, not a graceful drain)"
grep_must "${WORKER_KILL_CHECK}" 'acks_late|reject_on_worker_lost|redeliver' \
  "worker-kill drill exercises the acks_late redelivery (ADR-0008 §5 — a killed worker's task is re-run)"
# (b) EXACTLY-ONCE side effects on the redelivery (no duplicate DB write / audit row).
grep_must "${WORKER_KILL_CHECK}" 'EXACTLY-ONCE' \
  "worker-kill drill asserts the redelivery is EXACTLY-ONCE (no duplicate side effect, G-REL §319)"
grep_must "${WORKER_KILL_CHECK}" 'DUPLICATED a side effect|no duplicate side effect' \
  "worker-kill drill FAILS on a duplicated side effect (a double DB write / double audit row — G-REL §319)"
grep_must "${WORKER_KILL_CHECK}" 'snapshots.*= .1.|CAP_SNAP.*=.*1|= "1" \] && \[ "\$\{CAP_AUD' \
  "worker-kill drill asserts exactly 1 snapshot row + 1 audit row on the config-capture redelivery"
# (c) Celery success ≥ 99% AND four-eyes not bypassed / not double-executed.
grep_must "${WORKER_KILL_CHECK}" 'SUCCESS_FLOOR' \
  "worker-kill drill asserts the Celery success rate against a floor (≥99%, G-REL §320)"
grep_must "${WORKER_KILL_CHECK}" 'RATE_PCT.*-ge.*SUCCESS_FLOOR|RATE_PCT" -ge "\$\{SUCCESS_FLOOR' \
  "worker-kill drill PASSES only when success >= 99% and FAILS below it (the ≥99% bite, G-REL §320)"
grep_must "${WORKER_KILL_CHECK}" '\[ "\$\{CR_APPR\}" = "1" \]' \
  "worker-kill drill asserts the CR four-eyes gate (ADR-0020) is not bypassed on retry"
grep_must "${WORKER_KILL_CHECK}" 'double-execute|double-execut|DOUBLE-EXECUTED' \
  "worker-kill drill asserts the retried CR does NOT double-execute (ADR-0020 / G-REL §319)"
grep_must "${WORKER_KILL_CHECK}" 'cr-retry' \
  "worker-kill drill drives the CR execution-retry primitive (approved→executing twice)"
# (d) real-PG only (ADR-0047 §5) — no SQLite CODE path (the driver/URL forms, not
#     the rationale comment which names SQLite).
grep_must "${WORKER_KILL_HELPER}" 'requires real PostgreSQL' \
  "worker idempotency probe HARD-FAILS on a non-postgresql URL (real-PG only, ADR-0047 §5)"
grep_must_not "${WORKER_KILL_HELPER}" 'sqlite://|aiosqlite|:memory:|\.sqlite' \
  "worker idempotency probe has NO SQLite code path (the write-lock/isolation semantics need real PG, ADR-0047 §5)"
grep_must "${WORKER_KILL_HELPER}" 'capture_snapshot|_persist|ChangeRequestService|_nightly_backup_core' \
  "worker idempotency probe drives the REAL W2-T4 code path (config._persist / ChangeRequestService / nightly_backup)"
# (e) SKIP loudly on a no-worker run (never false-green).
grep_must "${WORKER_KILL_CHECK}" 'SKIP:' \
  "worker-kill drill SKIPS LOUDLY when no worker pod is present (a missing worker tier is never a false-green pass)"
# (f) the negative control is SHIPPED + wired, and PROVEN to bite by the self-test.
grep_must "${WORKER_KILL_CHECK}" 'WORKER_KILL_DRILL_NEGATIVE_CONTROL' \
  "worker-kill drill ships the negative control (idempotency guard off) as a toggle (ADR-0047 §2)"
grep_must "${WORKER_KILL_HELPER}" 'WORKER_IDEM_NEGATIVE_CONTROL' \
  "worker idempotency probe honours the negative-control flag (guard bypassed → double-write, ADR-0047 §2)"
grep_must "${WORKER_KILL_BITE}" 'WORKER_KILL_DRILL_NEGATIVE_CONTROL=1' \
  "worker-kill bite proof runs the drill WITH the negative control and asserts it goes RED"
grep_must "${WORKER_KILL_BITE}" 'FALSE-GREEN' \
  "worker-kill bite proof fails if the negative control does NOT turn the drill red (the anti-false-green guard)"
# (g) secret hygiene + L3/L5 plumbing (side-effecting tasks touch DB creds + audit spine).
grep_must "${WORKER_KILL_CHECK}" 'sh -c' \
  "worker-kill drill drives in-pod python via sh -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${WORKER_KILL_CHECK}" 'set -euo pipefail' \
  "worker-kill drill sets pipefail so a masked in-pod exit cannot read green (L5)"
grep_must "${WORKER_KILL_CHECK}" 'register_cleanup' \
  "worker-kill drill registers its teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${WORKER_KILL_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "worker-kill drill installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must_not "${WORKER_KILL_CHECK}" 'echo.*NETOPS_POSTGRES_PASSWORD|NETOPS_POSTGRES_PASSWORD=.*echo' \
  "worker-kill drill never echoes the Postgres password (secret hygiene)"
grep_must "${WORKER_KILL_CHECK}" 'reduced scale|deferred-accepted' \
  "worker-kill drill STATES its reduced scale + names the deferred certified-scale soak ceiling (ADR-0047 §1/§4)"

# --- P3 W4-T6: queue-burst KEDA + API load + PgBouncer budget drill invariants ---
# --- (G-SCA §326–§330, ADR-0043 §2/§3, ADR-0042 §4, ADR-0047 §1/§2/§3/§4) --------
# The queue-burst/load drill (queue-burst-load.sh) plugs into the HA assertion-
# runner. This validator BITES if the drill is silently weakened: it must (a) drive a
# 10x `discovery` burst into the REAL Redis list KEDA reads AND assert the burst
# Deployment's replica count ACTUALLY CHANGED (scale-out) — the spec's false-green
# risk — then assert scale-IN, (b) assert per-queue ISOLATION (siblings not starved),
# (c) assert the API load p95 held + a 1->2-replica improvement + zero 5xx (§327),
# (d) assert the PgBouncer connection budget holds (no exhaustion, §330), (e) SKIP
# loudly on a no-KEDA run (never false-green), (f) ship + wire the negative-control
# bite (sibling starvation / connection-budget breach → red), proven by the self-test,
# and (g) keep the L3/L5 + secret-hygiene guards. Removing any makes a check FAIL.
echo "== validating W4-T6 queue-burst + API load + PgBouncer budget drill artifacts =="

QBL_CHECK="${CHECKS_DIR}/queue-burst-load.sh"
QBL_PROBE="${CHECKS_DIR}/queue-burst-load-drill-probe.yaml"
QBL_BITE="${HERE}/queue-burst-load-bite.sh"
require_file "${QBL_CHECK}" "W4-T6 queue-burst + API load + PgBouncer budget drill check"
require_file "${QBL_PROBE}" "W4-T6 queue-burst/load drill probe pod manifest"
require_file "${QBL_BITE}"  "W4-T6 queue-burst/load drill negative-control bite proof (self-test)"

# (a) it drives a REAL 10x `discovery` burst into the Redis list KEDA reads AND
#     asserts the replica count ACTUALLY CHANGED (scale-out), then scale-IN.
grep_must "${QBL_CHECK}" 'RPUSH .*BURST_QUEUE|RPUSH \$\{BURST_QUEUE\}|LPUSH' \
  "queue-burst drill LPUSHes the burst into the REAL Redis list KEDA reads (its own LLEN signal)"
grep_must "${QBL_CHECK}" 'the replica count ACTUALLY changed|ACTUALLY CHANGED' \
  "queue-burst drill asserts the replica count ACTUALLY CHANGED (a burst that never moves a replica is a false-green — the spec risk)"
grep_must "${QBL_CHECK}" 'SCALED OUT|scale-out observed' \
  "queue-burst drill asserts KEDA SCALED OUT the burst Deployment under the 10x burst (G-SCA §329)"
grep_must "${QBL_CHECK}" 'SCALED IN|scale-in observed' \
  "queue-burst drill asserts KEDA SCALED IN after the burst drained (burst-drain SLO half of G-SCA §329)"
grep_must "${QBL_CHECK}" 'deploy_replicas' \
  "queue-burst drill reads the Deployment .spec.replicas (what KEDA/HPA set) — the observable scale signal"
# (b) per-queue ISOLATION — siblings not starved.
grep_must "${QBL_CHECK}" 'SIBLING_QUEUES|sibling' \
  "queue-burst drill witnesses SIBLING queues (config/docs/packet) for the isolation assertion (G-SCA §329)"
grep_must "${QBL_CHECK}" 'STARVED|not starved|per-queue isolation' \
  "queue-burst drill asserts the siblings are NOT starved by the burst (per-queue isolation, ADR-0043 §3)"
# (c) API load p95 held + 1->2-replica improvement + zero 5xx.
grep_must "${QBL_CHECK}" 'P95_BUDGET_MS' \
  "queue-burst drill asserts the API p95 against a (reduced-scale) budget (G-SCA §327)"
grep_must "${QBL_CHECK}" 'P95_2.*-le.*P95_BUDGET_MS|P95_2\}" -le "\$\{P95_BUDGET_MS' \
  "queue-burst drill PASSES only when p95 <= budget and FAILS when it exceeds it (the p95 bite, §327)"
grep_must "${QBL_CHECK}" '1->2-replica improvement|2 replicas beat 1' \
  "queue-burst drill asserts a 1->2-replica improvement (2 replicas beat 1 — the linear scale-out mechanism, §327)"
grep_must "${QBL_CHECK}" 'P95_2.*-le.*P95_1|P95_2\}" -le "\$\{P95_1' \
  "queue-burst drill compares the 2-replica p95 against the 1-replica p95 (the actual delta measurement, §327)"
grep_must "${QBL_CHECK}" 'ZERO 5xx|errors_5xx' \
  "queue-burst drill asserts ZERO 5xx under the reduced-scale load (§327)"
# (d) PgBouncer connection budget — no exhaustion.
grep_must "${QBL_CHECK}" 'POOLER_RW_HOST|PgBouncer|pooler' \
  "queue-burst drill probes the PgBouncer Pooler rw Service (the connection budget under test, ADR-0042 §4)"
grep_must "${QBL_CHECK}" 'connection budget HELD|connection-exhaustion|no connection-exhaustion|EXHAUSTION' \
  "queue-burst drill asserts NO connection exhaustion through the pooler under load (G-SCA §330)"
grep_must "${QBL_CHECK}" 'transaction-mode' \
  "queue-burst drill notes the transaction-mode pooling that multiplexes onto a small server pool (ADR-0042 §4)"
# (e) SKIP loudly on a no-KEDA run (never false-green).
grep_must "${QBL_CHECK}" 'SKIP:' \
  "queue-burst drill SKIPS LOUDLY when no KEDA ScaledObject is present (a missing autoscaler is never a false-green pass)"
# (f) the negative control is SHIPPED + wired, and PROVEN to bite by the self-test.
grep_must "${QBL_CHECK}" 'QUEUE_BURST_DRILL_NEGATIVE_CONTROL' \
  "queue-burst drill ships the negative control (shared scaler starvation / connection-budget regression) as a toggle (ADR-0047 §2)"
grep_must "${QBL_CHECK}" 'shared scaler|SHARED scaler|shared/misconfigured' \
  "queue-burst drill's negative control emulates a SHARED/misconfigured scaler that starves a sibling (ADR-0043 §Alternatives / §2)"
grep_must "${QBL_BITE}" 'QUEUE_BURST_DRILL_NEGATIVE_CONTROL=1' \
  "queue-burst bite proof runs the drill WITH the negative control and asserts it goes RED"
grep_must "${QBL_BITE}" 'FALSE-GREEN' \
  "queue-burst bite proof fails if the negative control does NOT turn the drill red (the anti-false-green guard)"
grep_must "${QBL_BITE}" 'NO_SCALE_OUT' \
  "queue-burst bite proof also proves a burst that never moves the replica count goes RED (the scale-out step is load-bearing)"
# (g) secret hygiene + L3/L5 plumbing (the load path touches Redis broker + DB pooler creds).
grep_must "${QBL_CHECK}" 'exec -i' \
  "queue-burst drill feeds the Redis/DB password over stdin (kubectl exec -i), not argv (secret hygiene / N11)"
grep_must "${QBL_CHECK}" 'read -r RPW|read -r PGPW|IFS= read -r RPW|IFS= read -r PGPW' \
  "queue-burst drill reads the Redis/DB password from stdin inside the pod (never a visible argv arg)"
grep_must "${QBL_CHECK}" 'sh -c|bash -c' \
  "queue-burst drill drives in-pod redis-cli/loadgen via sh -c/bash -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${QBL_CHECK}" 'set -euo pipefail' \
  "queue-burst drill sets pipefail so a masked in-pod exit cannot read green (L5)"
grep_must "${QBL_CHECK}" 'register_cleanup' \
  "queue-burst drill registers its teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${QBL_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "queue-burst drill installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must_not "${QBL_CHECK}" 'echo.*REDIS_PW_VALUE|echo.*PGPASSWORD_VALUE|REDIS_PW_VALUE=.*echo|PGPASSWORD_VALUE=.*echo' \
  "queue-burst drill never echoes the Redis/Postgres password (secret hygiene)"
grep_must "${QBL_CHECK}" 'reduced scale|deferred-accepted' \
  "queue-burst drill STATES its reduced scale + names the deferred certified-scale G-SCA ceiling (ADR-0047 §1/§4)"
grep_must_not "${QBL_CHECK}" 'sqlite://|aiosqlite|:memory:|\.sqlite' \
  "queue-burst drill has NO SQLite code path — the PgBouncer/pool probe runs on the real CNPG cluster (ADR-0047 §5)"
# probe pod hygiene: non-root, digest-pinned, no :latest, no API token.
grep_must "${QBL_PROBE}" 'runAsNonRoot: true' \
  "queue-burst drill probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must "${QBL_PROBE}" 'image:.*@sha256:[0-9a-f]{64}' \
  "queue-burst drill probe pod pins its image by sha256 digest, not a mutable tag (N12)"
grep_must_not "${QBL_PROBE}" 'image:.*:latest' \
  "no :latest image tag in the queue-burst drill probe pod (admission would reject)"
grep_must "${QBL_PROBE}" 'automountServiceAccountToken: false' \
  "queue-burst drill probe pod drops its API token (least privilege, ADR-0029 §5)"

# --- P3 W4-T7: compressed-soak drill invariants (G-REL §315 compressed, ----------
# --- ADR-0046 §1/§2/§6 SLOs/burn-rate, ADR-0047 §1/§2/§3/§4) ---------------------
# The compressed-soak drill (compressed-soak.sh) plugs into the HA assertion-runner.
# This validator BITES if the drill is silently weakened: it must (a) drive STEADY
# mixed load over a COMPRESSED WINDOW (stated, sampled MANY times — not one reading)
# and assert the §6 SLOs stay WITHIN budget over the window (no burn-rate alert would
# fire), (b) assert NO slow resource regression (PgBouncer conns / worker RSS / queue
# depth bounded — a trend → fail), (c) SKIP loudly on a no-api run (never
# false-green), (d) ship + wire the negative-control bite (injected SLO regression +
# leak → red), proven by the self-test which ADDITIONALLY runs a REAL `promtool test
# rules` over the W3-T2/W3-T3 rules, (e) STATE its reduced scale + name the deferred
# 30-day calendar soak, and (f) keep the L3/L5 + secret-hygiene guards. Removing any
# makes a check FAIL.
echo "== validating W4-T7 compressed-soak drill artifacts =="

SOAK_CHECK="${CHECKS_DIR}/compressed-soak.sh"
SOAK_PROBE="${CHECKS_DIR}/compressed-soak-drill-probe.yaml"
SOAK_BITE="${HERE}/compressed-soak-bite.sh"
SOAK_PROMTOOL_TEST="$(cd "${KIND_DIR}/../.." && pwd)/deploy/observability/slo-compressed-soak.test.yaml"
require_file "${SOAK_CHECK}"         "W4-T7 compressed-soak drill check"
require_file "${SOAK_PROBE}"         "W4-T7 compressed-soak drill probe pod manifest"
require_file "${SOAK_BITE}"          "W4-T7 compressed-soak drill negative-control bite proof (self-test)"
require_file "${SOAK_PROMTOOL_TEST}" "W4-T7 compressed-soak SLO-held promtool fixture (real W3-T2/W3-T3 rules)"

# (a) STEADY load over a COMPRESSED WINDOW, sampled MANY times, asserting §6 SLOs
#     stay WITHIN budget over the window (no burn-rate alert would fire).
grep_must "${SOAK_CHECK}" 'SOAK_WINDOW_S' \
  "compressed-soak drill drives load over a stated COMPRESSED WINDOW (SOAK_WINDOW_S — minutes, not the 30-day SLA)"
grep_must "${SOAK_CHECK}" 'SOAK_SAMPLE_INTERVAL_S|sampling' \
  "compressed-soak drill SAMPLES the SLIs across the window (many samples — the sustained-window assertion, not one reading)"
grep_must "${SOAK_CHECK}" 'MAX_AVAIL_ERR|worst.*avail_err|worst-over-window' \
  "compressed-soak drill tracks the WORST SLI over the window (SLO held only if EVERY sample stayed in budget)"
grep_must "${SOAK_CHECK}" 'AVAIL_ERR_BUDGET_PERMILLE' \
  "compressed-soak drill asserts the availability SLI against the fast-burn error budget (§6 row 1, ADR-0046 §2)"
grep_must "${SOAK_CHECK}" 'MAX_AVAIL_ERR.*-le.*AVAIL_ERR_BUDGET_PERMILLE|MAX_AVAIL_ERR\}" -le "\$\{AVAIL_ERR_BUDGET_PERMILLE' \
  "compressed-soak drill PASSES only when the window availability error <= budget and FAILS when it exceeds it (the SLO-held bite)"
grep_must "${SOAK_CHECK}" 'LATENCY_SLOW_FRAC_PERMILLE' \
  "compressed-soak drill asserts the read-latency too-slow fraction against the fast-burn budget (§6 row 2, ADR-0046 §2)"
grep_must "${SOAK_CHECK}" 'no.*burn-rate alert.*fire|burn-rate alert WOULD fire|no NetopsApi' \
  "compressed-soak drill frames the SLO-held assertion as 'no burn-rate alert would fire' (the W3-T3 alert condition, ADR-0046 §2)"
# (b) NO slow resource regression — bounded connection / memory / queue-depth trends.
grep_must "${SOAK_CHECK}" 'CONN_START|CONN_END|pgbouncer_server_conns' \
  "compressed-soak drill samples the PgBouncer server-connection count at window START + END (the connection-leak trend, ADR-0047 §2 soak)"
grep_must "${SOAK_CHECK}" 'RSS_START|RSS_END|worker_rss_kb' \
  "compressed-soak drill samples the worker RSS at window START + END (the memory-leak trend, ADR-0047 §2 soak)"
grep_must "${SOAK_CHECK}" 'QDEPTH_START|QDEPTH_END|queue_len' \
  "compressed-soak drill samples the queue depth at window START + END (the backlog trend, ADR-0047 §2 soak)"
grep_must "${SOAK_CHECK}" 'TRENDED UP|BOUNDED' \
  "compressed-soak drill FAILS on a monotone upward resource TREND and passes when bounded (a leak → a trend → fail, ADR-0047 §2 soak)"
grep_must "${SOAK_CHECK}" 'GROWTH_TOLERANCE' \
  "compressed-soak drill compares the END-vs-START delta against a bounded-growth tolerance (a leak beyond noise → fail)"
# (c) SKIP loudly on a no-api run (never false-green).
grep_must "${SOAK_CHECK}" 'SKIP:' \
  "compressed-soak drill SKIPS LOUDLY when no api Deployment is present (a missing target is never a false-green pass)"
# (d) the negative control is SHIPPED + wired, and PROVEN to bite by the self-test
#     (which runs the REAL promtool SLO-held fixture too).
grep_must "${SOAK_CHECK}" 'COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL' \
  "compressed-soak drill ships the negative control (injected SLO regression + resource leak) as a toggle (ADR-0047 §2)"
grep_must "${SOAK_CHECK}" 'error-rate.*latency perturbation|latency perturbation|injected.*SLO regression|SLO regression' \
  "compressed-soak drill's negative control injects an error-rate + latency perturbation (a burn-rate breach, ADR-0046 §6 / ADR-0047 §2)"
grep_must "${SOAK_BITE}" 'COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL=1' \
  "compressed-soak bite proof runs the drill WITH the negative control and asserts it goes RED"
grep_must "${SOAK_BITE}" 'FALSE-GREEN' \
  "compressed-soak bite proof fails if the negative control does NOT turn the drill red (the anti-false-green guard)"
grep_must "${SOAK_BITE}" 'promtool test rules' \
  "compressed-soak bite proof runs a REAL promtool test over the W3-T2/W3-T3 rules (the SLO-held / no-burn-rate-alert assertion bites cluster-free, ADR-0046 §2/§6)"
# The fake-kubectl in the bite proof must inject disc_err_permille above budget under
# the negative control — so the discovery SLO assertion is NOT tautological (a drill
# that always passes discovery because disc_err is NA/0 is not a gate; ADR-0047 §2).
grep_must "${SOAK_BITE}" 'disc_err_permille=5[0-9][0-9]|disc_err_permille=[2-9][0-9][0-9]' \
  "compressed-soak bite proof fake-kubectl injects disc_err_permille above the 144‰ discovery budget under the negative control (the discovery SLO assertion is NOT tautological — ADR-0047 §2)"
# The drill itself must inject disc_err=500 (or >144) under NEG=1 so the real
# in-pod sample path turns the discovery assertion RED, not just the fake-kubectl.
grep_must "${SOAK_CHECK}" 'disc_err=5[0-9][0-9]|disc_err=[2-9][0-9][0-9]' \
  "compressed-soak drill injects a discovery error rate above the fast-burn budget (144‰) when NEG=1 — proving the discovery SLO assertion bites under the negative control (ADR-0047 §2)"
# The promtool fixture must load the ACTUAL recording rules + burn-rate alerts and
# carry BOTH a healthy-silent case AND a firing negative control (the anti-false-green
# alert-as-test control, ADR-0046 §6). It must ADDITIONALLY carry a discovery SLO
# negative-control case so the NetopsDiscoverySuccessFastBurn alert is proven to bite.
grep_must "${SOAK_PROMTOOL_TEST}" 'slo-recording.rules.yaml' \
  "compressed-soak promtool fixture loads the W3-T2 recording rules (evaluates the SAME SLI series Prometheus does)"
grep_must "${SOAK_PROMTOOL_TEST}" 'slo-burn-rate.alerts.yaml' \
  "compressed-soak promtool fixture loads the W3-T3 burn-rate alerts (the alerts the soak must NOT trip)"
grep_must "${SOAK_PROMTOOL_TEST}" 'exp_alerts: \[\]' \
  "compressed-soak promtool fixture asserts the HEALTHY window fires NO alert (SLOs held — positive path)"
grep_must "${SOAK_PROMTOOL_TEST}" 'NEGATIVE CONTROL' \
  "compressed-soak promtool fixture carries the NEGATIVE-CONTROL firing case (injected regression → burn-rate alert fires)"
grep_must "${SOAK_PROMTOOL_TEST}" 'NetopsDiscoverySuccessFastBurn' \
  "compressed-soak promtool fixture carries a NetopsDiscoverySuccessFastBurn firing case (discovery SLO negative control bites — ADR-0047 §2)"
# (e) STATE reduced scale + NAME the deferred 30-day calendar soak.
grep_must "${SOAK_CHECK}" 'reduced scale|deferred-accepted' \
  "compressed-soak drill STATES its reduced (compressed-window) scale + names the deferred 30-day calendar soak (ADR-0047 §1/§4)"
grep_must "${SOAK_CHECK}" '30-day' \
  "compressed-soak drill explicitly names the 30-day CALENDAR soak as the deferred ceiling (never claimed, ADR-0047 §4)"
# (f) secret hygiene + L3/L5 + N1 plumbing (the load path touches Redis broker + DB pooler creds).
grep_must "${SOAK_CHECK}" 'exec -i' \
  "compressed-soak drill feeds the Redis/DB password over stdin (kubectl exec -i), not argv (secret hygiene / N11)"
grep_must "${SOAK_CHECK}" 'read -r RPW|IFS= read -r RPW|read -r PGPW|IFS= read -r PGPW' \
  "compressed-soak drill reads the Redis/DB password from stdin inside the pod (never a visible argv arg)"
grep_must "${SOAK_CHECK}" 'sh -c|bash -c' \
  "compressed-soak drill drives in-pod redis-cli/loadgen via sh -c/bash -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${SOAK_CHECK}" 'set -euo pipefail' \
  "compressed-soak drill sets pipefail so a masked in-pod exit cannot read green (L5)"
grep_must "${SOAK_CHECK}" 'register_cleanup' \
  "compressed-soak drill registers its teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${SOAK_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "compressed-soak drill installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must_not "${SOAK_CHECK}" 'echo.*REDIS_PW_VALUE|echo.*PGPASSWORD_VALUE|REDIS_PW_VALUE=.*echo|PGPASSWORD_VALUE=.*echo' \
  "compressed-soak drill never echoes the Redis/Postgres password (secret hygiene)"
grep_must_not "${SOAK_CHECK}" 'sqlite://|aiosqlite|:memory:|\.sqlite' \
  "compressed-soak drill has NO SQLite code path — the connection/pool probe runs on the real CNPG cluster (ADR-0047 §5)"
# probe pod hygiene: non-root, digest-pinned, no :latest, no API token.
grep_must "${SOAK_PROBE}" 'runAsNonRoot: true' \
  "compressed-soak drill probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must "${SOAK_PROBE}" 'image:.*@sha256:[0-9a-f]{64}' \
  "compressed-soak drill probe pod pins its image by sha256 digest, not a mutable tag (N12)"
grep_must_not "${SOAK_PROBE}" 'image:.*:latest' \
  "no :latest image tag in the compressed-soak drill probe pod (admission would reject)"
grep_must "${SOAK_PROBE}" 'automountServiceAccountToken: false' \
  "compressed-soak drill probe pod drops its API token (least privilege, ADR-0029 §5)"

# --- P3 W4-T8: N-2 -> N upgrade rehearsal drill invariants (G-MNT §346, ----------
# --- PRODUCTION.md §10 expand/contract, ADR-0002/0029/0005 D5, ADR-0047 §2/§4/§5) -
# The upgrade rehearsal (n2-upgrade-rehearsal.sh) plugs into the HA assertion-runner.
# This validator BITES if the drill is silently weakened: it must (a) run the EXPAND
# migration (alembic upgrade head) in the rolling order, (b) roll the api holding the
# >=2-ready availability floor (no downtime), (c) assert the N-1 reader still works
# against the migrated schema (expand additive) + no data loss + audit spine intact,
# (d) SKIP loudly on a non-HA run (never false-green), (e) ship + wire the two
# negative controls (contract-too-early column drop -> N-1 reader red; force-unavail ->
# no-downtime red), proven by the self-test, and (f) keep the L3/L5 + secret-hygiene
# guards. Removing any makes a check below FAIL.
echo "== validating W4-T8 N-2 -> N upgrade rehearsal drill artifacts =="

N2_UPGRADE_CHECK="${CHECKS_DIR}/n2-upgrade-rehearsal.sh"
N2_UPGRADE_PROBE="${CHECKS_DIR}/n2-upgrade-rehearsal-drill-probe.yaml"
N2_UPGRADE_BITE="${HERE}/n2-upgrade-rehearsal-bite.sh"
require_file "${N2_UPGRADE_CHECK}" "W4-T8 upgrade rehearsal drill check"
require_file "${N2_UPGRADE_PROBE}" "W4-T8 upgrade rehearsal drill probe pod manifest"
require_file "${N2_UPGRADE_BITE}"  "W4-T8 upgrade rehearsal drill negative-control bite proof (self-test)"

# (a) it runs the EXPAND migration (alembic upgrade head) as the pre-upgrade step.
grep_must "${N2_UPGRADE_CHECK}" 'alembic .*upgrade head|upgrade head' \
  "upgrade rehearsal runs the EXPAND migration (alembic upgrade head) as the rolling-order pre-upgrade step (ADR-0002 expand/contract)"
grep_must "${N2_UPGRADE_CHECK}" 'ROLLING ORDER' \
  "upgrade rehearsal drives the ADR-0029 rolling order (migrate -> workers -> api -> Neo4j rebuild)"
grep_must "${N2_UPGRADE_CHECK}" 'ADD COLUMN' \
  "upgrade rehearsal's positive path ships an ADDITIVE expand (ADD COLUMN) — an N-1 reader is unaffected (PRODUCTION.md §10)"
# (b) it rolls the api holding the >=2-ready availability floor (no downtime).
grep_must "${N2_UPGRADE_CHECK}" 'API_AVAIL_FLOOR' \
  "upgrade rehearsal asserts the api availability floor is held through the roll (no downtime, G-MNT §346)"
grep_must "${N2_UPGRADE_CHECK}" 'MIN_READY.*-ge.*API_AVAIL_FLOOR|MIN_READY:-0\}" -ge "\$\{API_AVAIL_FLOOR' \
  "upgrade rehearsal PASSES only when the api never dropped below the floor and FAILS when it did (the no-downtime bite)"
grep_must "${N2_UPGRADE_CHECK}" 'rollout restart' \
  "upgrade rehearsal actually ROLLS the workloads (rollout restart), not a no-op"
# (c) N-1 reader compat + no data loss + audit spine intact.
grep_must "${N2_UPGRADE_CHECK}" 'N-1 reader' \
  "upgrade rehearsal asserts an N-1 reader (SELECT n1_col) still works against the migrated schema (expand additive, G-MNT §346)"
grep_must "${N2_UPGRADE_CHECK}" 'no seeded-row loss|committed DATA LOSS' \
  "upgrade rehearsal asserts NO committed-data loss across the upgrade (G-MNT §346)"
grep_must "${N2_UPGRADE_CHECK}" 'audit spine intact|committed-audit loss' \
  "upgrade rehearsal asserts the audit spine survives the migration (count + max seq, ADR-0038 §3)"
# (d) SKIP loudly on a non-HA run (never false-green) + real-PG only (no SQLite path).
grep_must "${N2_UPGRADE_CHECK}" 'SKIP:' \
  "upgrade rehearsal SKIPS LOUDLY when no CNPG Cluster / api tier is present (a missing tier is never a false-green pass)"
grep_must_not "${N2_UPGRADE_CHECK}" 'sqlite://|aiosqlite|:memory:|\.sqlite' \
  "upgrade rehearsal has NO SQLite code path — the expand/contract + audit-survival semantics need real PG (ADR-0047 §5)"
# (e) the TWO negative controls are SHIPPED + wired, and PROVEN to bite by the self-test.
grep_must "${N2_UPGRADE_CHECK}" 'N2_UPGRADE_DRILL_NEGATIVE_CONTROL' \
  "upgrade rehearsal ships the contract-too-early negative control (drops a column an N-1 pod reads) as a toggle (ADR-0047 §2)"
grep_must "${N2_UPGRADE_CHECK}" 'DROP COLUMN n1_col' \
  "upgrade rehearsal's negative control DROPS the column the N-1 reader selects (contract shipped too early, PRODUCTION.md §10)"
grep_must "${N2_UPGRADE_CHECK}" 'N2_UPGRADE_DRILL_FORCE_API_UNAVAIL' \
  "upgrade rehearsal ships the force-unavailability negative control (api below the floor during the roll) as a toggle (ADR-0047 §2)"
grep_must "${N2_UPGRADE_BITE}" 'N2_UPGRADE_DRILL_NEGATIVE_CONTROL=1' \
  "upgrade rehearsal bite proof runs the drill WITH the contract-too-early control and asserts it goes RED"
grep_must "${N2_UPGRADE_BITE}" 'N2_UPGRADE_DRILL_FORCE_API_UNAVAIL=1' \
  "upgrade rehearsal bite proof runs the drill WITH the force-unavailability control and asserts it goes RED"
grep_must "${N2_UPGRADE_BITE}" 'FALSE-GREEN' \
  "upgrade rehearsal bite proof fails if a negative control does NOT turn the drill red (the anti-false-green guard)"
# (f) secret hygiene + L3/L5 plumbing (audit spine + DB superuser is secret surface).
grep_must "${N2_UPGRADE_CHECK}" 'read -r PGPASSWORD' \
  "upgrade rehearsal feeds the DB password over stdin (kubectl exec -i), not argv (secret hygiene / N11)"
grep_must "${N2_UPGRADE_CHECK}" 'sh -c' \
  "upgrade rehearsal drives in-pod psql/alembic via sh -c positional args, not \$(VAR) in the exec argv (L3)"
grep_must "${N2_UPGRADE_CHECK}" 'set -euo pipefail' \
  "upgrade rehearsal sets pipefail so a masked in-pod psql/alembic exit cannot read green (L5)"
grep_must "${N2_UPGRADE_CHECK}" 'register_cleanup' \
  "upgrade rehearsal registers its probe-pod + seed-table teardown via register_cleanup (composes with the assert-exit bite, N1)"
grep_must_not "${N2_UPGRADE_CHECK}" '^[[:space:]]*trap[[:space:]]+([^#[:space:]]+|'"'"'[^'"'"']*'"'"'|"[^"]*")[[:space:]]+EXIT' \
  "upgrade rehearsal installs NO bare 'trap … EXIT' (would clobber lib.sh's assert-exit bite, N1)"
grep_must "${N2_UPGRADE_CHECK}" 'reduced scale|deferred-accepted' \
  "upgrade rehearsal STATES its reduced scale + names the deferred prod-shaped/contract ceiling (ADR-0047 §1/§4, PRODUCTION.md §10)"
# probe pod hygiene: non-root, digest-pinned, no :latest, no API token.
grep_must "${N2_UPGRADE_PROBE}" 'runAsNonRoot: true' \
  "upgrade rehearsal probe pod is non-root (restricted PSA admissible, ADR-0029 §3)"
grep_must "${N2_UPGRADE_PROBE}" 'image:.*@sha256:[0-9a-f]{64}' \
  "upgrade rehearsal probe pod pins its image by sha256 digest, not a mutable tag (N12)"
grep_must_not "${N2_UPGRADE_PROBE}" 'image:.*:latest' \
  "no :latest image tag in the upgrade rehearsal probe pod (admission would reject)"
grep_must "${N2_UPGRADE_PROBE}" 'automountServiceAccountToken: false' \
  "upgrade rehearsal probe pod drops its API token (least privilege, ADR-0029 §5)"

echo "== validator summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::kind harness validator found ${fails} violation(s)" >&2
  exit 1
fi
echo "kind harness validator: all invariants present."
