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
    if grep -v '^[[:space:]]*#' "${_chk}" | grep -Eq 'trap[[:space:]]+[^[:space:]#]+[[:space:]]+EXIT'; then
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

echo "== validator summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::kind harness validator found ${fails} violation(s)" >&2
  exit 1
fi
echo "kind harness validator: all invariants present."
