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
selftest_line="$(grep -n 'CNI self-test PASSED' "${HARNESS}" | head -1 | cut -d: -f1)"
runner_line="$(grep -n 'bash "${ASSERT_RUNNER}"' "${HARNESS}" | head -1 | cut -d: -f1)"
if [ -n "${selftest_line}" ] && [ -n "${runner_line}" ] && \
   [ "${selftest_line}" -lt "${runner_line}" ]; then
  ok "CNI self-test runs BEFORE the assertion-runner (assertions never trust an unproven CNI)"
else
  bad "CNI self-test must precede the assertion-runner (self-test=${selftest_line:-?} runner=${runner_line:-?})"
fi

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
grep_must "${RUNNER}" 'test ! -s|-s "\$\{log\}"|! -s "\$\{log\}"' \
  "assertion-runner guards an empty (silent no-op) check log (L5)"

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
grep_must "${LIB}" 'ASSERT_LIB_NO_TRAP' \
  "lib.sh honours the ASSERT_LIB_NO_TRAP opt-out (so the runner can suppress the trap)"

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

echo "== validator summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::kind harness validator found ${fails} violation(s)" >&2
  exit 1
fi
echo "kind harness validator: all invariants present."
