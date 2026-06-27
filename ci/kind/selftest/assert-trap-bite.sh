#!/usr/bin/env bash
# EMPIRICAL self-test for the lib.sh assert-exit trap + cleanup composition (N1).
#
# This is the BITE for the trap-clobber finding (PR #76 N1): the two live checks
# (collector-egress.sh, mtls-postgres.sh) need probe-pod teardown, but a bare
# `trap cleanup EXIT` in a check REPLACES lib.sh's `trap _assert_exit_trap EXIT`
# (bash keeps only the last EXIT trap), so a recorded ASSERT_FAIL with an rc=0
# body would run cleanup and EXIT 0 = FALSE-GREEN. The fix is `register_cleanup`,
# which lib.sh's trap invokes before applying the assert-fail exit logic.
#
# Unlike validate-harness.sh (static greps), this runs lib.sh as a real check
# subprocess and asserts the OBSERVABLE behaviour:
#   1. a check that records an ASSERT_FAIL and registers a cleanup, then returns 0
#      from its body, EXITS NON-ZERO (the assert bite survives cleanup);
#   2. the registered cleanup actually RAN (teardown composes, is not dropped);
#   3. a clean check (no ASSERT_FAIL) with a registered cleanup EXITS 0 and the
#      cleanup still ran (cleanup is not coupled to failure).
#
# Run: ci/kind/selftest/assert-trap-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness` job runs this alongside validate-harness.sh (no cluster).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
LIB="${KIND_DIR}/assertions/lib.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- scenario 1+2: ASSERT_FAIL + registered cleanup, body returns 0 -----------
# Spawn a child bash that behaves exactly like a real check: source lib.sh (which
# arms the EXIT trap), record a failure via _fail, register a cleanup that leaves
# a marker file, then let the body fall off the end with status 0.
marker1="${WORK}/cleanup-ran-1"
child1="${WORK}/check1.sh"
cat > "${child1}" <<EOF
#!/usr/bin/env bash
set -uo pipefail
. "${LIB}"
my_cleanup() { : > "${marker1}"; }
register_cleanup my_cleanup
_fail "synthetic recorded failure (must bite through cleanup)"
# Body completes 'successfully' — without the trap this would exit 0 (false-green).
true
EOF
bash "${child1}" >/dev/null 2>&1
rc1=$?

if [ "${rc1}" -ne 0 ]; then
  ok "recorded ASSERT_FAIL + registered cleanup + rc=0 body EXITS NON-ZERO (rc=${rc1}) — trap bites through cleanup"
else
  bad "FALSE-GREEN: a check that recorded an ASSERT_FAIL exited 0 (cleanup clobbered the assert-exit trap)"
fi
if [ -f "${marker1}" ]; then
  ok "registered cleanup RAN on the failing-assert path (teardown composes with the bite)"
else
  bad "registered cleanup did NOT run — register_cleanup is not wired into the assert-exit trap"
fi

# --- scenario 3: clean check + registered cleanup exits 0, cleanup still runs --
marker2="${WORK}/cleanup-ran-2"
child2="${WORK}/check2.sh"
cat > "${child2}" <<EOF
#!/usr/bin/env bash
set -uo pipefail
. "${LIB}"
my_cleanup() { : > "${marker2}"; }
register_cleanup my_cleanup
_pass "synthetic recorded pass (no failure)"
true
EOF
bash "${child2}" >/dev/null 2>&1
rc2=$?

if [ "${rc2}" -eq 0 ]; then
  ok "clean check (no ASSERT_FAIL) with a registered cleanup EXITS 0 (cleanup not coupled to failure)"
else
  bad "a clean check with a registered cleanup exited non-zero (rc=${rc2}) — cleanup must not force a failure"
fi
if [ -f "${marker2}" ]; then
  ok "registered cleanup RAN on the passing path too (teardown always runs)"
else
  bad "registered cleanup did NOT run on the passing path"
fi

# --- scenario 4: regression guard — a bare `trap cleanup EXIT` clobbers --------
# Demonstrate WHY register_cleanup is required: a child that uses the OLD pattern
# (bare `trap cleanup EXIT` after sourcing lib.sh) reads FALSE-GREEN. This is the
# negative control proving the bite is real, not vacuous.
child3="${WORK}/check3.sh"
cat > "${child3}" <<EOF
#!/usr/bin/env bash
set -uo pipefail
. "${LIB}"
clobber_cleanup() { :; }
trap clobber_cleanup EXIT   # the BUG: replaces lib.sh's assert-exit trap
_fail "synthetic recorded failure (clobbered trap will not bite)"
true
EOF
bash "${child3}" >/dev/null 2>&1
rc3=$?
if [ "${rc3}" -eq 0 ]; then
  ok "negative control confirmed: a bare 'trap cleanup EXIT' DOES clobber the bite (rc=0) — so register_cleanup is load-bearing"
else
  bad "negative control unexpected: a clobbering 'trap cleanup EXIT' still exited non-zero (rc=${rc3}) — re-check the trap model"
fi

# --- scenario 5: N5 — an EXPORTED ASSERT_LIB_NO_TRAP must NOT disarm a child ---
# The runner opts itself out of the trap with ASSERT_LIB_NO_TRAP=1, but invokes
# each check via `env -u ASSERT_LIB_NO_TRAP bash "${check}"`. Even if an ancestor
# EXPORTED the opt-out, the child must still bite. Reproduce the leak (export it)
# and the runner's exact stripping form, and assert the child STILL exits non-zero.
child4="${WORK}/check4.sh"
cat > "${child4}" <<EOF
#!/usr/bin/env bash
set -uo pipefail
. "${LIB}"
_fail "synthetic recorded failure (leaked opt-out must not disarm me)"
true
EOF
# With the opt-out EXPORTED but stripped by env -u (the runner's form) → bites.
ASSERT_LIB_NO_TRAP=1 \
  bash -c 'export ASSERT_LIB_NO_TRAP; env -u ASSERT_LIB_NO_TRAP bash "$1" >/dev/null 2>&1' _ "${child4}"
rc4=$?
if [ "${rc4}" -ne 0 ]; then
  ok "child sees the assert-exit trap ARMED despite an exported ASSERT_LIB_NO_TRAP (env -u strips the leak) — rc=${rc4} (N5)"
else
  bad "FALSE-GREEN: an exported ASSERT_LIB_NO_TRAP leaked into the child and disarmed its bite (N5)"
fi
# Negative control: WITHOUT env -u, a leaked exported opt-out DOES disarm → rc=0.
ASSERT_LIB_NO_TRAP=1 \
  bash -c 'export ASSERT_LIB_NO_TRAP; bash "$1" >/dev/null 2>&1' _ "${child4}"
rc4b=$?
if [ "${rc4b}" -eq 0 ]; then
  ok "negative control: a leaked exported opt-out WITHOUT env -u disarms the child (rc=0) — so env -u is load-bearing (N5)"
else
  bad "negative control unexpected: leaked opt-out without env -u still bit (rc=${rc4b}) — re-check the leak model (N5)"
fi

echo "== assert-trap-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::assert-trap self-test found ${fails} violation(s)" >&2
  exit 1
fi
echo "assert-trap self-test: trap composes cleanup with the assert-fail bite."
