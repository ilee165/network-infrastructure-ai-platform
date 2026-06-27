#!/usr/bin/env bash
# EMPIRICAL self-test for the egress-probe tristate (N4) + deny retry (N3).
#
# No cluster needed: we STUB `run_in_pod` (lib.sh's only kubectl-exec seam) to
# simulate the in-pod `sh -c` probe under three conditions and assert the assert_*
# helpers classify each correctly:
#   - connect SUCCEEDS  -> allowed=PASS, blocked=FAIL
#   - connect FAILS     -> allowed=FAIL, blocked=PASS  (genuine deny)
#   - nc MISSING/broken -> allowed=FAIL, blocked=FAIL  (UNKNOWN, never a deny pass)
# The third row is the N4 bite: before the fix a broken probe read as a confirmed
# deny (false-green). We also exercise the N3 retry: a target reachable on the
# first probe(s) then blocked records a single PASS; reachable on ALL retries is a
# FAIL.
#
# Run: ci/kind/selftest/egress-probe-tristate.sh   (exits non-zero on any violation)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
LIB="${KIND_DIR}/assertions/lib.sh"

# Source lib.sh as the RUNNER would (no assert-exit trap — we want to inspect
# ASSERT_PASS/ASSERT_FAIL in-process, not exit on them).
ASSERT_LIB_NO_TRAP=1
# shellcheck source=../assertions/lib.sh
. "${LIB}"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# PROBE_MODE drives the stub: ok | blocked | nomissing
#   ok       -> the in-pod sh -c runs nc which "succeeds"
#   blocked  -> nc "fails" cleanly (connection refused/timeout) => exit 1
#   nomissing-> `command -v nc` fails inside the pod => exit 2 (PROBE-ERROR)
# We replace run_in_pod with a stub that executes the SAME `sh -c` script lib.sh
# passes, but with a fake `nc`/`command` on PATH so no real network/cluster is hit.
run_in_pod() {
  # args: ns pod -- sh -c <script> _ host port timeout
  shift 3 || true          # drop ns pod --
  local sh="$1" dashc="$2" script="$3"; shift 3
  # remaining: _ host port timeout
  local stubdir; stubdir="$(mktemp -d)"
  case "${PROBE_MODE}" in
    ok)
      cat > "${stubdir}/nc" <<'EOS'
#!/usr/bin/env bash
exit 0
EOS
      ;;
    blocked)
      cat > "${stubdir}/nc" <<'EOS'
#!/usr/bin/env bash
exit 1
EOS
      ;;
    nomissing)
      : # deliberately no nc on the stub PATH
      ;;
  esac
  [ -f "${stubdir}/nc" ] && chmod +x "${stubdir}/nc"
  # Run lib.sh's exact in-pod script with ONLY the stub dir + coreutils on PATH so
  # `command -v nc` resolves to the stub (or not, for nomissing).
  PATH="${stubdir}:/usr/bin:/bin" "${sh}" "${dashc}" "${script}" "$@"
  local rc=$?
  rm -rf "${stubdir}"
  return "${rc}"
}

reset_counts() { ASSERT_PASS=0; ASSERT_FAIL=0; }

# --- row 1: connect SUCCEEDS --------------------------------------------------
PROBE_MODE=ok; reset_counts
assert_egress_allowed netops probe 10.0.0.1 5432 2 "allowed-when-reachable" >/dev/null 2>&1
[ "${ASSERT_PASS}" -eq 1 ] && ok "reachable target => assert_egress_allowed PASS" \
  || bad "reachable target should PASS assert_egress_allowed (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"
PROBE_MODE=ok; reset_counts
assert_egress_blocked netops probe 1.1.1.1 53 2 "blocked-when-reachable" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "reachable target => assert_egress_blocked FAIL (not a false deny pass)" \
  || bad "reachable target should FAIL assert_egress_blocked (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"

# --- row 2: connect FAILS cleanly (genuine deny) ------------------------------
PROBE_MODE=blocked; reset_counts
assert_egress_blocked netops probe 1.1.1.1 53 2 "blocked-genuine-deny" >/dev/null 2>&1
[ "${ASSERT_PASS}" -eq 1 ] && ok "clean connect-failure => assert_egress_blocked PASS (genuine deny)" \
  || bad "clean connect-failure should PASS assert_egress_blocked (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"
PROBE_MODE=blocked; reset_counts
assert_egress_allowed netops probe 10.0.0.1 5432 2 "allowed-but-blocked" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "clean connect-failure => assert_egress_allowed FAIL" \
  || bad "clean connect-failure should FAIL assert_egress_allowed (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"

# --- row 3 (THE N4 BITE): broken probe (nc missing) is UNKNOWN, never a deny ---
PROBE_MODE=nomissing; reset_counts
assert_egress_blocked netops probe 1.1.1.1 53 2 "blocked-but-probe-broken" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "N4: broken probe (nc missing) => assert_egress_blocked FAIL (NOT a false deny pass)" \
  || bad "N4 FALSE-GREEN: broken probe must FAIL assert_egress_blocked, not pass as a deny (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"
PROBE_MODE=nomissing; reset_counts
assert_egress_allowed netops probe 10.0.0.1 5432 2 "allowed-but-probe-broken" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "N4: broken probe => assert_egress_allowed FAIL (cannot confirm reachability)" \
  || bad "N4: broken probe must FAIL assert_egress_allowed (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"

# --- N3 retry: still reachable on ALL retries => FAIL -------------------------
PROBE_MODE=ok; reset_counts
assert_egress_blocked_retry netops probe 1.1.1.1 53 1 2 0 "retry-persistently-reachable" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "N3: persistently-reachable across retries => assert_egress_blocked_retry FAIL" \
  || bad "N3: persistently-reachable should FAIL the retry deny (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"
# N3 retry: a clean block => PASS.
PROBE_MODE=blocked; reset_counts
assert_egress_blocked_retry netops probe 1.1.1.1 53 1 2 0 "retry-blocked" >/dev/null 2>&1
[ "${ASSERT_PASS}" -eq 1 ] && ok "N3: blocked target => assert_egress_blocked_retry PASS" \
  || bad "N3: blocked target should PASS the retry deny (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"
# N3 retry + N4: broken probe across retries => FAIL, never a deny pass.
PROBE_MODE=nomissing; reset_counts
assert_egress_blocked_retry netops probe 1.1.1.1 53 1 2 0 "retry-broken-probe" >/dev/null 2>&1
[ "${ASSERT_FAIL}" -eq 1 ] && ok "N3+N4: broken probe in retry => FAIL (not a deny pass)" \
  || bad "N3+N4: broken probe in retry must FAIL (pass=${ASSERT_PASS} fail=${ASSERT_FAIL})"

# --- set -e survival: a BLOCKED probe must not ABORT the check ----------------
# Real checks run with `set -euo pipefail`. A bare `out="$(cmd)"` assignment is
# subject to set -e, so a non-zero probe (the BLOCKED case!) would abort the check
# before classification — a silent crash that the runner's empty-log guard might
# not catch cleanly. Spawn a child WITH `set -e` that stubs run_in_pod as a single
# command (like the real kubectl exec) returning the BLOCKED status, and assert the
# child completes and records the PASS (rc 0) rather than aborting.
child_se="${WORK}/setest.sh"
cat > "${child_se}" <<EOF
set -euo pipefail
ASSERT_LIB_NO_TRAP=1
. "${LIB}"
run_in_pod() {
  shift 3 || true
  local sh="\$1" dc="\$2" script="\$3"; shift 3
  "\${sh}" "\${dc}" '
    nc() { return 1; }
    command() { case "\$2" in nc) return 0;; esac; builtin command "\$@"; }
    command -v nc >/dev/null 2>&1 || exit 2
    if nc -z -w "\$3" "\$1" "\$2"; then exit 0; else exit 1; fi
  ' "\$@"
}
assert_egress_blocked netops probe 1.1.1.1 53 2 "deny-under-set-e" >/dev/null 2>&1
# If we reached here without aborting, the set -e guard held. Surface the counts.
echo "\${ASSERT_PASS} \${ASSERT_FAIL}"
EOF
se_out="$(bash "${child_se}" 2>/dev/null || true)"
if [ "${se_out}" = "1 0" ]; then
  ok "set -e survival: a BLOCKED probe records a PASS and does NOT abort the check (out='${se_out}')"
else
  bad "set -e: a BLOCKED probe aborted or misclassified the check (expected '1 0', got '${se_out}') — out=\$(...) needs an if-guard"
fi

echo "== egress-probe-tristate summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::egress-probe tristate self-test found ${fails} violation(s)" >&2
  exit 1
fi
echo "egress-probe tristate self-test: broken probe never reads as a deny; retry polls correctly."
