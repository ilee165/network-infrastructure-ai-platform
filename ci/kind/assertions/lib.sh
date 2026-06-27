#!/usr/bin/env bash
# Shared assertion helpers for the W4-T3 kind harness (ADR-0039 §6 / ADR-0041 §3).
#
# Sourced by every check under ci/kind/assertions/checks/*.sh and by the harness
# CNI self-test. Provides the deterministic enforcement-bite primitives the two
# downstream tasks reuse:
#   - assert_egress_allowed / assert_egress_blocked  (W4-T5 NetworkPolicy deny)
#   - assert_handshake_ok / assert_handshake_refused  (W4-T4 mTLS plaintext-refusal)
#   - run_in_pod                                       (pipe-safe `kubectl exec`)
#
# L5 (P1-W4-LESSONS): every check pipeline runs under `set -o pipefail`; helpers
# that capture command output guard it with `test -n`/explicit status so a masked
# exit code can never read green. The runner sets pipefail globally; helpers do
# not re-enable it but DO depend on it being on.
#
# L3 (P1-W4-LESSONS): when a probe command embeds a value, it is passed to the
# in-pod shell as a positional arg and dereferenced as "$1" inside `sh -c` — never
# interpolated as $(VAR) into an exec argv (K8s does not substitute it; here we
# drive `kubectl exec` from the runner shell, but the same discipline applies to
# any manifest the checks apply).

# --- result accounting ------------------------------------------------------
ASSERT_PASS=0
ASSERT_FAIL=0

_pass() {
  ASSERT_PASS=$((ASSERT_PASS + 1))
  echo "PASS: $*"
}

_fail() {
  ASSERT_FAIL=$((ASSERT_FAIL + 1))
  echo "FAIL: $*" >&2
}

# Total failures seen so far. The EXIT trap installed below turns a non-zero
# ASSERT_FAIL into a non-zero check exit, which the runner then counts as a failed
# check — so a recorded failure bites even without an explicit `exit`.
assert_failures() { echo "${ASSERT_FAIL}"; }

# --- make the assert_failures path actually BITE ----------------------------
# Each check runs in its OWN `bash "${check}"` subprocess (see run-assertions.sh),
# so ASSERT_FAIL lives and dies with that process — the runner cannot read it. A
# check that records a failure via assert_egress_blocked / assert_handshake_*
# but forgets to `exit "$(assert_failures)"` would therefore leave the subprocess
# exiting 0 and read FALSE-GREEN. To honour the documented contract ("a check may
# leave a non-zero assert_failures") we install an EXIT trap when lib.sh is
# SOURCED BY A CHECK: on normal completion the check's exit status becomes its
# accumulated ASSERT_FAIL count, so any recorded failure propagates to the runner
# without the check author having to remember the explicit exit.
#
# The runner sources lib.sh too, but manages its OWN exit code; it sets
# ASSERT_LIB_NO_TRAP=1 before sourcing so this trap is NOT armed in the runner
# process (which would otherwise force its exit status to ASSERT_FAIL=0 — benign,
# but we keep the runner's exit logic authoritative).
#
# CLEANUP COMPOSITION (N1): a check that needs teardown (e.g. delete a probe pod)
# MUST NOT do `trap cleanup EXIT` — bash keeps only the LAST EXIT trap, so that
# would CLOBBER _assert_exit_trap and a recorded ASSERT_FAIL with an rc=0 body
# would read FALSE-GREEN. Instead the check calls `register_cleanup <fn>`; the
# assert-exit trap runs every registered cleanup FIRST, then applies the
# assert-fail exit logic. Multiple registrations run in registration order.
ASSERT_CLEANUP_FNS=()
register_cleanup() {
  ASSERT_CLEANUP_FNS+=("$1")
}
_run_registered_cleanups() {
  # Run each registered cleanup, swallowing its failure so one broken teardown
  # cannot mask the assert-fail exit logic that follows.
  local fn
  for fn in "${ASSERT_CLEANUP_FNS[@]:-}"; do
    [ -n "${fn}" ] || continue
    "${fn}" || true
  done
}
_assert_exit_trap() {
  local rc=$?
  # Run any cleanups the check registered BEFORE deciding the exit status, so a
  # check's teardown always runs yet never replaces this trap (N1 trap-clobber).
  _run_registered_cleanups
  # A check that already failed/aborted with a non-zero status keeps that status
  # (don't mask a `set -e` abort with a smaller ASSERT_FAIL). Only when the check
  # body completed "successfully" (rc=0) do we surface any recorded assert fails.
  if [ "${rc}" -eq 0 ] && [ "${ASSERT_FAIL}" -ne 0 ]; then
    echo "::error::check recorded ${ASSERT_FAIL} assertion failure(s) — exiting non-zero (lib.sh assert-trap)" >&2
    exit "${ASSERT_FAIL}"
  fi
  exit "${rc}"
}
if [ "${ASSERT_LIB_NO_TRAP:-0}" != "1" ]; then
  trap _assert_exit_trap EXIT
fi

# --- in-pod exec (pipe-safe) ------------------------------------------------
# run_in_pod <namespace> <pod> -- <cmd...>
# Runs a command inside a pod. Returns the command's exit status. The caller is
# responsible for interpreting it; pipefail (set by the runner) ensures a failing
# `kubectl exec` is not masked when its output is piped.
run_in_pod() {
  local ns="$1" pod="$2"
  shift 2
  [ "$1" = "--" ] && shift
  kubectl exec -n "${ns}" "${pod}" -- "$@"
}

# --- egress assertions (W4-T5) ----------------------------------------------
# A short-timeout TCP connect from inside a pod. We use `nc -z -w` so a denied
# egress returns promptly instead of hanging the job.
#
# N4: a non-zero exit must NOT be read uniformly as "policy denied". A BROKEN probe
# (missing `nc`, image without a shell, a `kubectl exec` transport error) also
# exits non-zero — treating that as a confirmed deny is a false-green. _tcp_probe
# therefore returns a TRISTATE:
#   0  = TCP connect SUCCEEDED (egress reached the target)
#   1  = the probe RAN and the connect FAILED (genuine block / refused / timeout)
#   2  = the probe itself is BROKEN (nc missing / exec/transport error) — UNKNOWN,
#        never a deny. The in-pod wrapper prints a sentinel before invoking nc so a
#        missing-tool or unexpected error is distinguishable from a clean connect
#        failure, and a non-zero `kubectl exec` (transport) also maps to 2.
_PROBE_OK=0
_PROBE_BLOCKED=1
_PROBE_ERROR=2
_tcp_probe() {
  local ns="$1" pod="$2" host="$3" port="$4" timeout="${5:-5}"
  local out rc
  # `sh -c` with positional args (L3): host/port are "$1"/"$2" inside the pod,
  # never $(VAR)-interpolated into the argv. The wrapper distinguishes a missing
  # `nc` (exit 2 / PROBE-ERROR) from a clean nc connect failure (exit 1 / BLOCKED).
  #
  # NB: a bare `out="$(cmd)"` assignment is subject to `set -e` — a non-zero cmd
  # (the BLOCKED case!) would abort the check before we classify it. Guard the
  # substitution with an `if` so the non-zero result is captured, not fatal.
  if out="$(run_in_pod "${ns}" "${pod}" -- sh -c '
    command -v nc >/dev/null 2>&1 || { echo "PROBE-ERROR: nc not found in probe image" >&2; exit 2; }
    if nc -z -w "$3" "$1" "$2"; then
      exit 0
    else
      exit 1
    fi
  ' _ "${host}" "${port}" "${timeout}" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  # A non-zero `kubectl exec` that is NOT our explicit 1 (clean nc failure) is a
  # transport/exec error (e.g. pod gone, exec denied) — UNKNOWN, not a deny.
  if [ "${rc}" -eq 2 ]; then
    [ -n "${out}" ] && echo "${out}" >&2
    return "${_PROBE_ERROR}"
  fi
  if [ "${rc}" -eq 0 ]; then
    return "${_PROBE_OK}"
  fi
  if [ "${rc}" -eq 1 ]; then
    return "${_PROBE_BLOCKED}"
  fi
  # Any other code (126/127 from a broken shell/cmd, kubectl transport rc) → error.
  [ -n "${out}" ] && echo "${out}" >&2
  echo "PROBE-ERROR: unexpected probe exit ${rc} (treated as UNKNOWN, not a deny)" >&2
  return "${_PROBE_ERROR}"
}

# assert_egress_allowed <ns> <pod> <host> <port> [timeout] <description>
# Doubles as the PROBE-SANITY precondition for assert_egress_blocked (N4): if the
# allowed probe cannot even connect to a target that SHOULD be reachable, the probe
# tooling is suspect and a later "blocked" result proves nothing.
assert_egress_allowed() {
  local ns="$1" pod="$2" host="$3" port="$4"
  local timeout=5 desc rc
  if [ "$#" -ge 6 ]; then timeout="$5"; desc="$6"; else desc="$5"; fi
  # set -e-safe: `_tcp_probe; rc=$?` would let the probe's non-zero (BLOCKED/ERROR)
  # tristate abort the check before rc is read. Capture rc without aborting.
  rc=0; _tcp_probe "${ns}" "${pod}" "${host}" "${port}" "${timeout}" || rc=$?
  if [ "${rc}" -eq "${_PROBE_OK}" ]; then
    _pass "${desc} (egress ${host}:${port} reachable as required)"
  elif [ "${rc}" -eq "${_PROBE_ERROR}" ]; then
    _fail "${desc} (egress ${host}:${port} probe is BROKEN — nc missing / exec error; cannot confirm reachability)"
  else
    _fail "${desc} (egress ${host}:${port} was BLOCKED but should be ALLOWED)"
  fi
}

# assert_egress_blocked <ns> <pod> <host> <port> [timeout] <description>
# The deterministic deny bite (ADR-0041 §3): the probe MUST fail to connect — AND
# the failure must be a genuine policy DENY, not a broken probe (N4). A
# PROBE-ERROR (nc missing / exec error) is recorded as a FAIL, never a deny pass.
# Callers SHOULD run an assert_egress_allowed first as a probe-sanity precondition
# (a working allowed probe proves nc/exec are healthy, so a subsequent block is
# attributable to policy, not tooling).
assert_egress_blocked() {
  local ns="$1" pod="$2" host="$3" port="$4"
  local timeout=5 desc rc
  if [ "$#" -ge 6 ]; then timeout="$5"; desc="$6"; else desc="$5"; fi
  # set -e-safe (see assert_egress_allowed): capture the tristate without aborting.
  rc=0; _tcp_probe "${ns}" "${pod}" "${host}" "${port}" "${timeout}" || rc=$?
  if [ "${rc}" -eq "${_PROBE_OK}" ]; then
    _fail "${desc} (egress ${host}:${port} SUCCEEDED but should be BLOCKED — CNI not enforcing or policy too broad)"
  elif [ "${rc}" -eq "${_PROBE_ERROR}" ]; then
    _fail "${desc} (egress ${host}:${port} probe is BROKEN — nc missing / exec error; a broken probe is NOT a confirmed deny)"
  else
    _pass "${desc} (egress ${host}:${port} blocked as required)"
  fi
}

# assert_egress_blocked_retry <ns> <pod> <host> <port> <timeout> <retries> <delay> <description>
# N3: the small retry the collector-egress check's comment promises. A slow CNI
# dataplane program can leave egress transiently reachable just after the deny
# policy is applied; we poll up to <retries> times (with <delay>s between) until
# the probe reports BLOCKED, then record a SINGLE assertion result. A PROBE-ERROR
# (nc missing / exec error, N4) aborts the retry immediately and is recorded as a
# FAIL — a broken probe is never a deny. A target still REACHABLE after all
# retries is the hard deny failure.
assert_egress_blocked_retry() {
  local ns="$1" pod="$2" host="$3" port="$4" timeout="$5" retries="$6" delay="$7" desc="$8"
  local attempt rc=0
  for attempt in $(seq 1 "${retries}"); do
    # set -e-safe: capture the tristate without letting a non-zero abort the loop.
    rc=0; _tcp_probe "${ns}" "${pod}" "${host}" "${port}" "${timeout}" || rc=$?
    if [ "${rc}" -eq "${_PROBE_BLOCKED}" ]; then
      _pass "${desc} (egress ${host}:${port} blocked as required, after ${attempt} attempt(s))"
      return 0
    fi
    if [ "${rc}" -eq "${_PROBE_ERROR}" ]; then
      _fail "${desc} (egress ${host}:${port} probe is BROKEN — nc missing / exec error; a broken probe is NOT a confirmed deny)"
      return 0
    fi
    # rc == _PROBE_OK: still reachable; wait and retry (slow dataplane program).
    # `if` (not `&&`) so a false test on the last attempt does not abort under set -e.
    if [ "${attempt}" -lt "${retries}" ]; then sleep "${delay}"; fi
  done
  _fail "${desc} (egress ${host}:${port} still REACHABLE after ${retries} attempt(s) — should be BLOCKED; CNI not enforcing or policy too broad)"
}

# --- mTLS handshake assertions (W4-T4) --------------------------------------
# These wrap a command that performs (or attempts) the mTLS handshake. W4-T4
# supplies the concrete client invocation (psql with sslmode=verify-full, or an
# openssl s_client probe); the harness only needs the pass/fail polarity here.

# assert_handshake_ok <description> -- <cmd...>
# The valid-cert client handshakes successfully (ADR-0039 §6).
assert_handshake_ok() {
  local desc="$1"
  shift
  [ "$1" = "--" ] && shift
  if "$@"; then
    _pass "${desc} (mTLS handshake succeeded as required)"
  else
    _fail "${desc} (mTLS handshake FAILED but a valid-cert client should succeed)"
  fi
}

# assert_handshake_refused <description> -- <cmd...>
# A plaintext / wrong-CA client is REFUSED (ADR-0039 §3/§6 — the refusal bite).
assert_handshake_refused() {
  local desc="$1"
  shift
  [ "$1" = "--" ] && shift
  if "$@"; then
    _fail "${desc} (connection SUCCEEDED but plaintext/wrong-CA must be REFUSED — Postgres not requiring mTLS)"
  else
    _pass "${desc} (plaintext/wrong-CA refused as required)"
  fi
}
