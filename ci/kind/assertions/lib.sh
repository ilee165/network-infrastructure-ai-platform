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

# Total failures seen so far (the runner exits non-zero when > 0).
assert_failures() { echo "${ASSERT_FAIL}"; }

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
# A short-timeout TCP connect from inside a pod. Success = the port is reachable;
# failure (non-zero) = blocked/unreachable. We use `nc -z -w` so a denied egress
# returns promptly instead of hanging the job.
_tcp_probe() {
  local ns="$1" pod="$2" host="$3" port="$4" timeout="${5:-5}"
  # `sh -c` with positional args (L3): host/port are "$1"/"$2" inside the pod,
  # never $(VAR)-interpolated into the argv.
  run_in_pod "${ns}" "${pod}" -- sh -c 'nc -z -w "$3" "$1" "$2"' _ "${host}" "${port}" "${timeout}"
}

# assert_egress_allowed <ns> <pod> <host> <port> [timeout] <description>
assert_egress_allowed() {
  local ns="$1" pod="$2" host="$3" port="$4"
  local timeout=5 desc
  if [ "$#" -ge 6 ]; then timeout="$5"; desc="$6"; else desc="$5"; fi
  if _tcp_probe "${ns}" "${pod}" "${host}" "${port}" "${timeout}"; then
    _pass "${desc} (egress ${host}:${port} reachable as required)"
  else
    _fail "${desc} (egress ${host}:${port} was BLOCKED but should be ALLOWED)"
  fi
}

# assert_egress_blocked <ns> <pod> <host> <port> [timeout] <description>
# The deterministic deny bite (ADR-0041 §3): the probe MUST fail to connect.
assert_egress_blocked() {
  local ns="$1" pod="$2" host="$3" port="$4"
  local timeout=5 desc
  if [ "$#" -ge 6 ]; then timeout="$5"; desc="$6"; else desc="$5"; fi
  if _tcp_probe "${ns}" "${pod}" "${host}" "${port}" "${timeout}"; then
    _fail "${desc} (egress ${host}:${port} SUCCEEDED but should be BLOCKED — CNI not enforcing or policy too broad)"
  else
    _pass "${desc} (egress ${host}:${port} blocked as required)"
  fi
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
