#!/usr/bin/env bash
# KEDA per-queue worker ScaledObject policy BITE (W2-T3, ADR-0043 §2/§3/§4).
#
# Proves the netops.hardening workerscale.* rules actually BITE — a gate that only
# PASSES the compliant render is not enough; it must REJECT the exact ADR-0043
# violations the per-queue autoscaling exists to prevent. The ScaledObject is a
# KEDA CRD on the kubeconform -skip list, so these conftest rules are the policy
# coverage keeping the skip from hiding a regression. Each NEGATIVE fixture is one
# violation and MUST be DENIED by the INTENDED rule; each POSITIVE fixture is the
# compliant shape and MUST PASS (no false-reject).
#
# Negatives (the ADR-0043 failures):
#   - packet SO targeting a GENERAL Deployment -> a NET_RAW/parser pod could scale
#     onto a general node, breaking the ADR-0031 sandbox-pool isolation (§4)
#   - plain `redis` scaler with a STATIC address -> a primary host pin breaks on a
#     Redis failover (ADR-0043 §2 / ADR-0044 — Sentinel discovery required)
#   - INLINED Redis password in trigger metadata -> a secret-surface leak; the
#     credential must be by-reference via a TriggerAuthentication
#   - NO maxReplicaCount -> inherits the KEDA default (100); one queue can consume
#     the whole node budget and starve the others (§3 / G-SCA §329 isolation)
#
# Positives (compliant shapes that MUST NOT be false-rejected):
#   - a sandbox-pinned packet ScaledObject: redis-sentinel trigger + Sentinel
#     discovery + by-reference credential + explicit coherent min/max
#
# Run:  bash deploy/kubernetes/policy/fixtures/run-keda-scaledobject-bite.sh
# CI:   the `infra` job runs this after the KEDA render+validate step (needs conftest).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
POLICY="${REPO}/deploy/kubernetes/policy/rego"

NEG_PACKET_GENERAL="${HERE}/keda_so_packet_general_target_DENY.yaml"
NEG_STATIC_REDIS="${HERE}/keda_so_static_redis_DENY.yaml"
NEG_INLINE_PW="${HERE}/keda_so_inline_password_DENY.yaml"
NEG_NO_MAX="${HERE}/keda_so_no_max_DENY.yaml"
POS_SO="${HERE}/keda_so_compliant_PASS.yaml"

fail=0

# conftest exits non-zero on BOTH a real policy denial AND a harness error (bad
# args, an unparseable/missing policy, or a rego RUNTIME exception). A negative
# fixture must be rejected by a genuine DENY — NOT by an exec error that merely
# happens to be non-zero (the negative-check fail-open). expect_deny therefore
# REQUIRES: conftest exits non-zero AND its summary reports >=1 failure AND 0
# exceptions AND the message matches the intended rule.
_run_conftest() {  # prints output; sets global RC
  if CONFTEST_OUT="$(conftest test "$1" --policy "${POLICY}" --all-namespaces 2>&1)"; then
    RC=0
  else
    RC=$?
  fi
}

_indent() { printf '%s\n' "${CONFTEST_OUT}" | sed 's/^/    /' >&2; }

expect_deny() {  # label, fixture, expected-message-substring
  local label="$1" fixture="$2" expected="$3"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "FAIL: ${label} PASSED conftest — fixture was NOT denied" >&2
    _indent
    fail=1
  elif printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* exception'; then
    echo "FAIL: ${label} raised a conftest EXCEPTION (policy runtime error) — not a real deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  elif ! printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* failure'; then
    echo "FAIL: ${label} exited ${RC} but reported NO failures — conftest exec error, not a deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  elif ! printf '%s' "${CONFTEST_OUT}" | grep -qF -- "${expected}"; then
    # A deny fired, but NOT the intended workerscale rule: an UNRELATED hardening
    # rule could trip while the rule under test silently regressed. Require the
    # SPECIFIC message so the bite proves the INTENDED rule bit (not just any deny).
    echo "FAIL: ${label} was denied, but NOT by the intended rule — expected message substring not found: ${expected}" >&2
    _indent
    fail=1
  else
    echo "PASS: ${label} was DENIED by the intended rule (matched: ${expected})"
  fi
}

expect_pass() {  # label, fixture
  local label="$1" fixture="$2"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "PASS: ${label} PASSED (no false-reject of the compliant shape)"
  else
    echo "FAIL: ${label} was DENIED/errored — the workerscale rules false-reject a compliant manifest" >&2
    _indent
    fail=1
  fi
}

echo "== KEDA per-queue ScaledObject policy bite (ADR-0043 §2/§3/§4) =="

echo "-- negative (packet SO targeting a GENERAL Deployment) MUST be DENIED --"
expect_deny "packet general-target" "${NEG_PACKET_GENERAL}" "must target a sandbox-pinned Deployment"

echo "-- negative (plain redis scaler, static host pin) MUST be DENIED --"
expect_deny "static redis host pin" "${NEG_STATIC_REDIS}" "must use a redis-sentinel trigger"

echo "-- negative (inlined Redis password in trigger metadata) MUST be DENIED --"
expect_deny "inline password" "${NEG_INLINE_PW}" "MUST be by-reference via a TriggerAuthentication"

echo "-- negative (no maxReplicaCount ceiling) MUST be DENIED --"
expect_deny "no max ceiling" "${NEG_NO_MAX}" "must set an explicit maxReplicaCount"

echo "-- positive (compliant sandbox-pinned packet ScaledObject) MUST PASS --"
expect_pass "compliant packet SO" "${POS_SO}"

if [ "${fail}" -ne 0 ]; then
  echo "::error::KEDA per-queue ScaledObject policy bite FAILED" >&2
  exit 1
fi
echo "KEDA ScaledObject policy bite: all directions correct (sandbox-pinned packet target + Sentinel-aware trigger + credential by-reference + explicit per-queue ceiling)."
