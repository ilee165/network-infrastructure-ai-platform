#!/usr/bin/env bash
# api HPA + PDB policy BITE (W2-T1, ADR-0043 §1 / PRODUCTION.md §3.2).
#
# Proves the netops.hardening W2-T1 api-scale rules actually BITE — a gate that
# only PASSES the compliant render is not enough; it must REJECT the exact
# ADR-0043 violations the api scale-out exists to prevent. Each NEGATIVE fixture
# is one violation and MUST be DENIED; each POSITIVE fixture is the compliant
# shape and MUST PASS (no false-reject). Both directions are checked so a
# regression in EITHER (a too-weak rule that lets a negative pass, or a too-strict
# rule that false-rejects the positive) fails this script.
#
# Negatives (the ADR-0043 failures):
#   - HPA minReplicas 1            -> floor cannot survive a single node loss;
#     defeats the PDB                                  (§1 / Alt #6)
#   - HPA CPU-only (no req-rate)   -> an I/O-bound flood drives p95 past the §327
#     budget while CPU stays low; would not scale      (§1 / Alt #1)
#   - HPA no-CPU (req-rate only)   -> missing the compute-bound basis the dual
#     signal requires                                  (§1)
#   - PDB minAvailable 0           -> a drain can take the api tier to zero (§3.2)
#   - PDB maxUnavailable-only      -> over a small tier a drain can reach zero;
#     §3.2 names minAvailable as the floor             (§3.2)
#
# Positives (compliant shapes that MUST NOT be false-rejected):
#   - HPA minReplicas 2 + CPU + request-rate dual signal (standard render)
#   - HPA CPU-only + netops.ai/requestrate-disabled=true annotation (opt-out render
#     when requestRate.enabled=false — cluster has no Prometheus adapter; a deliberate
#     opt-out must not be treated the same as an accidental regression)
#   - PDB minAvailable 1
#
# Run:  bash deploy/kubernetes/policy/fixtures/run-api-hpa-pdb-bite.sh
# CI:   the `infra` job runs this after the conftest gate (needs only conftest).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
POLICY="${REPO}/deploy/kubernetes/policy/rego"

NEG_FLOOR_ONE="${HERE}/api_hpa_floor_one_DENY.yaml"
NEG_CPU_ONLY="${HERE}/api_hpa_cpu_only_DENY.yaml"
NEG_NO_CPU="${HERE}/api_hpa_no_cpu_DENY.yaml"
NEG_PDB_ZERO="${HERE}/api_pdb_zero_DENY.yaml"
NEG_PDB_MAXUNAVAIL="${HERE}/api_pdb_maxunavailable_DENY.yaml"
POS_HPA="${HERE}/api_hpa_compliant_PASS.yaml"
POS_HPA_OPTOUT="${HERE}/api_hpa_cpu_only_optout_PASS.yaml"
POS_PDB="${HERE}/api_pdb_compliant_PASS.yaml"

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
    # A deny fired, but NOT the intended api-scale rule: an UNRELATED hardening
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
    echo "FAIL: ${label} was DENIED/errored — the api-scale rules false-reject a compliant manifest" >&2
    _indent
    fail=1
  fi
}

echo "== api HPA + PDB policy bite (ADR-0043 §1 / PRODUCTION.md §3.2) =="

echo "-- negative (HPA minReplicas 1) MUST be DENIED --"
expect_deny "hpa floor-1" "${NEG_FLOOR_ONE}" "must set minReplicas >= 2"

echo "-- negative (HPA CPU-only, no request-rate signal) MUST be DENIED --"
expect_deny "hpa cpu-only" "${NEG_CPU_ONLY}" "must include a request-rate signal IN ADDITION to CPU"

echo "-- negative (HPA no CPU metric) MUST be DENIED --"
expect_deny "hpa no-cpu" "${NEG_NO_CPU}" "must include a CPU Resource (Utilization) metric"

echo "-- negative (PDB minAvailable 0) MUST be DENIED --"
expect_deny "pdb min-0" "${NEG_PDB_ZERO}" "must set an integer minAvailable >= 1"

echo "-- negative (PDB maxUnavailable-only) MUST be DENIED --"
expect_deny "pdb maxunavailable-only" "${NEG_PDB_MAXUNAVAIL}" "must set an integer minAvailable >= 1"

echo "-- positive (compliant api HPA) MUST PASS --"
expect_pass "hpa compliant" "${POS_HPA}"

echo "-- positive (cpu-only HPA with requestrate-disabled annotation — opt-out) MUST PASS --"
expect_pass "hpa cpu-only opt-out (requestrate-disabled annotation)" "${POS_HPA_OPTOUT}"

echo "-- positive (compliant api PDB) MUST PASS --"
expect_pass "pdb compliant" "${POS_PDB}"

if [ "${fail}" -ne 0 ]; then
  echo "::error::api HPA + PDB policy bite FAILED" >&2
  exit 1
fi
echo "api HPA + PDB policy bite: all directions correct (floor>=2 + CPU+req-rate dual signal + opt-out annotation + PDB minAvailable>=1)."
