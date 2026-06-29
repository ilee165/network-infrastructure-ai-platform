#!/usr/bin/env bash
# CloudNativePG HA-tier policy BITE (W1-T1, ADR-0042).
#
# Proves the netops.hardening cnpg.* rules actually BITE — a gate that only
# PASSES the compliant render is not enough; it must REJECT the exact ADR-0042
# violations the audit-spine HA tier exists to prevent. Each NEGATIVE fixture is
# one violation and MUST be DENIED; each POSITIVE fixture is the compliant shape
# and MUST PASS (no false-reject). Both directions are checked so a regression in
# EITHER (a too-weak rule that lets a negative pass, or a too-strict rule that
# false-rejects the positive) fails this script.
#
# Negatives (the ADR-0042 failures):
#   - async / no synchronous stanza  -> a primary kill loses a committed audit
#     row (G-REL §316 zero-audit-loss failure)                       (§2)
#   - synchronous_commit forced cluster-wide -> sync on ALL writes,
#     throughput collapse (over-scoping)                       (§2 / Alt #3)
#   - synchronous stanza present but synchronous_commit UNSET -> inherits the PG
#     default `on`, so the quorum round-trip is forced onto every write (the
#     SAME throughput collapse, reached implicitly)            (§2 / Alt #3)
#   - PgBouncer SESSION mode -> breaks the connection budget + the per-txn
#     audit `SET LOCAL` scoping                                       (§4)
#   - PgBouncer transaction mode but NO default_pool_size -> unbounded
#     server-side pool, no connection budget                  (§4 / G-SCA §330)
#
# Run:  bash deploy/kubernetes/policy/fixtures/run-cnpg-bite.sh
# CI:   the `infra` job runs this after the conftest gate (needs only conftest).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
POLICY="${REPO}/deploy/kubernetes/policy/rego"

NEG_ASYNC="${HERE}/cnpg_async_no_sync_DENY.yaml"
NEG_SYNCALL="${HERE}/cnpg_sync_on_all_writes_DENY.yaml"
NEG_SYNCUNSET="${HERE}/cnpg_sync_commit_unset_DENY.yaml"
NEG_POOL_SESSION="${HERE}/cnpg_pooler_session_DENY.yaml"
NEG_POOL_UNBOUNDED="${HERE}/cnpg_pooler_unbounded_DENY.yaml"
POS_CLUSTER="${HERE}/cnpg_cluster_quorum_PASS.yaml"
POS_POOLER="${HERE}/cnpg_pooler_transaction_PASS.yaml"

fail=0

# conftest exits non-zero on BOTH a real policy denial AND a harness error (bad
# args, an unparseable/missing policy, or a rego RUNTIME exception). A negative
# fixture must be rejected by a genuine DENY — NOT by an exec error that merely
# happens to be non-zero (the negative-check fail-open). expect_deny therefore
# REQUIRES: conftest exits non-zero AND its summary reports >=1 failure AND 0
# exceptions. A non-zero exit with no failure line, or with an exception, is a
# harness error and fails the bite LOUD instead of passing it open.
_run_conftest() {  # prints output; sets global RC
  if CONFTEST_OUT="$(conftest test "$1" --policy "${POLICY}" --all-namespaces 2>&1)"; then
    RC=0
  else
    RC=$?
  fi
}

_indent() { printf '%s\n' "${CONFTEST_OUT}" | sed 's/^/    /' >&2; }

expect_deny() {  # label, fixture
  local label="$1" fixture="$2"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "FAIL: ${label} PASSED conftest — fixture was NOT denied" >&2
    _indent
    fail=1
  elif printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* exception'; then
    echo "FAIL: ${label} raised a conftest EXCEPTION (policy runtime error) — not a real deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  elif printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* failure'; then
    echo "PASS: ${label} was DENIED (>=1 conftest failure)"
  else
    echo "FAIL: ${label} exited ${RC} but reported NO failures — conftest exec error, not a deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  fi
}

expect_pass() {  # label, fixture
  local label="$1" fixture="$2"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "PASS: ${label} PASSED (no false-reject of the compliant shape)"
  else
    echo "FAIL: ${label} was DENIED/errored — the cnpg rules false-reject a compliant manifest" >&2
    _indent
    fail=1
  fi
}

echo "== CloudNativePG HA-tier policy bite (ADR-0042) =="

echo "-- negative (async / NO synchronous stanza) MUST be DENIED --"
expect_deny "cnpg async-no-sync" "${NEG_ASYNC}"

echo "-- negative (synchronous_commit forced cluster-wide) MUST be DENIED --"
expect_deny "cnpg sync-on-all-writes" "${NEG_SYNCALL}"

echo "-- negative (synchronous set but synchronous_commit UNSET — implicit PG default \`on\`) MUST be DENIED --"
expect_deny "cnpg sync-commit-unset" "${NEG_SYNCUNSET}"

echo "-- negative (PgBouncer SESSION mode) MUST be DENIED --"
expect_deny "cnpg pooler session-mode" "${NEG_POOL_SESSION}"

echo "-- negative (PgBouncer NO default_pool_size budget) MUST be DENIED --"
expect_deny "cnpg pooler unbounded" "${NEG_POOL_UNBOUNDED}"

echo "-- positive (compliant ANY 1 quorum Cluster) MUST PASS --"
expect_pass "cnpg compliant cluster" "${POS_CLUSTER}"

echo "-- positive (compliant transaction-mode Pooler) MUST PASS --"
expect_pass "cnpg compliant pooler" "${POS_POOLER}"

if [ "${fail}" -ne 0 ]; then
  echo "::error::CloudNativePG HA-tier policy bite FAILED" >&2
  exit 1
fi
echo "CloudNativePG HA-tier policy bite: all directions correct (sync-quorum + pooler budget)."
