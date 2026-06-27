#!/usr/bin/env bash
# pg_hba weak-hostssl policy BITE (PR#76 round-2 #26/#27/#29).
#
# Proves the netops.hardening pg_hba rule rejects a WEAKER hostssl row even when a
# strict row also exists (pg_hba is first-match-wins), WITHOUT false-rejecting an
# EQUIVALENT secure row that differs only in benign whitespace/column spacing or
# carries optional trailing pg_hba options. This is the policy-as-test guard the
# round-2 finding requires: the NEGATIVE fixture must FAIL conftest and the
# POSITIVE fixture must PASS it. Both directions are checked so a regression in
# EITHER (a too-weak rule that lets the negative pass, or a too-strict rule that
# false-rejects the positive) fails this script.
#
# Run:  bash deploy/kubernetes/policy/fixtures/run-pg-hba-bite.sh
# CI:   the `infra` job runs this after the conftest gate (needs only conftest).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
POLICY="${REPO}/deploy/kubernetes/policy/rego"
NEG="${HERE}/pg_hba_weak_hostssl_DENY.yaml"
POS="${HERE}/pg_hba_strict_variation_PASS.yaml"

fail=0

echo "== pg_hba weak-hostssl policy bite =="

# NEGATIVE: a weak `trust clientcert=verify-full` hostssl row placed before the
# strict row MUST be DENIED. conftest exits non-zero on a deny; we REQUIRE that.
echo "-- negative fixture (a weak hostssl row alongside a strict one) MUST be DENIED --"
if conftest test "${NEG}" --policy "${POLICY}" --all-namespaces; then
  echo "FAIL: negative fixture PASSED conftest — a weak hostssl row was NOT denied (first-match-wins weakening is undetected)" >&2
  fail=1
else
  echo "PASS: negative fixture was DENIED (the weak hostssl row bites)"
fi

# POSITIVE: strict rows with whitespace/column variation + an optional trailing
# pg_hba option MUST PASS (no false-reject of equivalent secure rows).
echo "-- positive fixture (strict rows, whitespace + trailing-option variation) MUST PASS --"
if conftest test "${POS}" --policy "${POLICY}" --all-namespaces; then
  echo "PASS: positive fixture PASSED (no false-reject of equivalent secure rows)"
else
  echo "FAIL: positive fixture was DENIED — the strict-hostssl regex false-rejects an equivalent secure row" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::pg_hba weak-hostssl policy bite FAILED" >&2
  exit 1
fi
echo "pg_hba weak-hostssl policy bite: both directions correct."
