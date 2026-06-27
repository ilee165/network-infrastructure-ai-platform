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
# R3 #11/#12 (PR#76 round 3): leading-whitespace tolerance. An INDENTED weak
# hostssl row must still be DENIED (the matcher must SEE it), and an INDENTED
# strict row must still PASS (no leading-whitespace false-reject).
NEG_INDENTED="${HERE}/pg_hba_indented_weak_hostssl_DENY.yaml"
POS_INDENTED="${HERE}/pg_hba_indented_strict_hostssl_PASS.yaml"

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

# NEGATIVE (indented): an INDENTED weak `trust clientcert=verify-full` hostssl row
# MUST be DENIED — pg_hba ignores leading whitespace, so the matcher must still see
# the row and the per-row strict check must bite (R3 #11).
echo "-- negative fixture (an INDENTED weak hostssl row) MUST be DENIED --"
if conftest test "${NEG_INDENTED}" --policy "${POLICY}" --all-namespaces; then
  echo "FAIL: indented-weak fixture PASSED conftest — a whitespace-prefixed weak hostssl row BYPASSED the strictness check (leading-whitespace bypass)" >&2
  fail=1
else
  echo "PASS: indented-weak fixture was DENIED (the leading-whitespace weak row bites)"
fi

# POSITIVE (indented): INDENTED but otherwise-strict hostssl rows MUST PASS — the
# leading-whitespace tolerance must NOT false-reject an equivalent secure row (R3 #12).
echo "-- positive fixture (INDENTED strict hostssl rows) MUST PASS --"
if conftest test "${POS_INDENTED}" --policy "${POLICY}" --all-namespaces; then
  echo "PASS: indented-strict fixture PASSED (no leading-whitespace false-reject)"
else
  echo "FAIL: indented-strict fixture was DENIED — the strict-hostssl regex false-rejects an indented secure row" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::pg_hba weak-hostssl policy bite FAILED" >&2
  exit 1
fi
echo "pg_hba weak-hostssl policy bite: both directions correct (incl. indented rows)."
