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
# round-4 #05: an explicit non-TLS `hostnossl` row (and its indented variant) must be
# DENIED. `hostnossl` is a plaintext-capable connection type the old `^[ \t]*host\s`
# matcher missed entirely (the `n` after `host` is not whitespace).
NEG_HOSTNOSSL="${HERE}/pg_hba_hostnossl_DENY.yaml"
NEG_HOSTNOSSL_INDENTED="${HERE}/pg_hba_indented_hostnossl_DENY.yaml"

fail=0

# conftest exits non-zero on BOTH a real policy denial AND a harness error (bad
# args, an unparseable/missing policy, or a rego RUNTIME exception). A negative
# fixture must be rejected by a genuine DENY — NOT by an exec error that merely
# happens to be non-zero (round-5 #03 / the negative-check fail-open). expect_deny
# therefore REQUIRES: conftest exits non-zero AND its summary reports >=1 failure
# AND 0 exceptions. A non-zero exit with no failure line, or with an exception, is
# a harness error and fails the bite LOUD instead of passing it open.
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
    echo "PASS: ${label} PASSED (no false-reject of an equivalent secure row)"
  else
    echo "FAIL: ${label} was DENIED/errored — the strict-hostssl regex false-rejects an equivalent secure row" >&2
    _indent
    fail=1
  fi
}

echo "== pg_hba weak-hostssl policy bite =="

# NEGATIVE: a weak `trust clientcert=verify-full` hostssl row placed before the
# strict row MUST be DENIED (first-match-wins weakening must be caught).
echo "-- negative fixture (a weak hostssl row alongside a strict one) MUST be DENIED --"
expect_deny "weak-hostssl fixture" "${NEG}"

# POSITIVE: strict rows with whitespace/column variation + an optional trailing
# pg_hba option MUST PASS (no false-reject of equivalent secure rows).
echo "-- positive fixture (strict rows, whitespace + trailing-option variation) MUST PASS --"
expect_pass "strict-variation fixture" "${POS}"

# NEGATIVE (indented): an INDENTED weak hostssl row MUST be DENIED — pg_hba ignores
# leading whitespace, so the matcher must still see it and the per-row strict check
# must bite (R3 #11).
echo "-- negative fixture (an INDENTED weak hostssl row) MUST be DENIED --"
expect_deny "indented-weak fixture" "${NEG_INDENTED}"

# POSITIVE (indented): INDENTED but otherwise-strict hostssl rows MUST PASS — the
# leading-whitespace tolerance must NOT false-reject an equivalent secure row (R3 #12).
echo "-- positive fixture (INDENTED strict hostssl rows) MUST PASS --"
expect_pass "indented-strict fixture" "${POS_INDENTED}"

# NEGATIVE (round-4 #05): an explicit non-TLS `hostnossl` row MUST be DENIED — it is
# a plaintext-capable connection type that the old `host`-only matcher never saw.
echo "-- negative fixture (an explicit non-TLS \`hostnossl\` row) MUST be DENIED --"
expect_deny "hostnossl fixture" "${NEG_HOSTNOSSL}"

# NEGATIVE (round-4 #05 + R3 #11): an INDENTED `hostnossl` row MUST also be DENIED.
echo "-- negative fixture (an INDENTED non-TLS \`hostnossl\` row) MUST be DENIED --"
expect_deny "indented-hostnossl fixture" "${NEG_HOSTNOSSL_INDENTED}"

if [ "${fail}" -ne 0 ]; then
  echo "::error::pg_hba weak-hostssl policy bite FAILED" >&2
  exit 1
fi
echo "pg_hba weak-hostssl + hostnossl policy bite: all directions correct (incl. indented rows)."
