#!/usr/bin/env bash
# promtool alert-as-test BITE proof for the report-engine alerts (P4 W3-T1,
# ADR-0053 §9; ADR-0046 §6) — the run-promtool-bite.sh pattern applied to
# report-engine.alerts.yaml.
#
# POSITIVE — the clean rules + their firing/healthy cases pass
#            (`promtool check rules` + `promtool test rules`).
# NEGATIVE — with the weekly staleness threshold raised to an unreachable value
#            (the alert MUTED, it can never fire), the corresponding FIRING
#            test goes RED; removing the relay's absent-series fail-closed branch
#            also makes its FIRING test go RED. A gate that stayed green under
#            either mutation would be false-green.
#
# The mutation is applied to a COPY in a temp dir; committed rules are never
# changed.
#
# Run:  bash deploy/observability/run-report-promtool-bite.sh
# CI:   the `observability` job runs this after the clean check+test steps.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="${HERE}/report-engine.alerts.yaml"
TEST="${HERE}/report-engine.alerts.test.yaml"

if ! command -v promtool >/dev/null 2>&1; then
  echo "FAIL: promtool not found on PATH" >&2
  exit 1
fi

fail=0

# POSITIVE: clean rules load and their unit tests pass.
promtool check rules "${RULES}" >/dev/null
promtool test rules "${TEST}" >/dev/null
echo "PASS: clean report-engine rules load and all firing/healthy cases pass"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# Mute: raise the weekly staleness threshold so the condition is never true.
sed 's/(8 \* 86400)/(8 * 9999999999)/g' "${RULES}" > "${TMP}/report-engine.alerts.yaml"
cp "${TEST}" "${TMP}/report-engine.alerts.test.yaml"

# Guard against a sed no-op (rule drift would make the negative vacuous).
if cmp -s "${RULES}" "${TMP}/report-engine.alerts.yaml"; then
  echo "FAIL: mutation was a no-op — the weekly staleness threshold was not found to mute (rule drift?)" >&2
  fail=1
else
  if promtool test rules "${TMP}/report-engine.alerts.test.yaml" >/dev/null 2>&1; then
    echo "FAIL: the MUTED staleness alert's firing test still PASSED — the gate does NOT bite (false-green)" >&2
    fail=1
  else
    echo "PASS: the muted staleness alert's firing test went RED — the gate bites"
  fi
fi

# Remove the relay's fail-closed absent-series branch. Its dedicated FIRING
# corpus case must fail while the remaining expression still loads cleanly.
sed 's/) or absent(netops_report_outbox_relay_last_success_timestamp)/)/g' \
  "${RULES}" > "${TMP}/report-engine.alerts.yaml"

if cmp -s "${RULES}" "${TMP}/report-engine.alerts.yaml"; then
  echo "FAIL: mutation was a no-op — the relay absent-series branch was not found (rule drift?)" >&2
  fail=1
else
  if promtool test rules "${TMP}/report-engine.alerts.test.yaml" >/dev/null 2>&1; then
    echo "FAIL: removing the relay absent-series branch still PASSED — the gate does NOT bite (false-green)" >&2
    fail=1
  else
    echo "PASS: removing the relay absent-series branch went RED — the gate bites"
  fi
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::report-engine promtool alert-as-test bite FAILED" >&2
  exit 1
fi
echo "report-engine promtool bite: both directions correct (clean rules pass; a muted never-firing alert fails its firing test)."
