#!/usr/bin/env bash
# promtool alert-as-test BITE proof (W3-T3, ADR-0046 §6; PRODUCTION.md §11 G-OBS).
#
# THE anti-false-green discipline (P1-W4 lesson, ADR-0046 §6 / alternative 4): a
# rules file that LOADS cleanly (`promtool check rules` green) can still contain an
# alert that NEVER FIRES — a green-at-setup alert that masks the very regression the
# gate exists to catch. The firing `promtool test rules` cases guard against that,
# but only if they actually BITE. This script proves it both ways:
#
#   POSITIVE  — the clean alert rules + their firing/healthy tests pass
#               (`promtool check rules` + `promtool test rules`), so the gate is not
#               vacuously red.
#   NEGATIVE  — when one alert is MUTED (its burn threshold raised to an unreachable
#               value, so it can never fire), the corresponding FIRING test goes RED.
#               A gate that stayed green here would be a false-green gate.
#
# The mutation is applied to a COPY in a temp dir; the committed rules are never
# changed. If the negative does NOT fail, the gate is not biting and this script
# exits non-zero so CI fails (the gate is unsafe to promote).
#
# Run:  bash deploy/observability/run-promtool-bite.sh
# CI:   the `observability` job runs this after the clean promtool check+test steps.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="${HERE}/slo-burn-rate.alerts.yaml"
RECORDING="${HERE}/slo-recording.rules.yaml"
TEST="${HERE}/slo-burn-rate.alerts.test.yaml"

if ! command -v promtool >/dev/null 2>&1; then
  echo "::error::promtool not on PATH — cannot run the alert-as-test bite proof" >&2
  exit 1
fi

fail=0

echo "== promtool alert-as-test bite (ADR-0046 §6) =="

# ---------------------------------------------------------------------------
# POSITIVE: the clean rules + tests must pass (gate is not vacuously red).
# ---------------------------------------------------------------------------
echo "-- positive: clean recording + alert rules check, and firing/healthy tests pass --"
if promtool check rules "${RECORDING}" "${RULES}" >/dev/null 2>&1 \
   && promtool test rules "${TEST}" >/dev/null 2>&1; then
  echo "PASS: clean rules check + alert tests are green"
else
  echo "FAIL: clean rules/tests did NOT pass — the gate is red before any mutation" >&2
  promtool check rules "${RECORDING}" "${RULES}" 2>&1 | sed 's/^/    /' >&2 || true
  promtool test rules "${TEST}" 2>&1 | sed 's/^/    /' >&2 || true
  fail=1
fi

# ---------------------------------------------------------------------------
# NEGATIVE: mute one alert; its firing test MUST go red.
# Raise the api-availability burn threshold (14.4 * 0.001) to an unreachable
# 14.4 * 1e9 so NetopsApiAvailabilityFastBurn can never fire. The firing case
# "api availability fast burn — FIRES on a sustained 5xx stream" must then FAIL.
# ---------------------------------------------------------------------------
echo "-- negative: a MUTED alert (threshold made unreachable) MUST fail its firing test --"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

cp "${RECORDING}" "${TMP}/slo-recording.rules.yaml"
# Mute: replace the budget threshold so the burn condition is never satisfied.
sed 's/(14.4 \* 0.001)/(14.4 * 1e9)/g' "${RULES}" > "${TMP}/slo-burn-rate.alerts.yaml"
# Point the test file at the muted alerts copy (same recording rules filename).
sed 's#slo-burn-rate.alerts.yaml#slo-burn-rate.alerts.yaml#' "${TEST}" > "${TMP}/slo-burn-rate.alerts.test.yaml"

# Confirm the mutation actually changed the file (guard against a sed no-op that
# would make the negative vacuously "pass" the wrong way).
if cmp -s "${RULES}" "${TMP}/slo-burn-rate.alerts.yaml"; then
  echo "FAIL: mutation was a no-op — the api-availability burn threshold was not found to mute (rule drift?)" >&2
  fail=1
else
  if promtool test rules "${TMP}/slo-burn-rate.alerts.test.yaml" >/dev/null 2>&1; then
    echo "FAIL: the MUTED alert's firing test still PASSED — the alert-as-test gate does NOT bite (false-green)" >&2
    fail=1
  else
    echo "PASS: the muted alert's firing test went RED — the gate bites (a never-firing alert is caught)"
  fi
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::promtool alert-as-test bite FAILED" >&2
  exit 1
fi
echo "promtool alert-as-test bite: both directions correct (clean rules pass; a muted never-firing alert fails its firing test)."
