#!/usr/bin/env bash
# Fault-injection MTTD gate BITE proof (W3-T5, ADR-0046 §5/§6; PRODUCTION.md §11
# G-OBS §386). Proves the MTTD harness (slo-mttd.faultinjection.test.yaml) is not
# a vacuous/false-green gate, in BOTH directions:
#
#   POSITIVE  — the clean W3-T2 recording rules + W3-T3 burn-rate alerts evaluate
#               the three §386 fault series so each fast/PAGE alert FIRES within
#               MTTD < 5 min, and the healthy negative controls stay silent
#               (`promtool test rules` green).
#   NEGATIVE  — when the fast alerts are SLOWED past the 5 min budget (their
#               `for: 2m` hold raised to `for: 6m`, so detection now lands > 5 min
#               after the fault begins), the MTTD firing assertions (which check
#               the alert is FIRING at 3 m, strictly < 5 min) MUST go RED.
#
# This is THE distinction the task spec demands: a harness that asserts an alert
# "fires eventually" but never bounds the window does NOT bite when detection
# slows — it would stay green with a `for: 6m` that blows the MTTD budget. The
# slowed-alert negative confirms the WINDOW is the assertion (ADR-0046 §5 risk:
# "asserts an alert fires but never checks the window -> MTTD unproven"; §6
# anti-false-green: a NEW gate must RUN and BITE before it is relied on).
#
# Why slow `for:` rather than mute the threshold: muting (the run-promtool-bite.sh
# mutation) proves the alert fires AT ALL; slowing the hold proves the alert fires
# WITHIN 5 MIN. The MTTD gate's job is the window, so the window-relevant mutation
# is the one that must bite here. The mutation is applied to a COPY in a temp dir;
# the committed rules are never changed.
#
# BASIS = synthetic-series simulated budget (ADR-0046 §5). The LIVE-CLUSTER MTTD
# run (real injected fault on the W4-T1 kind cluster + 30-day soak) is
# NAMED-DEFERRED to W4/W5 per ADR-0046 §0 — this in-CI promtool proof is the
# blocking gate that bites on every PR, not a substitute for the live drill.
#
# Run:  bash deploy/observability/run-mttd-bite.sh
# CI:   the `observability` job runs this after the clean MTTD test step.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORDING="${HERE}/slo-recording.rules.yaml"
ALERTS="${HERE}/slo-burn-rate.alerts.yaml"
MTTD_TEST="${HERE}/slo-mttd.faultinjection.test.yaml"

if ! command -v promtool >/dev/null 2>&1; then
  echo "::error::promtool not on PATH — cannot run the fault-injection MTTD bite proof" >&2
  exit 1
fi

fail=0

echo "== fault-injection MTTD bite (ADR-0046 §5/§6; §386 MTTD < 5 min) =="

# ---------------------------------------------------------------------------
# POSITIVE: the clean rules detect each of the three §386 faults within 5 min.
# ---------------------------------------------------------------------------
echo "-- positive: clean rules -> each fault alert FIRES within MTTD < 5 min, healthy series silent --"
if promtool check rules "${RECORDING}" "${ALERTS}" >/dev/null 2>&1 \
   && promtool test rules "${MTTD_TEST}" >/dev/null 2>&1; then
  echo "PASS: clean MTTD harness is green (db-down / queue-stall / llm-failure each detected < 5 min)"
else
  echo "FAIL: clean MTTD harness did NOT pass — the gate is red before any mutation" >&2
  promtool check rules "${RECORDING}" "${ALERTS}" 2>&1 | sed 's/^/    /' >&2 || true
  promtool test rules "${MTTD_TEST}" 2>&1 | sed 's/^/    /' >&2 || true
  fail=1
fi

# ---------------------------------------------------------------------------
# NEGATIVE: slow the fast alerts past the 5 min budget; the MTTD firing
# assertions (firing at 3 m) MUST go red. A gate that stayed green here would be
# a window-blind gate (the exact "fires eventually but MTTD unproven" trap).
# ---------------------------------------------------------------------------
echo "-- negative: fast alerts SLOWED to for:6m (detection > 5 min) MUST fail the MTTD assertions --"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

cp "${RECORDING}" "${TMP}/slo-recording.rules.yaml"
cp "${MTTD_TEST}" "${TMP}/slo-mttd.faultinjection.test.yaml"
# Slow EVERY fast-tier `for: 2m` to `for: 6m` so the page alerts cannot fire
# until 7 m — past the 5 min MTTD budget the harness asserts.
sed 's/for: 2m/for: 6m/g' "${ALERTS}" > "${TMP}/slo-burn-rate.alerts.yaml"

# Guard against a sed no-op (rule drift) making the negative vacuously "pass".
if cmp -s "${ALERTS}" "${TMP}/slo-burn-rate.alerts.yaml"; then
  echo "FAIL: mutation was a no-op — no 'for: 2m' fast-tier hold found to slow (rule drift?)" >&2
  fail=1
else
  if promtool test rules "${TMP}/slo-mttd.faultinjection.test.yaml" >/dev/null 2>&1; then
    echo "FAIL: the SLOWED alerts still passed the MTTD assertions — the MTTD gate does NOT bite (window-blind false-green)" >&2
    fail=1
  else
    echo "PASS: the slowed (for:6m, detection > 5 min) alerts went RED on the MTTD assertions — the window IS the gate"
  fi
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::fault-injection MTTD bite FAILED" >&2
  exit 1
fi
echo "fault-injection MTTD bite: both directions correct (clean rules detect < 5 min; slowed alerts miss the budget and fail)."
