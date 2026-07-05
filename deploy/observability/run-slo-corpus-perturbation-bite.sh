#!/usr/bin/env bash
# SLO-corpus PERTURBATION bite proof (W5-T1, ADR-0046 §5/§6; PRODUCTION.md §6 /
# §11 G-OBS §386). Proves the alert-correctness corpus's fire-WITHIN-WINDOW floor
# is NOT vacuous (the P2 firewall-floor lesson), in BOTH directions:
#
#   POSITIVE  — the committed perturbation corpus (slo-corpus-perturbation.test.yaml)
#               passes: a breach present from t0 FIRES its fast alert by eval 8m, and
#               the matched breach whose onset is DELAYED to t10 stays silent at 8m.
#   NEGATIVE  — when the two FIRING cases' onset is DELAYED past the window (their
#               input series `120x20`->`0x9 120x20` and `600x20`->`0x9 600x20`) WHILE
#               their "exp firing at 8m" assertions are left unchanged, the delayed
#               breach has not fired by 8m, so `promtool test rules` MUST go RED with
#               a genuine assertion FAILURE (`got:[]`). A gate that stayed green here
#               would be a vacuous "fires eventually" floor (detection could slide
#               arbitrarily late and the eval would never notice).
#
# This is the corpus-DELAY counterpart to run-mttd-bite.sh's rule-SLOW mutation:
# there the alert's `for:` hold is slowed; here the FAULT itself arrives late. Both
# assert the WINDOW is the load-bearing part of the assertion, not just eventual
# firing. The mutation is applied to a COPY in a temp dir; committed rules/corpus are
# never changed. A NEGATIVE that does not RED — or that reds on a parse error rather
# than an assertion failure — exits non-zero so CI fails (the floor is unsafe to cite).
#
# Run:  bash deploy/observability/run-slo-corpus-perturbation-bite.sh
# CI:   the `observability` job runs this after the clean promtool check+test steps.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORDING="${HERE}/slo-recording.rules.yaml"
ALERTS="${HERE}/slo-burn-rate.alerts.yaml"
CORPUS="${HERE}/slo-corpus-perturbation.test.yaml"

if ! command -v promtool >/dev/null 2>&1; then
  echo "::error::promtool not on PATH — cannot run the SLO-corpus perturbation bite proof" >&2
  exit 1
fi

fail=0

echo "== SLO-corpus perturbation bite (ADR-0046 §5/§6; §386 fire-within-window floor) =="

# ---------------------------------------------------------------------------
# POSITIVE: the committed corpus passes — the from-t0 breach FIRES by 8m and the
# delayed-onset control stays silent (so the delayed series is valid input and the
# window is what suppresses a late breach).
# ---------------------------------------------------------------------------
echo "-- positive: committed corpus green (from-t0 breach fires by 8m; delayed onset silent) --"
if promtool check rules "${RECORDING}" "${ALERTS}" >/dev/null 2>&1 \
   && promtool test rules "${CORPUS}" >/dev/null 2>&1; then
  echo "PASS: clean rules check + perturbation corpus are green"
else
  echo "FAIL: clean rules/corpus did NOT pass — the floor is red before any mutation" >&2
  promtool check rules "${RECORDING}" "${ALERTS}" 2>&1 | sed 's/^/    /' >&2 || true
  promtool test rules "${CORPUS}" 2>&1 | sed 's/^/    /' >&2 || true
  fail=1
fi

# ---------------------------------------------------------------------------
# NEGATIVE: DELAY the two firing cases' onset past the window; their unchanged
# "exp firing at 8m" assertions MUST fail (the delayed breach hasn't fired yet).
# ---------------------------------------------------------------------------
echo "-- negative: firing cases with onset DELAYED past the window MUST fail their firing assertion --"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

cp "${RECORDING}" "${TMP}/slo-recording.rules.yaml"
cp "${ALERTS}" "${TMP}/slo-burn-rate.alerts.yaml"
# Delay ONLY the from-t0 firing series (`120x20`, `600x20`); the already-delayed
# control series (`0x9 200x20`, `0x9 700x20`) contain neither literal, so they are
# untouched and keep passing — the RED comes solely from the two delayed firing cases.
sed -e "s/'120x20'/'0x9 120x20'/" -e "s/'600x20'/'0x9 600x20'/" \
  "${CORPUS}" > "${TMP}/slo-corpus-perturbation.test.yaml"

# Guard against a sed no-op (corpus drift) making the negative vacuously "pass".
if cmp -s "${CORPUS}" "${TMP}/slo-corpus-perturbation.test.yaml"; then
  echo "FAIL: mutation was a no-op — the '120x20'/'600x20' firing series were not found (corpus drift?)" >&2
  fail=1
else
  # Capture output so we can distinguish an ASSERTION failure (`FAILED` — the window
  # bites) from a PARSE error (invalid delayed series — which must NOT count as a bite).
  set +e
  neg_out="$(cd "${TMP}" && promtool test rules slo-corpus-perturbation.test.yaml 2>&1)"
  neg_rc=$?
  set -e
  if [ "${neg_rc}" -eq 0 ]; then
    echo "FAIL: the DELAYED firing cases still PASSED — the fire-within-window floor is VACUOUS" >&2
    echo "${neg_out}" | sed 's/^/    /' >&2
    fail=1
  elif ! printf '%s' "${neg_out}" | grep -qiE "got:|exp:"; then
    # promtool prints `FAILED:` for BOTH parse errors and assertion mismatches, so a
    # bare `FAILED` match would let a parse error masquerade as a bite. Require the
    # alert-assertion mismatch shape (`got:`/`exp:`) — only a real firing-assertion
    # failure carries it; a parse/load error does not.
    echo "FAIL: the delayed corpus did not fail on an ASSERTION (no got:/exp: mismatch — likely a PARSE/load error) — mutation is not a valid bite" >&2
    echo "${neg_out}" | sed 's/^/    /' >&2
    fail=1
  else
    echo "PASS: the delayed-onset firing cases went RED on their firing assertion (got:/exp: mismatch) — the window IS the floor"
  fi
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::SLO-corpus perturbation bite FAILED" >&2
  exit 1
fi
echo "SLO-corpus perturbation bite: both directions correct (committed corpus green; a delayed-past-window breach fails its firing assertion)."
