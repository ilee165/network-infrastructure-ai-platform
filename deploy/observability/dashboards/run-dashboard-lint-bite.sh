#!/usr/bin/env bash
# Dashboard-lint BITE proof (W3-T4, ADR-0046 §4; PRODUCTION.md §11 G-OBS §335).
#
# THE anti-false-green discipline (P1-W4 lesson; mirrors run-promtool-bite.sh): a
# structural lint that PASSES on the committed dashboards is only trustworthy as a
# RED gate if it actually BITES on a bad dashboard. A "green at setup" lint that
# would pass a dashboard with a missing golden signal / a missing §335 subject / a
# RENAMED metric is a false-green gate. This script proves it both directions:
#
#   POSITIVE — the committed dashboards pass lint_dashboards.py (the gate is not
#              vacuously red).
#   NEGATIVE — three independent mutations on a COPY each make the lint go RED:
#                (a) drop a golden-signal panel        → "missing golden-signal panel"
#                (b) rename a netops_* metric in an expr → "references no known series"
#                (c) delete a dashboard (drop a subject) → "§335 coverage gap"
#              A gate that stayed green on any of these would be a false-green gate.
#
# Mutations are applied to a COPY in a temp dir; the committed dashboards are never
# changed. If any negative does NOT fail, the gate is not biting → exit non-zero so
# CI fails (the gate is unsafe to promote).
#
# Run:  bash deploy/observability/dashboards/run-dashboard-lint-bite.sh
# CI:   the `observability` job runs this after the clean dashboard-lint step.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINT="${HERE}/lint_dashboards.py"

PY="$(command -v python3 || command -v python || true)"
if [ -z "${PY}" ]; then
  echo "::error::python not on PATH — cannot run the dashboard-lint bite proof" >&2
  exit 1
fi

fail=0
echo "== dashboard-lint bite (ADR-0046 §4 / §335) =="

# ---------------------------------------------------------------------------
# POSITIVE: committed dashboards must pass (gate is not vacuously red).
# ---------------------------------------------------------------------------
echo "-- positive: committed dashboards pass the structural/coverage lint --"
if "${PY}" "${LINT}" >/dev/null 2>&1; then
  echo "PASS: committed dashboards are lint-clean"
else
  echo "FAIL: committed dashboards did NOT pass — gate is red before any mutation" >&2
  "${PY}" "${LINT}" 2>&1 | sed 's/^/    /' >&2 || true
  fail=1
fi

# Helper: copy all dashboards + the linter into a temp dir, run lint there.
# A mutation is applied by the caller via $1 (a shell snippet operating in $TMP).
run_negative() {
  local label="$1"; shift
  local mutate="$1"; shift
  local TMP
  TMP="$(mktemp -d)"
  cp "${HERE}"/*.json "${TMP}/" 2>/dev/null || true
  cp "${LINT}" "${TMP}/lint_dashboards.py"
  ( cd "${TMP}" && eval "${mutate}" )
  if "${PY}" "${TMP}/lint_dashboards.py" >/dev/null 2>&1; then
    echo "FAIL: ${label} — lint still PASSED on a mutated set (false-green)" >&2
    fail=1
  else
    echo "PASS: ${label} — lint went RED on the mutation (gate bites)"
  fi
  rm -rf "${TMP}"
}

# (a) Drop a golden-signal panel from the api dashboard: remove the panel whose
#     netopsGoldenSignal is "errors". The lint must report a missing signal.
echo "-- negative (a): drop a golden-signal panel → must fail --"
run_negative "missing-golden-signal" '
"'"${PY}"'" - <<PYEOF
import json
with open("netops-api.json") as f: d=json.load(f)
d["panels"]=[p for p in d["panels"] if p.get("netopsGoldenSignal")!="errors"]
with open("netops-api.json","w") as f: json.dump(d,f)
PYEOF
'

# (b) Rename a netops_* metric in an expr (simulate a base-metric rename): the
#     panel expr then references no known series and the lint must fail.
echo "-- negative (b): rename a netops_* metric in an expr → must fail --"
run_negative "renamed-metric" '
sed -i "s/netops_http_requests_total/netops_http_requests_RENAMED/g" netops-api.json
'

# (c) Delete a dashboard (drop the redis subject): the §335 coverage gate fails.
echo "-- negative (c): delete a dashboard (drop a §335 subject) → must fail --"
run_negative "missing-subject" 'rm -f netops-redis.json'

# ---------------------------------------------------------------------------
# VENDOR SYNC: the chart embeds a copy of the dashboards
# (deploy/kubernetes/netops/dashboards/) so helm `.Files.Get` can reach them
# (it cannot read outside the chart root). The canonical source is this dir
# (deploy/observability/dashboards/). That copy is produced at BUILD TIME by
# sync-to-chart.sh (it is not a committed file — see .gitignore). This section
# runs the real sync-to-chart.sh first, so the check exercises the actual copy
# mechanism end-to-end, then asserts the two trees are byte-identical for the
# *.json files as a sanity check: a broken/partial copy script (e.g. one that
# silently drops a file, or leaves a stale/renamed one behind) would still ship
# a STALE dashboard while the lint passes the fresh one (a false-green) — this
# check still has real value even with a real sync step in the loop.
# ---------------------------------------------------------------------------
SYNC_SCRIPT="${HERE}/sync-to-chart.sh"
CHART_DASHBOARDS="${HERE}/../../kubernetes/netops/dashboards"
echo "-- vendor sync: run sync-to-chart.sh, then assert canonical == chart-embedded copy --"
sync_fail=0
if ! bash "${SYNC_SCRIPT}"; then
  echo "FAIL: sync-to-chart.sh did not complete successfully" >&2
  sync_fail=1
fi
for f in "${HERE}"/*.json; do
  base="$(basename "${f}")"
  if [ ! -f "${CHART_DASHBOARDS}/${base}" ]; then
    echo "FAIL: ${base} missing from the chart-embedded copy (${CHART_DASHBOARDS}) after sync" >&2
    sync_fail=1
  elif ! cmp -s "${f}" "${CHART_DASHBOARDS}/${base}"; then
    echo "FAIL: ${base} DIFFERS between canonical and chart-embedded copy after sync (broken copy script)" >&2
    sync_fail=1
  fi
done
# Reverse: no orphan vendored dashboard the canonical source lacks.
for f in "${CHART_DASHBOARDS}"/*.json; do
  base="$(basename "${f}")"
  if [ ! -f "${HERE}/${base}" ]; then
    echo "FAIL: ${base} exists in the chart copy but not in the canonical source (broken copy script)" >&2
    sync_fail=1
  fi
done
if [ "${sync_fail}" -eq 0 ]; then
  echo "PASS: sync-to-chart.sh copied canonical and chart-embedded dashboards byte-identically (no drift)"
else
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::dashboard-lint bite FAILED" >&2
  exit 1
fi
echo "dashboard-lint bite: all directions correct (committed dashboards pass; a missing signal / renamed metric / dropped subject each fail the lint; sync-to-chart.sh copies the canonical dashboards into the chart byte-identically)."
