#!/usr/bin/env bash
# Copy-to-chart sync (W4-T2b, ADR-0046 §4).
#
# The canonical dashboards-as-code source is THIS directory
# (deploy/observability/dashboards/*.json). Helm's `.Files.Get`/`.Files.Glob`
# can only read files inside the chart's own directory tree
# (deploy/kubernetes/netops/), so the chart cannot read this directory
# directly. This script copies the canonical JSON into
# deploy/kubernetes/netops/dashboards/ — a BUILD-TIME ARTIFACT, not a
# committed file (see .gitignore) — so the chart's
# grafana-dashboards-configmap.yaml template can embed it via
# `.Files.Glob "dashboards/*.json"`.
#
# Run this before any `helm lint` / `helm template` / `helm package` against
# deploy/kubernetes/netops (CI: once in the `infra` job, once in the
# `observability` job — see .github/workflows/ci.yml) and before the
# dashboard-lint bite proof's vendor-sync check
# (run-dashboard-lint-bite.sh), which also calls this script so the check
# exercises the real copy mechanism end-to-end.
#
# Usage: bash deploy/observability/dashboards/sync-to-chart.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DASHBOARDS="${HERE}/../../kubernetes/netops/dashboards"

mkdir -p "${CHART_DASHBOARDS}"

# Clear any stale copy FIRST so a deletion in the canonical source propagates
# (otherwise an orphan vendored dashboard could survive a source deletion and
# ship a stale/removed dashboard into the cluster — a silent drift).
rm -f "${CHART_DASHBOARDS}"/*.json

shopt -s nullglob
sources=("${HERE}"/*.json)
shopt -u nullglob

if [ "${#sources[@]}" -eq 0 ]; then
  echo "::error::no *.json dashboards found in ${HERE} — refusing to leave the chart copy empty" >&2
  exit 1
fi

cp "${sources[@]}" "${CHART_DASHBOARDS}/"

echo "synced ${#sources[@]} dashboard(s) from ${HERE} into ${CHART_DASHBOARDS}"
