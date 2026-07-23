#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
promtool check rules "$ROOT/slo-recording.rules.yaml" "$ROOT/slo-burn-rate.alerts.yaml"
promtool test rules "$ROOT/reconciliation.alerts.test.yaml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp "$ROOT/"{slo-recording.rules.yaml,slo-burn-rate.alerts.yaml,reconciliation.alerts.test.yaml} "$TMP/"
sed -i 's/> 0/> 999/g' "$TMP/slo-burn-rate.alerts.yaml"
if promtool test rules "$TMP/reconciliation.alerts.test.yaml" >/dev/null 2>&1; then
  echo "reconciliation bite failed: muted rules passed firing controls" >&2
  exit 1
fi
echo "reconciliation promtool bite: clean rules pass; muted alerts fail"
