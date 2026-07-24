#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
promtool check rules "$ROOT/slo-recording.rules.yaml" "$ROOT/slo-burn-rate.alerts.yaml"
promtool test rules "$ROOT/reconciliation.alerts.test.yaml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

assert_mutation_bites() {
  local name="$1" expression="$2" replacement="$3"
  rm -f "$TMP/"*
  cp "$ROOT/"{slo-recording.rules.yaml,slo-burn-rate.alerts.yaml,reconciliation.alerts.test.yaml} "$TMP/"
  sed -i "s|$expression|$replacement|g" "$TMP/slo-burn-rate.alerts.yaml"
  if promtool test rules "$TMP/reconciliation.alerts.test.yaml" >/dev/null 2>&1; then
    echo "reconciliation bite failed: $name mutation passed" >&2
    exit 1
  fi
}

assert_mutation_bites "backup alert" "NetopsConfigBackupCompletenessBurn" "MutedConfigBackupCompletenessBurn"
assert_mutation_bites "CR alert" "NetopsChangeRequestAuditCompletenessBurn" "MutedChangeRequestAuditCompletenessBurn"
assert_mutation_bites "trace alert" "NetopsReasoningTracePersistenceBurn" "MutedReasoningTracePersistenceBurn"
assert_mutation_bites "inconsistency branch" "> 0" "> 999"
assert_mutation_bites "query-health branch" "== 0" "== -1"
assert_mutation_bites "freshness branch" ">= 90000" ">= 999999"
assert_mutation_bites "enabled exclusion branch" "schedule_enabled{reconciliation=\"config_backup\"} == 1" "schedule_enabled{reconciliation=\"config_backup\"} == 0"
assert_mutation_bites "enabled absent branch" "absent(slo:netops_reconciliation:schedule_enabled" "vector(0) and (slo:netops_reconciliation:schedule_enabled"
assert_mutation_bites "absent-health branch" "absent(slo:netops_reconciliation:query_healthy" "vector(0) and (slo:netops_reconciliation:query_healthy"
assert_mutation_bites "absent-count branch" "absent(slo:netops_reconciliation:inconsistencies" "vector(0) and (slo:netops_reconciliation:inconsistencies"
assert_mutation_bites "absent-freshness branch" "absent(slo:netops_reconciliation:age_seconds" "vector(0) and (slo:netops_reconciliation:age_seconds"
echo "reconciliation promtool bite: every alert and independent branch bites"
