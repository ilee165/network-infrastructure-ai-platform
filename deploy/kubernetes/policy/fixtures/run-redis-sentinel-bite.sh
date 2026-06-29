#!/usr/bin/env bash
# Redis Sentinel HA-tier policy BITE (W1-T4, ADR-0044 §1).
#
# Proves the netops.hardening W1-T4 redis-sentinel.* rules actually BITE — a gate
# that only PASSES the compliant render is not enough; it must REJECT the exact
# ADR-0044 violations the Sentinel HA tier exists to prevent. Each NEGATIVE fixture
# is one violation and MUST be DENIED; each POSITIVE fixture is the compliant shape
# and MUST PASS (no false-reject). Both directions are checked so a regression in
# EITHER (a too-weak rule that lets a negative pass, or a too-strict rule that
# false-rejects the positive) fails this script.
#
# Negatives (the ADR-0044 failures):
#   - AOF disabled (`appendonly no`)            -> a full-shard restart starts EMPTY,
#     not recovering durable state                                          (§1)
#   - requirepass INLINED in the .conf ConfigMap -> the password leaks into a
#     non-secret object dumped freely               (§1 / ADR-0029 §6)
#   - Redis data StatefulSet REDIS_PASSWORD inlined as a `value:` literal -> the
#     credential sits in the rendered manifest / Helm history (ADR-0029 §6)
#   - Redis data StatefulSet with 1 replica -> no replica to promote on a primary
#     loss; failover impossible                                             (§1)
#   - Sentinel StatefulSet with 1 Sentinel -> no odd-majority quorum; a single
#     loss deadlocks the failover vote                                      (§1)
#   - Sentinel StatefulSet running a PLAIN redis-server (no --sentinel / no monitor)
#     -> monitors nothing; NO automatic failover                            (§1)
#
# Run:  bash deploy/kubernetes/policy/fixtures/run-redis-sentinel-bite.sh
# CI:   the `infra` job runs this after the conftest gate (needs only conftest).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
POLICY="${REPO}/deploy/kubernetes/policy/rego"

NEG_AOF_OFF="${HERE}/redis_aof_off_DENY.yaml"
NEG_CFG_SECRET="${HERE}/redis_config_inline_secret_DENY.yaml"
NEG_PW_INLINE="${HERE}/redis_password_inline_DENY.yaml"
NEG_FEW_REDIS="${HERE}/redis_too_few_replicas_DENY.yaml"
NEG_OMIT_REDIS="${HERE}/redis_replicas_omitted_DENY.yaml"
NEG_FEW_SENT="${HERE}/sentinel_too_few_DENY.yaml"
NEG_NO_MON="${HERE}/sentinel_no_monitor_DENY.yaml"
POS_CONFIG="${HERE}/redis_aof_config_PASS.yaml"
POS_REDIS="${HERE}/redis_data_statefulset_PASS.yaml"
POS_SENTINEL="${HERE}/sentinel_statefulset_PASS.yaml"

fail=0

# conftest exits non-zero on BOTH a real policy denial AND a harness error (bad
# args, an unparseable/missing policy, or a rego RUNTIME exception). A negative
# fixture must be rejected by a genuine DENY — NOT by an exec error that merely
# happens to be non-zero (the negative-check fail-open). expect_deny therefore
# REQUIRES: conftest exits non-zero AND its summary reports >=1 failure AND 0
# exceptions.
_run_conftest() {  # prints output; sets global RC
  if CONFTEST_OUT="$(conftest test "$1" --policy "${POLICY}" --all-namespaces 2>&1)"; then
    RC=0
  else
    RC=$?
  fi
}

_indent() { printf '%s\n' "${CONFTEST_OUT}" | sed 's/^/    /' >&2; }

expect_deny() {  # label, fixture, expected-message-substring
  local label="$1" fixture="$2" expected="$3"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "FAIL: ${label} PASSED conftest — fixture was NOT denied" >&2
    _indent
    fail=1
  elif printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* exception'; then
    echo "FAIL: ${label} raised a conftest EXCEPTION (policy runtime error) — not a real deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  elif ! printf '%s' "${CONFTEST_OUT}" | grep -qE '[1-9][0-9]* failure'; then
    echo "FAIL: ${label} exited ${RC} but reported NO failures — conftest exec error, not a deny (harness error, not pass-open)" >&2
    _indent
    fail=1
  elif ! printf '%s' "${CONFTEST_OUT}" | grep -qF -- "${expected}"; then
    # A deny fired, but NOT the intended redis-sentinel rule: an UNRELATED hardening
    # rule could trip while the rule under test silently regressed. Require the
    # SPECIFIC message so the bite proves the INTENDED rule bit (not just any deny).
    echo "FAIL: ${label} was denied, but NOT by the intended rule — expected message substring not found: ${expected}" >&2
    _indent
    fail=1
  else
    echo "PASS: ${label} was DENIED by the intended rule (matched: ${expected})"
  fi
}

expect_pass() {  # label, fixture
  local label="$1" fixture="$2"
  _run_conftest "${fixture}"
  if [ "${RC}" -eq 0 ]; then
    echo "PASS: ${label} PASSED (no false-reject of the compliant shape)"
  else
    echo "FAIL: ${label} was DENIED/errored — the redis-sentinel rules false-reject a compliant manifest" >&2
    _indent
    fail=1
  fi
}

echo "== Redis Sentinel HA-tier policy bite (ADR-0044 §1) =="

echo "-- negative (AOF disabled) MUST be DENIED --"
expect_deny "redis AOF-off" "${NEG_AOF_OFF}" "must set \`appendonly yes\`"

echo "-- negative (requirepass INLINED in the config ConfigMap) MUST be DENIED --"
expect_deny "redis config inline-secret" "${NEG_CFG_SECRET}" "must NOT inline requirepass/masterauth/auth-pass"

echo "-- negative (REDIS_PASSWORD inlined as a value: literal) MUST be DENIED --"
expect_deny "redis password inline" "${NEG_PW_INLINE}" "REDIS_PASSWORD must NOT carry an inline \`value:\` literal"

echo "-- negative (Sentinel-tier Redis with 1 replica) MUST be DENIED --"
expect_deny "redis too-few-replicas" "${NEG_FEW_REDIS}" "must run >= 3 replicas"

echo "-- negative (Sentinel-tier Redis OMITS replicas — K8s defaults to 1) MUST be DENIED --"
expect_deny "redis replicas-omitted" "${NEG_OMIT_REDIS}" "must run >= 3 replicas"

echo "-- negative (1 Sentinel — no odd quorum) MUST be DENIED --"
expect_deny "sentinel too-few" "${NEG_FEW_SENT}" "must run >= 3 Sentinels"

echo "-- negative (Sentinel runs plain redis-server, no monitor) MUST be DENIED --"
expect_deny "sentinel no-monitor" "${NEG_NO_MON}" "must run Sentinel"

echo "-- positive (compliant AOF config) MUST PASS --"
expect_pass "redis compliant config" "${POS_CONFIG}"

echo "-- positive (compliant 3-replica Redis StatefulSet) MUST PASS --"
expect_pass "redis compliant statefulset" "${POS_REDIS}"

echo "-- positive (compliant 3-Sentinel StatefulSet) MUST PASS --"
expect_pass "sentinel compliant statefulset" "${POS_SENTINEL}"

if [ "${fail}" -ne 0 ]; then
  echo "::error::Redis Sentinel HA-tier policy bite FAILED" >&2
  exit 1
fi
echo "Redis Sentinel HA-tier policy bite: all directions correct (AOF + auth-by-ref + quorum + monitor)."
