#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T7 compressed-soak drill
# (ADR-0047 §2 — the negative-control rule; ADR-0046 §1/§2/§6 SLOs/burn-rate;
# G-REL §315 compressed).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the compressed-soak drill (compressed-soak.sh)
# runs LIVE only on a kind cluster with the api + workers + PgBouncer + Redis HA
# topology, which CANNOT run on the authoring host (Windows, no Docker/Linux kind).
# ADR-0047 §2 nonetheless requires the drill's negative control be SHOWN to bite
# (plant → red → revert), never merely asserted. This self-test earns that proof
# WITHOUT a cluster, in TWO complementary layers:
#
#   LAYER 1 — the REAL promtool SLO-held bite (the load-bearing one). The drill's
#   core assertion is "the §6 SLOs stay within budget and NO burn-rate alert fires
#   over the window." We prove THAT bites against the ACTUAL W3-T2 recording rules +
#   W3-T3 burn-rate alerts with a real `promtool test rules` over a
#   compressed-soak-shaped timeseries (deploy/observability/slo-compressed-soak.test.yaml):
#   a HEALTHY sustained window fires NO alert (SLOs held), a PERTURBED window (the
#   injected error-rate + latency perturbation the drill applies with the negative
#   control) DOES fire the burn-rate alert (a burn-rate breach → RED). This is the
#   same rule + alert files Prometheus loads, so the SLO-held / no-alert assertion is
#   proven to bite cluster-free.
#
#   LAYER 2 — the drill-flow polarity against a fake kubectl. We run the REAL
#   compressed-soak.sh against a fake `kubectl` that simulates the api Deployment,
#   the Redis pod / queue LLENs, and the in-pod loadgen + resource probes, and assert
#   the OBSERVABLE polarity:
#     POSITIVE  — steady load, SLIs in budget, resources bounded → drill GREEN (exit 0)
#     NEGATIVE  — COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL=1 → the injected SLO
#                 regression breaches the availability + latency budgets over the
#                 window AND a resource leak trends up → the SLO-held + bounded-trend
#                 assertions go RED → drill RED (exit != 0)
#
# The NEGATIVE scenario is the planted regression; POSITIVE is the revert-to-green.
# A soak whose "SLOs held" would read green whether or not the SLIs were within
# budget — or that "no leak" whether or not a resource trended — is not a gate
# (P1-W4 false-green). Both layers ship here so the drill is a real gate.
#
# Run: ci/kind/selftest/compressed-soak-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness-ha` job runs this (no cluster needed — it is the local bite
#      proof for the live soak drill's negative control, incl. the real promtool run).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
REPO_ROOT="$(cd "${KIND_DIR}/../.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/compressed-soak.sh"
SOAK_PROMTOOL_TEST="${REPO_ROOT}/deploy/observability/slo-compressed-soak.test.yaml"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::compressed-soak.sh not found at ${CHECK}" >&2
  exit 2
fi
if [ ! -f "${SOAK_PROMTOOL_TEST}" ]; then
  echo "::error::compressed-soak promtool fixture not found at ${SOAK_PROMTOOL_TEST}" >&2
  exit 2
fi

# ==========================================================================
# LAYER 1 — REAL promtool SLO-held bite (the core assertion, cluster-free).
# ==========================================================================
# The healthy-window case asserts NO burn-rate alert fires; the negative-control
# cases assert the injected error-rate / latency perturbation DOES fire the alert.
# promtool exits non-zero if any expectation is unmet — so a rule/alert that never
# fires on the real regression FAILS here (the anti-false-green control). We require
# promtool on PATH (the observability CI job installs it; the kind-harness-ha job
# also has it available). If promtool is genuinely absent we FAIL loudly rather than
# skip the load-bearing SLO-held proof.
if command -v promtool >/dev/null 2>&1; then
  echo "== LAYER 1: real promtool SLO-held bite over the W3-T2/W3-T3 rules =="
  # promtool resolves rule_files relative to the fixture's dir, so run from there.
  if ( cd "${REPO_ROOT}/deploy/observability" && promtool test rules "slo-compressed-soak.test.yaml" ) ; then
    ok "promtool SLO-held bite: HEALTHY compressed-soak window fires NO burn-rate alert (SLOs held) AND the injected error-rate + latency perturbations DO fire the burn-rate alerts (a burn-rate breach → RED) — the SLO-held assertion bites against the real W3-T2/W3-T3 rules (ADR-0046 §2/§6; ADR-0047 §2)"
  else
    bad "promtool SLO-held bite FAILED — either the HEALTHY window falsely fired an alert, or an injected SLO regression did NOT fire its burn-rate alert (the SLO-held assertion does not bite; it is not a gate, ADR-0047 §2)"
  fi
else
  bad "promtool NOT on PATH — cannot run the load-bearing SLO-held bite proof (the compressed-soak drill's core assertion is 'no burn-rate alert fires over the window'; that must be proven against the real rules). Install promtool (the observability CI job does)."
fi

# ==========================================================================
# LAYER 2 — drill-flow polarity against a fake kubectl (no cluster).
# ==========================================================================
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH simulating just enough of the HA topology for
# compressed-soak.sh: the api Deployment exists; the platform + superuser Secrets
# resolve to throwaway dev values; a Redis pod exists; the in-pod exec is either
# redis-cli (RPUSH/LLEN/DEL) or the bash loadgen sample / resource probe. The sample
# line's SLI permilles flip on the negative-control flag the drill exports into the
# exec — so the SAME assertions the live cluster would evaluate are exercised. The
# resource probes return LEAK sentinels under the negative control (the drill turns
# those into a trending START→END delta), bounded values otherwise.
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the compressed-soak drill self-test. Deterministic, no cluster.
set -uo pipefail
args=("$@")
joined="$*"

case "${joined}" in
  *"get deploy"*)
    # api Deployment precondition existence check — present.
    exit 0 ;;
  *"get secret"*"jsonpath="*)
    # platform redis / cnpg superuser password (base64 of a throwaway dev value —
    # NOT a real secret).
    printf '%s' "ZHJpbGwtZGV2LXB3"; exit 0 ;;   # base64("drill-dev-pw")
  *"get pods"*"redis-sentinel"*|*"get pods"*"redis"*)
    echo "netops-redis-sentinel-0"; exit 0 ;;
  *"get pods"*"celery-queue=discovery"*|*"get pods"*"worker"*)
    echo "netops-worker-discovery-0"; exit 0 ;;
  *"apply -f"*|*"wait "*|*"delete pod"*|*"rollout status"*)
    exit 0 ;;
  *"exec -i"*|*"exec "*)
    cmd_all="$*"
    # (a) redis-cli (RPUSH the steady feed / LLEN the queue depth / DEL cleanup).
    if printf '%s' "${cmd_all}" | grep -q 'redis-cli'; then
      # Layout after the `_` sentinel: `_ <db> <verb> <key> [values…]`.
      redisverb=""; rediskey=""
      for i in "${!args[@]}"; do
        if [ "${args[$i]}" = "_" ]; then
          redisverb="${args[$((i+2))]:-}"; rediskey="${args[$((i+3))]:-}"; break
        fi
      done
      case "${redisverb}" in
        LLEN)  echo "0" ;;      # steady state: workers keep up → depth bounded
        RPUSH) echo "5" ;;
        DEL)   echo "1" ;;
        *)     echo "0" ;;
      esac
      exit 0
    fi
    # (b) the resource probes: PgBouncer conn count (pg_stat_activity) or worker RSS
    #     (cgroup memory). These are exec'd via bash -c / sh -c; the drill itself maps
    #     the negative control to LEAK sentinels BEFORE calling the fake, so here we
    #     just return a small bounded value for the positive path.
    if printf '%s' "${cmd_all}" | grep -q 'pg_stat_activity'; then
      echo "8"; exit 0        # bounded server-connection count
    fi
    if printf '%s' "${cmd_all}" | grep -q 'memory.current\|memory.usage_in_bytes'; then
      echo "20480"; exit 0    # bounded worker RSS (KiB)
    fi
    # (c) the bash loadgen sample. Read the positional args after `_`:
    #   <host> <port> <read_path> <metrics_path> <vus> <reqs> <boundary> <neg>
    if printf '%s' "${cmd_all}" | grep -q 'EPOCHREALTIME\|one_request\|SOAK sample'; then
      neg="0"
      for i in "${!args[@]}"; do
        if [ "${args[$i]}" = "_" ]; then neg="${args[$((i+8))]:-0}"; break; fi
      done
      if [ "${neg}" = "1" ]; then
        # NEGATIVE CONTROL: the injected SLO regression — availability error ratio,
        # too-slow fraction, AND discovery error rate all breach their fast-burn budgets
        # over the window (400‰ >> 14‰; 800‰ >> 720‰; 500‰ >> 144‰ for discovery).
        # disc_err_permille=500 proves the discovery SLO assertion is NOT tautological
        # (ADR-0047 §2: a planted regression must turn EVERY assertion RED).
        echo "SOAK sample avail_err_permille=400 slow_frac_permille=800 disc_err_permille=500 p95_ms=800 reqs=100"
      else
        # POSITIVE: every SLI well within budget.
        echo "SOAK sample avail_err_permille=0 slow_frac_permille=0 disc_err_permille=0 p95_ms=120 reqs=100"
      fi
      exit 0
    fi
    # Any other exec → succeed quietly.
    exit 0 ;;
  *)
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and a TINY compressed
# window (a couple of samples, near-zero sample interval) so the self-test is fast.
run_scenario() {
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    export CHART_NS="netops"
    export COMPRESSED_SOAK_WINDOW_S="1"          # 1s window → ~1-2 samples
    export COMPRESSED_SOAK_SAMPLE_INTERVAL_S="0" # no inter-sample sleep
    export COMPRESSED_SOAK_LOAD_VUS="2"
    export COMPRESSED_SOAK_LOAD_REQUESTS="4"
    export COMPRESSED_SOAK_QUEUE_FEED_PER_CYCLE="2"
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

echo "== LAYER 2: drill-flow polarity against a fake kubectl =="

# --- POSITIVE — SLIs in budget, resources bounded → GREEN ----------------------
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: steady load, §6 SLIs within budget over the window, resources bounded → drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path soak exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- NEGATIVE CONTROL — injected SLO regression + leak → RED -------------------
run_scenario export COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: injected error-rate + latency perturbation breaches the §6 SLO budgets over the window AND a resource leak trends up → drill RED (exit ${rc_neg}) — the SLO-held + bounded-trend assertions BITE (ADR-0047 §2)"
else
  bad "FALSE-GREEN: the negative control did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the SLO-held and/or bounded-resource-trend assertion specifically.
if grep -q "SLO BREACHED\|G-REL §315 VIOLATED\|TRENDED UP\|ADR-0047 §2 soak VIOLATED" "${LAST_LOG}"; then
  ok "negative-control RED is the SLO-held / bounded-resource-trend assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the SLO-held / trend assertion — check the bite is attributable (${LAST_LOG})"
fi

echo "== compressed-soak-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::compressed-soak bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "compressed-soak bite proof: (1) the real promtool run proves the §6 SLO-held / no-burn-rate-alert assertion bites against the W3-T2/W3-T3 rules (healthy window silent, injected regression fires); (2) the live drill is GREEN when the SLIs stay in budget + resources bounded and RED on an injected SLO regression + resource leak (ADR-0047 §2 negative control bites; ADR-0046 §2/§6; G-REL §315 compressed)."
