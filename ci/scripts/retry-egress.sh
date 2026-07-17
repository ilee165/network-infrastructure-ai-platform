#!/usr/bin/env bash
# Retry dependency/advisory acquisition only for explicit transient failures.
# Three TOTAL attempts: 5s then 10s backoff. Assertion/tool failures exit once.
set -euo pipefail

usage() {
  echo "usage: retry-egress.sh [--timeout-seconds N] -- command [args ...]" >&2
  exit 64
}

timeout_seconds=300
if [[ "${1:-}" == "--timeout-seconds" ]]; then
  [[ $# -ge 3 ]] || usage
  timeout_seconds="$2"
  shift 2
fi
[[ "${1:-}" == "--" ]] || usage
shift
[[ $# -gt 0 ]] || usage
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || usage

is_transient() {
  local status="$1"
  local output_file="$2"

  # GNU timeout: the acquisition itself exceeded the explicit per-attempt cap.
  if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
    return 0
  fi

  grep -Eiq \
    'HTTP([^0-9]|[[:space:]])*(500|502|503|504)([^0-9]|$)|(^|[^0-9])(500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout)([^0-9]|$)|returned (an )?error: (500|502|503|504)([^0-9]|$)|status( code)?[^0-9]*(500|502|503|504)([^0-9]|$)|(^|[^A-Z0-9_])E(500|502|503|504)([^0-9]|$)|EAI_AGAIN|ECONNRESET|ECONNREFUSED|ENETUNREACH|ETIMEDOUT|ERR_SOCKET_TIMEOUT|Temporary failure in name resolution|Could not resolve host|Connection refused|Failed to connect to|Connection reset by peer|TLS handshake timeout|TLS[^[:cntrl:]]*timed out|[Rr]ead[Tt]imeout|[Cc]onnect[Tt]imeout|read timed out|connection timed out' \
    "$output_file"
}

for attempt in 1 2 3; do
  echo "retry-egress: attempt ${attempt}/3" >&2
  output_file="$(mktemp)"
  set +e
  timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" "$@" >"$output_file" 2>&1
  status=$?
  set -e
  cat "$output_file"

  if [[ "$status" -eq 0 ]]; then
    rm -f "$output_file"
    exit 0
  fi

  if ! is_transient "$status" "$output_file"; then
    echo "retry-egress: non-transient failure; not retrying (status=${status})" >&2
    rm -f "$output_file"
    exit "$status"
  fi

  rm -f "$output_file"
  if [[ "$attempt" -eq 3 ]]; then
    echo "retry-egress: transient failure persisted through attempt 3" >&2
    exit "$status"
  fi

  if [[ -n "${RETRY_EGRESS_BACKOFF_SECONDS:-}" ]]; then
    backoff="$RETRY_EGRESS_BACKOFF_SECONDS"
  elif [[ "$attempt" -eq 1 ]]; then
    backoff=5
  else
    backoff=10
  fi
  [[ "$backoff" =~ ^[0-9]+$ ]] || usage
  if [[ "$backoff" -gt 0 ]]; then
    echo "retry-egress: transient failure; backing off ${backoff}s" >&2
    sleep "$backoff"
  fi
done

exit 70  # pragma: no cover -- loop always returns.
