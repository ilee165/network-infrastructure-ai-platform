#!/usr/bin/env bash
# Generate a DEV-ONLY self-signed TLS certificate for the compose edge proxy
# (M5 hardening, ADR-0013 §3). Writes tls.crt / tls.key into deploy/docker/tls/certs/,
# which docker-compose.tls.yml mounts read-only into the `edge` container.
#
# DEV ONLY. A self-signed cert triggers a browser trust warning and provides NO
# identity assurance. For production, terminate TLS with a CA-issued certificate
# (the Kubernetes Ingress TLS path, ADR-0013 §4) — never ship this cert.
#
# Usage (from anywhere):
#   bash deploy/docker/tls/generate-dev-cert.sh [COMMON_NAME]
# COMMON_NAME defaults to "localhost"; the SAN list covers localhost + 127.0.0.1.

set -euo pipefail

CN="${1:-localhost}"
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/tls.crt" || -f "$CERT_DIR/tls.key" ]]; then
  echo "refusing to overwrite existing cert in $CERT_DIR (remove it first)" >&2
  exit 1
fi

# Run from the cert dir with relative output paths and guard only the OpenSSL
# call against Git-Bash/MSYS path conversion: MSYS rewrites a leading-slash arg
# like "/CN=localhost" into a Windows path, so MSYS_NO_PATHCONV keeps -subj
# verbatim. Relative -keyout/-out are unaffected by it. No-op on Linux/macOS.
cd "$CERT_DIR"
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey rsa:2048 \
  -days 365 \
  -keyout tls.key \
  -out tls.crt \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:localhost,DNS:${CN},IP:127.0.0.1"

chmod 600 tls.key
echo "wrote dev self-signed cert to $CERT_DIR/{tls.crt,tls.key} (CN=${CN}, 365d)"
echo "DEV ONLY — browsers will warn; do not use in production."
