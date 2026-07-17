#!/usr/bin/env bash
# Download one pinned tarball, verify SHA-256, then extract/install one member.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 4 ]]; then
  echo "usage: install-verified-tarball.sh URL SHA256 MEMBER DESTINATION" >&2
  exit 64
fi

url="$1"
expected_sha256="${2,,}"
member="$3"
destination="$4"

if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "install-verified-tarball: SHA-256 must be exactly 64 hexadecimal characters" >&2
  exit 64
fi
if [[ "$member" == /* || "$member" == *".."* ]]; then
  echo "install-verified-tarball: unsafe archive member" >&2
  exit 64
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
archive="$workdir/archive.tar.gz"
extract_dir="$workdir/extracted"
mkdir -p "$extract_dir"

bash "$script_dir/retry-egress.sh" --timeout-seconds 180 -- \
  curl -fsSL "$url" -o "$archive"
actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "install-verified-tarball: checksum mismatch" >&2
  echo "expected ${expected_sha256}" >&2
  echo "actual   ${actual_sha256}" >&2
  exit 1
fi

# Extraction is intentionally unreachable until the checksum comparison passes.
tar -xzf "$archive" -C "$extract_dir" -- "$member"
install -m 0755 "$extract_dir/$member" "$destination"
