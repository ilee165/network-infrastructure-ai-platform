#!/usr/bin/env python3
"""Extract + base64-decode one Secret data key from a rendered Helm manifest.

Usage: extract_secret.py <rendered.yaml> <secret-name> <data-key>

Prints the decoded value (PEM) to stdout. Used by ci/mtls/render-twice.sh to pull
the dev-fallback mTLS cert material out of a `helm template` render for the L4
idempotency / consistency checks.

STDLIB ONLY (no PyYAML) so the CI `infra` job needs no extra pip install. The
render is well-formed Helm output: `---`-separated documents, each Secret has a
`metadata:`/`name:` and a `data:` block whose keys are `  <key>: <base64>` on one
line. We scan for the target Secret document, then its data key. This is a
narrow, render-shape-specific parser (not a general YAML reader) — sufficient for
the fixed structure templates/mtls-postgres.yaml emits.

Hardening (PR #76):
  - N9: the Secret is matched on `metadata.name` ONLY (the first `name:` under the
    top-level `metadata:` block), never on any `name:` field anywhere in the doc.
  - N10: the data value is base64-decoded with `validate=True`, so corrupt /
    malformed material fails the gate instead of being silently mangled.
"""

from __future__ import annotations

import base64
import binascii
import sys


def _documents(text: str) -> list[str]:
    return text.split("\n---")


def _metadata_name(lines: list[str]) -> str | None:
    """Return the `metadata.name` of a single YAML document, or None.

    N9: scope the name lookup to the `metadata:` block. We find the top-level
    `metadata:` key (no indentation) and return the FIRST `name:` nested directly
    under it (indented), stopping when the block ends (a non-indented line). This
    avoids matching an unrelated `name:` elsewhere in the document.
    """
    in_meta = False
    for line in lines:
        stripped = line.strip()
        # Top-level `metadata:` key — no indentation (it is a document-root key).
        if stripped == "metadata:" and not line.startswith((" ", "\t")):
            in_meta = True
            continue
        if in_meta:
            # A non-indented, non-blank line ends the metadata block.
            if stripped and not line.startswith(" "):
                break
            if stripped.startswith("name:"):
                return stripped.split("name:", 1)[1].strip()
    return None


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <rendered.yaml> <secret-name> <data-key>", file=sys.stderr)
        return 2
    path, name, key = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    for doc in _documents(text):
        lines = doc.splitlines()
        is_secret = any(line.strip() == "kind: Secret" for line in lines)
        if not is_secret:
            continue
        # N9: match ONLY metadata.name, not any `name:` field. A Secret can carry
        # unrelated `name:` keys (e.g. ownerReferences[].name, a label/annotation
        # value, or a port name nested elsewhere); keying off "any `name:`" could
        # match the wrong document. We track the top-level `metadata:` block and
        # read the FIRST `name:` directly under it (two-space indent).
        if name != _metadata_name(lines):
            continue
        # Find the data key line: `  <key>: <base64>` (indented two spaces under data:).
        in_data = False
        for line in lines:
            stripped = line.strip()
            if stripped == "data:":
                in_data = True
                continue
            if in_data and stripped and not line.startswith(" "):
                in_data = False
            if in_data and stripped.startswith(f"{key}:"):
                value = stripped.split(":", 1)[1].strip()
                # N10: STRICT base64 — reject malformed/corrupt material instead of
                # silently dropping bad characters, so corruption fails the gate.
                try:
                    decoded = base64.b64decode(value, validate=True)
                except (ValueError, binascii.Error) as exc:
                    print(
                        f"key {key!r} in Secret {name!r} is not valid base64: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                sys.stdout.buffer.write(decoded)
                return 0
        print(f"key {key!r} not found in Secret {name!r}", file=sys.stderr)
        return 1

    print(f"Secret {name!r} not found in {path!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
