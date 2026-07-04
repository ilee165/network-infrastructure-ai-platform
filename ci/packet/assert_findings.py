#!/usr/bin/env python3
"""GREEN-leg check for the ADR-0049 packet-analysis bite-proof.

Reads the confined executor's stdout (a single ``PacketFindings.model_dump_json()``
document) on stdin and asserts it is schema-shaped and reflects the one-packet
fixture: every ``PacketFindings`` field present, and ``packet_count >= 1``. Runs on
the bare runner (stdlib only) over the captured container stdout — a mismatch means
the fully confined tshark dissection did not round-trip, which fails the gate.
"""

from __future__ import annotations

import json
import sys

# The keys PacketFindings.model_dump() always emits (backend/app/engines/packet/analysis.py).
_REQUIRED_KEYS = {
    "packet_count",
    "top_talkers",
    "protocol_hierarchy",
    "tcp_resets",
    "tcp_retransmissions",
}


def main() -> int:
    raw = sys.stdin.read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"FAIL: executor stdout is not one JSON document ({exc})\n")
        return 1
    if not isinstance(doc, dict):
        sys.stderr.write("FAIL: findings payload is not a JSON object\n")
        return 1
    missing = _REQUIRED_KEYS - doc.keys()
    if missing:
        sys.stderr.write(f"FAIL: findings missing PacketFindings keys {sorted(missing)}\n")
        return 1
    count = doc["packet_count"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        sys.stderr.write(f"FAIL: expected packet_count >= 1 from the fixture, got {count!r}\n")
        return 1
    sys.stdout.write(f"OK: schema-valid PacketFindings, packet_count={count}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
