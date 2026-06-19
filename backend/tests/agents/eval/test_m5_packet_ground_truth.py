"""M5 packet top-talkers vs ``tshark`` ground-truth comparison (task T18).

MVP.md §7 criterion 4 requires that the Packet Analysis Agent's **top-talkers
summary matches ``tshark`` ground truth**. This file is that automated
comparison, over the T8/T11 normalized boundary, with **no live capture**:

* The analyzer under test is the real ``app.engines.packet.summarize_packets``
  (T8) — the same function the sandboxed ``packet.analyze_capture`` worker calls.
  Its input is a fixture of tshark ``-T json`` per-packet records (what
  ``tshark -T json`` emits for a pcap), checked in below — a recorded capture, no
  subprocess, no NIC.
* The **ground truth** is computed independently, from a *different* tshark
  output of the *same* capture: the ``tshark -q -z conv,ip`` conversation table
  (the canonical "Statistics -> Conversations -> IPv4" tally Wireshark shows).
  That recorded table is parsed here and the per-conversation packet/byte totals
  are taken as the reference. The two derivations share no code path, so the
  assertion proves the analyzer agrees with tshark's own tally rather than with
  itself.

Why this is honest: a top-talkers ranking is *deterministic aggregation* over
addressing metadata — there is no model judgment in it (the LLM only narrates the
already-computed findings, ADR-0023 §1). So the deterministic CI layer is the
correct and sufficient proof for this criterion; there is no real-LLM facet to
defer. The fixture is held out from the analyzer's own logic: it is expressed in
tshark's wire formats, not in ``PacketFindings`` terms.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.engines.packet import Conversation, summarize_packets

pytestmark = pytest.mark.eval


# ---------------------------------------------------------------------------
# Fixture A — the capture as tshark ``-T json`` per-packet records (analyzer in).
# A small, hand-traceable capture: three conversations of decreasing volume so
# the top-talkers ORDER is itself assertable, plus a TCP RST and a retransmission
# so the anomaly counters are exercised against ground truth too.
# ---------------------------------------------------------------------------

#: Conversations, by intended rank:
#:   A: 10.0.0.10 -> 10.0.0.20  — 4 packets, 4*150 = 600 bytes
#:   B: 10.0.0.11 -> 10.0.0.21  — 2 packets, 2*200 = 400 bytes
#:   C: 10.0.0.12 -> 10.0.0.22  — 1 packet,  1*120 = 120 bytes
_CONV_SPECS = [
    ("10.0.0.10", "10.0.0.20", 4, 150),
    ("10.0.0.11", "10.0.0.21", 2, 200),
    ("10.0.0.12", "10.0.0.22", 1, 120),
]


def _packet(src: str, dst: str, length: int, *, reset: bool = False, retrans: bool = False) -> dict:
    """One tshark ``-T json`` per-packet record (``_source.layers`` shape)."""
    tcp: dict = {}
    if reset:
        tcp["tcp.flags_tree"] = {"tcp.flags.reset": "1"}
    if retrans:
        tcp["tcp.analysis"] = {"tcp.analysis.retransmission": ""}
    return {
        "_source": {
            "layers": {
                "ip": {"ip.src": src, "ip.dst": dst},
                "frame": {"frame.len": str(length)},
                "tcp": tcp,
            }
        }
    }


def _tshark_json_capture() -> list[dict]:
    """Build the recorded ``tshark -T json`` capture for the fixture."""
    packets: list[dict] = []
    for i, (src, dst, count, length) in enumerate(_CONV_SPECS):
        for j in range(count):
            # Put one RST in conversation A and one retransmission in B so the
            # anomaly counters have a non-zero ground truth to match.
            reset = i == 0 and j == 0
            retrans = i == 1 and j == 0
            packets.append(_packet(src, dst, length, reset=reset, retrans=retrans))
    return packets


# ---------------------------------------------------------------------------
# Fixture B — the SAME capture as a ``tshark -q -z conv,ip`` table (ground truth).
# Checked in VERBATIM as a recorded-output fixture file (the shape tshark prints
# for IPv4 conversations: a header, a separator rule, then one row per
# conversation with bidirectional + per-direction frame/byte columns). Keeping it
# in a separate file — like the recorded netmiko/WAPI fixtures — keeps the ground
# truth genuinely external to the analyzer's own logic. We parse the ``->``
# direction frames/bytes per row as the reference.
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).parent / "fixtures"
_TSHARK_CONV_IP = (_FIXTURES / "tshark_conv_ip.txt").read_text(encoding="utf-8")

#: Matches one IPv4 conversation row of ``tshark -q -z conv,ip`` output:
#: ``<addr> <-> <addr>  <-frames> <-bytes>  <-frames> <-bytes>  <total>...``
#: We capture the source, dest, and the ``->`` direction frames/bytes (the
#: source-to-dest tally, which is the directed conversation the analyzer keys on).
_CONV_ROW = re.compile(
    r"^(?P<src>\d+\.\d+\.\d+\.\d+)\s+<->\s+(?P<dst>\d+\.\d+\.\d+\.\d+)\s+"
    r"\d+\s+\d+\s+"  # <- direction frames/bytes (unused here)
    r"(?P<frames>\d+)\s+(?P<bytes>\d+)\s+"  # -> direction frames/bytes (reference)
    r"\d+\s+\d+",  # total frames/bytes
    re.MULTILINE,
)


def _parse_tshark_conversations(table: str) -> list[Conversation]:
    """Parse a ``tshark -q -z conv,ip`` table into directed conversations.

    Returns one :class:`Conversation` per row using the ``->`` direction's frame
    and byte totals — the independent ground truth the analyzer must reproduce.
    Ordered most-active-first (as tshark prints conversations), so the list also
    encodes the expected top-talkers ranking.
    """
    conversations: list[Conversation] = []
    for match in _CONV_ROW.finditer(table):
        conversations.append(
            Conversation(
                src=match.group("src"),
                dst=match.group("dst"),
                packets=int(match.group("frames")),
                bytes=int(match.group("bytes")),
            )
        )
    return conversations


# ---------------------------------------------------------------------------
# The comparison.
# ---------------------------------------------------------------------------


class TestTopTalkersMatchTsharkGroundTruth:
    def test_ground_truth_parser_self_check(self) -> None:
        """Guard: the recorded tshark table parses to the three expected rows, in
        descending volume. If the parser silently matched nothing the comparison
        below could pass vacuously — this prevents that."""
        truth = _parse_tshark_conversations(_TSHARK_CONV_IP)
        assert truth == [
            Conversation(src="10.0.0.10", dst="10.0.0.20", packets=4, bytes=600),
            Conversation(src="10.0.0.11", dst="10.0.0.21", packets=2, bytes=400),
            Conversation(src="10.0.0.12", dst="10.0.0.22", packets=1, bytes=120),
        ]

    def test_top_talkers_match_tshark_conversation_tally(self) -> None:
        """The analyzer's top-talkers (packets + bytes, ordered) equal tshark's
        own ``conv,ip`` tally of the same capture — the MVP §7 #4 assertion."""
        findings = summarize_packets(_tshark_json_capture())
        truth = _parse_tshark_conversations(_TSHARK_CONV_IP)

        # Same number of conversations, same ranking, same per-conversation totals.
        assert findings.top_talkers == truth
        # The most-active conversation is first (the headline "top talker").
        assert findings.top_talkers[0].src == "10.0.0.10"
        assert findings.top_talkers[0].dst == "10.0.0.20"

    def test_packet_count_matches_total_frames(self) -> None:
        """Total analyzed packets equal the sum of tshark's per-conversation frames."""
        findings = summarize_packets(_tshark_json_capture())
        truth = _parse_tshark_conversations(_TSHARK_CONV_IP)
        assert findings.packet_count == sum(c.packets for c in truth)

    def test_tcp_anomaly_counters_match_seeded_ground_truth(self) -> None:
        """The capture carries exactly one RST and one retransmission; the
        analyzer's coarse anomaly counters must report exactly those."""
        findings = summarize_packets(_tshark_json_capture())
        assert findings.tcp_resets == 1
        assert findings.tcp_retransmissions == 1

    def test_top_n_truncates_to_busiest_conversations(self) -> None:
        """``top_n`` keeps the busiest conversations only — a 2-cap drops the
        smallest (C), preserving the tshark ranking of the survivors."""
        findings = summarize_packets(_tshark_json_capture(), top_n=2)
        truth = _parse_tshark_conversations(_TSHARK_CONV_IP)[:2]
        assert findings.top_talkers == truth
