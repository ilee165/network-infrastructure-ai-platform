#!/usr/bin/env python3
"""Generate a tiny, deterministic libpcap fixture for the ADR-0049 bite-proof.

The GREEN leg of the packet-analysis Linux bite-proof (``.github/workflows/ci.yml``
job ``packet-analysis-bite-proof``) needs a *real* pcap to push through the fully
confined executor. Rather than commit an opaque binary blob (which would also fight
the ``.gitattributes`` eol normalization), CI generates one at run time with this
stdlib-only writer: a classic-format libpcap containing exactly one
Ethernet/IPv4/UDP frame. tshark dissects it to a one-element ``-T json`` array, so
``summarize_packets`` returns ``packet_count == 1`` with a real
``10.0.0.1 -> 10.0.0.2`` conversation.

Usage::

    python3 gen_fixture_pcap.py <output-path>

No third-party dependencies (runs on the bare runner's system Python before the
container is built).
"""

from __future__ import annotations

import struct
import sys

# LINKTYPE_ETHERNET (see https://www.tcpdump.org/linktypes.html).
_LINKTYPE_ETHERNET = 1
# Classic pcap magic in host byte order (microsecond timestamps), version 2.4.
_PCAP_MAGIC = 0xA1B2C3D4


def _udp_over_ipv4_ethernet() -> bytes:
    """One minimal Ethernet/IPv4/UDP frame (payload ``b"hi"``).

    Header checksums are left zero — tshark flags them as bad but still dissects
    the packet, which is all the GREEN leg needs (a parseable, countable packet).
    """
    payload = b"hi"

    udp_len = 8 + len(payload)
    udp = struct.pack(
        ">HHHH",
        1234,  # src port
        4321,  # dst port
        udp_len,  # length
        0,  # checksum (0 = not computed)
    ) + payload

    total_len = 20 + udp_len
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5 (20 bytes)
        0x00,  # DSCP/ECN
        total_len,
        0x0000,  # identification
        0x0000,  # flags + fragment offset
        64,  # TTL
        17,  # protocol = UDP
        0x0000,  # header checksum (0 = not computed)
        bytes((10, 0, 0, 1)),  # src 10.0.0.1
        bytes((10, 0, 0, 2)),  # dst 10.0.0.2
    )

    ethernet = (
        bytes((0x02, 0x00, 0x00, 0x00, 0x00, 0x02))  # dst MAC (locally administered)
        + bytes((0x02, 0x00, 0x00, 0x00, 0x00, 0x01))  # src MAC
        + struct.pack(">H", 0x0800)  # EtherType = IPv4
    )
    return ethernet + ipv4 + udp


def build_pcap() -> bytes:
    """A complete classic-format libpcap byte stream with one packet."""
    global_header = struct.pack(
        "<IHHiIII",
        _PCAP_MAGIC,
        2,  # version major
        4,  # version minor
        0,  # thiszone (GMT)
        0,  # sigfigs
        65535,  # snaplen
        _LINKTYPE_ETHERNET,
    )
    frame = _udp_over_ipv4_ethernet()
    record_header = struct.pack(
        "<IIII",
        0,  # ts_sec
        0,  # ts_usec
        len(frame),  # captured length
        len(frame),  # original length
    )
    return global_header + record_header + frame


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: gen_fixture_pcap.py <output-path>\n")
        return 2
    with open(argv[1], "wb") as handle:
        handle.write(build_pcap())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
