"""Capture orchestration + analysis-summarizer tests (M5; ADR-0023 §1/§2).

Argv/CLI builders are pure functions — asserted to be lists/discrete lines with
the duration/size caps enforced and untrusted interface/filter values rejected
(injection rejection). No subprocess, no network.
"""

from __future__ import annotations

import pytest

from app.engines.packet import (
    MAX_DURATION_SECONDS,
    MAX_SIZE_BYTES,
    CaptureSpec,
    build_eos_capture_commands,
    build_tcpdump_argv,
    summarize_packets,
    validate_interface,
)
from app.engines.packet.capture import InterfaceValidationError
from app.engines.packet.filters import FilterValidationError

# ---------------------------------------------------------------------------
# Interface whitelist — injection rejection (SECURITY-CRITICAL)
# ---------------------------------------------------------------------------

_MALICIOUS_INTERFACES = [
    "eth0; rm -rf /",
    "eth0 && reboot",
    "$(reboot)",
    "-w/tmp/evil",  # leading dash → would be a flag
    "eth0 -i lo",  # whitespace → second token
    "eth0|nc",
    "../../etc/passwd",  # leading dot rejected (must start alnum letter)
    "",
]


@pytest.mark.parametrize("bad", _MALICIOUS_INTERFACES)
def test_malicious_interface_is_rejected(bad: str) -> None:
    with pytest.raises(InterfaceValidationError):
        validate_interface(bad)


@pytest.mark.parametrize("good", ["eth0", "Ethernet1", "Ethernet1/1", "ens192.100", "em0"])
def test_legitimate_interface_passes(good: str) -> None:
    assert validate_interface(good) == good


def test_capture_spec_rejects_malicious_filter_and_interface() -> None:
    with pytest.raises(InterfaceValidationError):
        CaptureSpec.create(interface="eth0; rm -rf /")
    with pytest.raises(FilterValidationError):
        CaptureSpec.create(interface="eth0", capture_filter="tcp; rm -rf /")


# ---------------------------------------------------------------------------
# Caps (mandatory duration/size bounds, ADR-0023 §2)
# ---------------------------------------------------------------------------


def test_capture_spec_clamps_duration_and_size_to_caps() -> None:
    spec = CaptureSpec.create(
        interface="eth0", duration_seconds=99999, size_bytes=10 * MAX_SIZE_BYTES
    )
    assert spec.duration_seconds == MAX_DURATION_SECONDS
    assert spec.size_bytes == MAX_SIZE_BYTES


def test_capture_spec_rejects_nonpositive_bounds() -> None:
    with pytest.raises(ValueError):
        CaptureSpec.create(interface="eth0", duration_seconds=0)


# ---------------------------------------------------------------------------
# tcpdump argv builder — list, no shell, capped, filter as discrete tokens
# ---------------------------------------------------------------------------


def test_build_tcpdump_argv_is_capped_list() -> None:
    spec = CaptureSpec.create(
        interface="eth0", capture_filter="tcp port 443", duration_seconds=120
    )
    argv = build_tcpdump_argv(spec, "/data/pcaps/abc.pcap")
    assert isinstance(argv, list)
    assert argv[0] == "tcpdump"
    assert argv[argv.index("-i") + 1] == "eth0"
    assert argv[argv.index("-w") + 1] == "/data/pcaps/abc.pcap"
    assert argv[argv.index("-G") + 1] == "120"  # duration cap honored
    # The BPF filter tokens are appended as discrete argv elements.
    assert argv[-3:] == ["tcp", "port", "443"]


def test_build_tcpdump_argv_without_filter_has_no_trailing_expression() -> None:
    spec = CaptureSpec.create(interface="eth0")
    argv = build_tcpdump_argv(spec, "/data/pcaps/x.pcap")
    assert argv[-2:] == ["-C", str(MAX_SIZE_BYTES // (1024 * 1024))]


# ---------------------------------------------------------------------------
# eos monitor-session builder — discrete CLI lines, capped
# ---------------------------------------------------------------------------


def test_build_eos_capture_commands_are_discrete_capped_lines() -> None:
    spec = CaptureSpec.create(
        interface="Ethernet1", capture_filter="tcp port 443", duration_seconds=60
    )
    commands = build_eos_capture_commands(spec, "flash:cap.pcap")
    assert isinstance(commands, list)
    assert all(isinstance(c, str) for c in commands)
    joined = "\n".join(commands)
    assert "monitor capture netops interface Ethernet1 both" in joined
    assert "limit duration 60" in joined
    assert "copy capture netops flash:cap.pcap" in joined
    # No shell metacharacters in any generated line (validated inputs only).
    assert ";" not in joined and "|" not in joined and "&" not in joined


# ---------------------------------------------------------------------------
# Analysis summarizer — top talkers / protocols (no payload bytes)
# ---------------------------------------------------------------------------


def _pkt(src: str, dst: str, proto: str, length: int = 100) -> dict:
    layers = {
        "frame": {"frame.len": str(length)},
        "ip": {"ip.src": src, "ip.dst": dst},
        proto: {},
    }
    return {"_source": {"layers": layers}}


def test_summarize_packets_ranks_top_talkers() -> None:
    packets = [
        _pkt("10.0.0.1", "10.0.0.2", "tcp"),
        _pkt("10.0.0.1", "10.0.0.2", "tcp"),
        _pkt("10.0.0.3", "10.0.0.4", "udp"),
    ]
    findings = summarize_packets(packets)
    assert findings.packet_count == 3
    assert findings.top_talkers[0].src == "10.0.0.1"
    assert findings.top_talkers[0].dst == "10.0.0.2"
    assert findings.top_talkers[0].packets == 2
    protocols = {p.protocol: p.packets for p in findings.protocol_hierarchy}
    assert protocols["tcp"] == 2
    assert protocols["udp"] == 1


def test_summarize_counts_tcp_resets_and_retransmissions() -> None:
    rst = {
        "_source": {
            "layers": {
                "frame": {"frame.len": "60"},
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                "tcp": {
                    "tcp.flags.reset": "1",
                    "tcp.analysis": {"tcp.analysis.retransmission": ""},
                },
            }
        }
    }
    findings = summarize_packets([rst])
    assert findings.tcp_resets == 1
    assert findings.tcp_retransmissions == 1
