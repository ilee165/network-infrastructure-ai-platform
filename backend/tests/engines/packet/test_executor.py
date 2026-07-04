"""Self-confining packet-analysis executor child (ADR-0049 T1).

Exercised entirely on the eager / enforcement-off path: the real seccomp filter
load is a Linux-kernel operation and is a deferred CI bite-proof (ADR-0049
§Acceptance), so here the libseccomp binding is injected as a fake and the
confinement steps are driven through the module seams. What IS pinned:

- request parsing (stdin JSON → :class:`ExecutorRequest`; bad input → USAGE);
- the blocker-pinned confinement ORDER (rlimits → no-new-privs → seccomp →
  self-verify → posture → analysis);
- FAIL CLOSED — a confinement-setup error with enforcement on exits with a
  distinct code and NEVER opens the pcap;
- the self-verify parse (``/proc/self/status`` positive + negative);
- the enforcement-off fallback returns one :class:`PacketFindings` JSON on stdout;
- ``PR_SET_PDEATHSIG`` is wired onto the tshark child;
- the filter is PROGRAMMED BY PARSING the committed strict JSON (single source of
  truth) — default deny action, ``kill_process`` override, unknown-syscall skip;
- the ``--self-test`` denied / not-confined exit codes for the CI bite-proof;
- diagnostics are sanitized (no raw filter / pcap bytes on stderr).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.engines.packet import executor
from app.engines.packet.analysis import PacketFindings
from app.engines.packet.executor import (
    ConfinementError,
    ExecutorRequest,
    ExitCode,
    build_syscall_filter,
    load_seccomp_profile,
    main,
    parse_seccomp_profile,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeFilter:
    """Records how the filter was programmed (no kernel load)."""

    def __init__(
        self,
        defaction: Any,
        *,
        raise_on: frozenset[str] = frozenset(),
        rule_exc: type[BaseException] = ValueError,
        preadded_arch: Any = None,
    ) -> None:
        self.defaction = defaction
        self.arches: list[Any] = []
        self.rules: list[tuple[Any, str]] = []
        self.loaded = False
        self._raise_on = raise_on
        self._rule_exc = rule_exc
        # The native arch libseccomp's SyscallFilter pre-adds for the running kernel.
        if preadded_arch is not None:
            self.arches.append(preadded_arch)

    def add_arch(self, arch: Any) -> None:
        # pyseccomp (ctypes) raises FileExistsError/EEXIST when re-adding an arch
        # that is already present (e.g. the native arch SyscallFilter pre-added).
        if arch in self.arches:
            raise FileExistsError(17, "File exists")
        self.arches.append(arch)

    def add_rule(self, action: Any, name: str) -> None:
        if name in self._raise_on:
            raise self._rule_exc(f"unknown syscall {name!r}")
        self.rules.append((action, name))

    def load(self) -> None:
        self.loaded = True


class _FakeArch:
    X86_64 = "X86_64"
    X86 = "X86"
    X32 = "X32"
    AARCH64 = "AARCH64"
    ARM = "ARM"


class _FakeSeccomp:
    """A stand-in for the libseccomp Python binding."""

    ALLOW = "ALLOW"
    KILL = "KILL"
    KILL_PROCESS = "KILL_PROCESS"
    LOG = "LOG"
    TRAP = "TRAP"
    Arch = _FakeArch

    def __init__(
        self,
        *,
        raise_on: frozenset[str] = frozenset(),
        rule_exc: type[BaseException] = ValueError,
        preadded_arch: Any = None,
    ) -> None:
        self.raise_on = raise_on
        self.rule_exc = rule_exc
        self.preadded_arch = preadded_arch
        self.last_filter: _FakeFilter | None = None

    @staticmethod
    def ERRNO(ret: int) -> Any:  # noqa: N802 — mirrors the libseccomp binding name
        return ("ERRNO", ret)

    def SyscallFilter(self, defaction: Any) -> _FakeFilter:  # noqa: N802 — binding name
        flt = _FakeFilter(
            defaction,
            raise_on=self.raise_on,
            rule_exc=self.rule_exc,
            preadded_arch=self.preadded_arch,
        )
        self.last_filter = flt
        return flt


class _FakeLibc:
    def __init__(self, *, ptrace_ret: int = 0, prctl_ret: int = 0) -> None:
        self.ptrace_ret = ptrace_ret
        self.prctl_ret = prctl_ret
        self.prctl_calls: list[tuple[int, ...]] = []

    def prctl(self, *args: int) -> int:
        self.prctl_calls.append(args)
        return self.prctl_ret

    def ptrace(self, *args: int) -> int:
        return self.ptrace_ret


def _request(**overrides: Any) -> ExecutorRequest:
    base: dict[str, Any] = {"pcap_path": "/data/pcaps/cap.pcap", "enforced": True}
    base.update(overrides)
    return ExecutorRequest.model_validate(base)


# ---------------------------------------------------------------------------
# Profile parsing — the committed JSON is the single source of truth
# ---------------------------------------------------------------------------


def test_parse_seccomp_profile_from_committed_json() -> None:
    profile = load_seccomp_profile()
    assert profile.default_action == "SCMP_ACT_ERRNO"
    assert profile.default_errno_ret == 1
    # archMap flattened: primary + sub-architectures.
    assert "SCMP_ARCH_X86_64" in profile.architectures
    assert "SCMP_ARCH_X86" in profile.architectures
    assert "SCMP_ARCH_X32" in profile.architectures
    assert "SCMP_ARCH_AARCH64" in profile.architectures
    # every allow group is preserved; read (file I/O) present, socket absent.
    allowed = {name for rule in profile.rules for name in rule.names}
    assert {"read", "openat", "execve", "prctl"} <= allowed
    assert "socket" not in allowed
    assert "ptrace" not in allowed
    assert all(rule.action == "SCMP_ACT_ALLOW" for rule in profile.rules)


def test_parse_seccomp_profile_defaults_errno_ret() -> None:
    profile = parse_seccomp_profile(
        {"defaultAction": "SCMP_ACT_ERRNO", "archMap": [], "syscalls": []}
    )
    assert profile.default_errno_ret == 1  # documented default when absent


# ---------------------------------------------------------------------------
# build_syscall_filter — translate JSON → libseccomp (fake binding)
# ---------------------------------------------------------------------------


def test_build_filter_default_deny_is_errno() -> None:
    profile = load_seccomp_profile()
    module = _FakeSeccomp()
    flt = build_syscall_filter(profile, module, deny_action="errno")
    assert flt.defaction == ("ERRNO", 1)  # JSON's SCMP_ACT_ERRNO, errno 1
    # architectures programmed from archMap.
    assert set(flt.arches) == {"X86_64", "X86", "X32", "AARCH64", "ARM"}
    # every allowed syscall added with ALLOW; read present.
    added = {name for _action, name in flt.rules}
    assert "read" in added and "openat" in added
    assert all(action == "ALLOW" for action, _name in flt.rules)


def test_build_filter_kill_process_override() -> None:
    profile = load_seccomp_profile()
    flt = build_syscall_filter(profile, _FakeSeccomp(), deny_action="kill_process")
    assert flt.defaction == "KILL_PROCESS"  # ADR-0049 blocker 8 escalation


def test_build_filter_unknown_deny_action_falls_back_to_json_default() -> None:
    profile = load_seccomp_profile()
    flt = build_syscall_filter(profile, _FakeSeccomp(), deny_action="bogus")
    assert flt.defaction == ("ERRNO", 1)  # honors the committed JSON default


def test_build_filter_skips_allow_syscall_unknown_to_this_libseccomp() -> None:
    """A syscall name this libseccomp build lacks is skipped for an ALLOW rule —
    skipping an allow only leaves it denied by default (strictly safer)."""
    profile = load_seccomp_profile()
    module = _FakeSeccomp(raise_on=frozenset({"futex_waitv"}))
    flt = build_syscall_filter(profile, module, deny_action="errno")
    added = {name for _action, name in flt.rules}
    assert "futex_waitv" not in added
    assert "futex" in added  # the rest of the group still added


def test_build_filter_tolerates_readding_native_arch_eexist() -> None:
    """pyseccomp (ctypes) raises ``FileExistsError``/EEXIST when re-adding the arch
    ``SyscallFilter`` already pre-added for the running kernel. build_syscall_filter
    must tolerate it and keep going — the CI ``--self-check`` regression (exit 90,
    ``FileExistsError``) that the fake-only unit suite previously hid."""
    profile = load_seccomp_profile()
    module = _FakeSeccomp(preadded_arch="X86_64")  # native arch pre-added, like libseccomp
    flt = build_syscall_filter(profile, module, deny_action="errno")  # must NOT raise
    assert "X86_64" in flt.arches  # pre-added, re-add tolerated
    assert {"X86", "X32", "AARCH64", "ARM"} <= set(flt.arches)  # the rest still added
    assert "read" in {name for _a, name in flt.rules}  # rules programmed after archs


def test_build_filter_skips_allow_syscall_oserror() -> None:
    """A syscall unknown to *this* libseccomp raises an OSError family error under
    the pyseccomp ctypes binding (not ValueError); an ALLOW rule is still skipped
    (strictly safer), matching the official-binding ValueError path."""
    profile = load_seccomp_profile()
    module = _FakeSeccomp(raise_on=frozenset({"futex_waitv"}), rule_exc=OSError)
    flt = build_syscall_filter(profile, module, deny_action="errno")
    added = {name for _action, name in flt.rules}
    assert "futex_waitv" not in added
    assert "futex" in added


# ---------------------------------------------------------------------------
# _install_seccomp_filter — end to end with the fake binding (covers load())
# ---------------------------------------------------------------------------


def test_install_seccomp_filter_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _FakeSeccomp()
    monkeypatch.setattr(executor, "_import_seccomp", lambda: module)
    executor._install_seccomp_filter(_request(deny_action="errno"))
    assert module.last_filter is not None
    assert module.last_filter.loaded is True


def test_import_seccomp_missing_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """BOTH binding spellings absent is a confinement failure, NOT a fallback
    trigger (ADR-0049 blocker 1 — never key confinement on an ImportError).

    Drives the REAL ``_import_seccomp`` (the code under test is its ImportError →
    ConfinementError wrapping): a patched ``__import__`` makes both ``import
    seccomp`` and ``import pyseccomp`` fail deterministically on any platform, so
    this bites on the Linux CI unit runner too (where the binding IS installed).
    """
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name in ("seccomp", "pyseccomp"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    with pytest.raises(ConfinementError):
        executor._import_seccomp()


def test_import_seccomp_falls_back_to_pyseccomp(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the official ``seccomp`` C binding is absent, fall back to the
    pip-installable ``pyseccomp`` fork (pyseccomp's documented drop-in pattern).

    This is the packet-analysis image's REAL runtime path — the official binding
    is not on PyPI, so only ``pyseccomp`` is installed. Regression pin for the CI
    build-time ``--self-check`` failure (``import seccomp`` alone → exit 90).
    """
    import builtins

    sentinel = object()
    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "seccomp":
            raise ImportError("No module named 'seccomp'")
        if name == "pyseccomp":
            return sentinel
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    assert executor._import_seccomp() is sentinel


# ---------------------------------------------------------------------------
# _set_rlimits — bounds set before confinement (injected resource recorder)
# ---------------------------------------------------------------------------


def test_set_rlimits_sets_all_bounds_before_confinement(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[int, int]]] = []

    class _FakeResource:
        RLIMIT_CPU = "CPU"
        RLIMIT_AS = "AS"
        RLIMIT_FSIZE = "FSIZE"
        RLIMIT_NOFILE = "NOFILE"
        RLIMIT_NPROC = "NPROC"
        RLIMIT_CORE = "CORE"

        def setrlimit(self, which: str, limits: tuple[int, int]) -> None:
            calls.append((which, limits))

    monkeypatch.setattr(executor, "_import_resource", lambda: _FakeResource())
    executor._set_rlimits(_request(timeout_seconds=60, rlimit_as_bytes=123, rlimit_nproc=8))

    setmap = dict(calls)
    assert setmap["CPU"] == (65, 65)  # timeout + margin
    assert setmap["AS"] == (123, 123)
    assert setmap["NPROC"] == (8, 8)
    assert setmap["CORE"] == (0, 0)


def test_set_rlimits_wraps_failure_as_confinement_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AngryResource:
        RLIMIT_CPU = "CPU"

        def setrlimit(self, *_a: Any) -> None:
            raise OSError("nope")

    monkeypatch.setattr(executor, "_import_resource", lambda: _AngryResource())
    with pytest.raises(ConfinementError):
        executor._set_rlimits(_request())


def test_set_no_new_privs_raises_on_prctl_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_libc", lambda: _FakeLibc(prctl_ret=-1))
    with pytest.raises(ConfinementError):
        executor._set_no_new_privs()


# ---------------------------------------------------------------------------
# Self-verify (ADR-0049 order step e)
# ---------------------------------------------------------------------------


def test_self_verify_true_when_confined(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        executor, "_read_proc_self_status", lambda: "Name:\ttshark\nNoNewPrivs:\t1\nSeccomp:\t2\n"
    )
    assert executor._self_verify() is True


@pytest.mark.parametrize(
    "status",
    [
        "NoNewPrivs:\t0\nSeccomp:\t2\n",  # no-new-privs not set
        "NoNewPrivs:\t1\nSeccomp:\t0\n",  # no filter loaded
        "NoNewPrivs:\t1\n",  # Seccomp field absent
        "",  # empty (unreadable)
    ],
)
def test_self_verify_false_when_not_confined(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    monkeypatch.setattr(executor, "_read_proc_self_status", lambda: status)
    assert executor._self_verify() is False


def test_self_verify_false_on_unreadable_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> str:
        raise OSError("no /proc")

    monkeypatch.setattr(executor, "_read_proc_self_status", _raise)
    assert executor._self_verify() is False


# ---------------------------------------------------------------------------
# Ordering — the blocker-pinned confinement sequence (ADR-0049 §Design review)
# ---------------------------------------------------------------------------


def _record_confinement_seams(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    order: list[str] = []
    monkeypatch.setattr(executor, "_set_rlimits", lambda req: order.append("rlimits"))
    monkeypatch.setattr(executor, "_set_no_new_privs", lambda: order.append("no_new_privs"))
    monkeypatch.setattr(executor, "_install_seccomp_filter", lambda req: order.append("seccomp"))

    def _verify() -> bool:
        order.append("self_verify")
        return True

    monkeypatch.setattr(executor, "_self_verify", _verify)
    monkeypatch.setattr(executor, "_assert_posture", lambda: order.append("posture"))

    def _analyze(req: ExecutorRequest) -> PacketFindings:
        order.append("analysis")
        return PacketFindings(packet_count=1)

    monkeypatch.setattr(executor, "_run_confined_analysis", _analyze)
    return order


def test_enforced_path_runs_steps_in_pinned_order(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    order = _record_confinement_seams(monkeypatch)
    code = executor._execute(_request(enforced=True), self_test=None)
    assert code == ExitCode.OK
    assert order == [
        "rlimits",
        "no_new_privs",
        "seccomp",
        "self_verify",
        "posture",
        "analysis",
    ]


# ---------------------------------------------------------------------------
# FAIL CLOSED (ADR-0049 blocker 1) — pcap never opened on a confinement failure
# ---------------------------------------------------------------------------


def _guard_analysis_never_runs(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    opened: list[str] = []
    monkeypatch.setattr(
        executor, "_run_confined_analysis", lambda req: opened.append(req.pcap_path)
    )
    monkeypatch.setattr(executor, "_fallback_analyze", lambda req: opened.append(req.pcap_path))
    return opened


def test_fail_closed_on_confinement_setup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_set_rlimits", lambda req: None)

    def _boom() -> None:
        raise ConfinementError("PR_SET_NO_NEW_PRIVS failed")

    monkeypatch.setattr(executor, "_set_no_new_privs", _boom)
    monkeypatch.setattr(executor, "_install_seccomp_filter", lambda req: None)
    opened = _guard_analysis_never_runs(monkeypatch)

    code = executor._execute(_request(enforced=True), self_test=None)
    assert code == ExitCode.CONFINEMENT_SETUP_FAILED
    assert opened == []  # the pcap was NEVER opened


def test_fail_closed_when_self_verify_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_confine", lambda req: None)
    monkeypatch.setattr(executor, "_self_verify", lambda: False)
    opened = _guard_analysis_never_runs(monkeypatch)

    code = executor._execute(_request(enforced=True), self_test=None)
    assert code == ExitCode.SELF_VERIFY_FAILED
    assert opened == []


def test_fail_closed_when_posture_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.engines.packet.posture import PostureError

    monkeypatch.setattr(executor, "_confine", lambda req: None)
    monkeypatch.setattr(executor, "_self_verify", lambda: True)

    def _bad_posture() -> None:
        raise PostureError("effective UID is 0 (root); the parser must run non-root")

    monkeypatch.setattr(executor, "_assert_posture", _bad_posture)
    opened = _guard_analysis_never_runs(monkeypatch)

    code = executor._execute(_request(enforced=True), self_test=None)
    assert code == ExitCode.POSTURE_FAILED
    assert opened == []


# ---------------------------------------------------------------------------
# Enforcement OFF — the eager / Windows-dev fallback
# ---------------------------------------------------------------------------


def test_enforcement_off_uses_unconfined_fallback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    confined: list[str] = []
    monkeypatch.setattr(executor, "_confine", lambda req: confined.append("confine"))
    monkeypatch.setattr(
        executor, "_fallback_analyze", lambda req: PacketFindings(packet_count=5, tcp_resets=2)
    )

    code = executor._execute(_request(enforced=False), self_test=None)

    assert code == ExitCode.OK
    assert confined == []  # confinement never attempted when enforcement is off
    out = capsys.readouterr().out
    # stdout is EXACTLY one PacketFindings JSON document.
    assert json.loads(out) == PacketFindings(packet_count=5, tcp_resets=2).model_dump()
    assert out == PacketFindings(packet_count=5, tcp_resets=2).model_dump_json()


def test_stdout_is_exactly_one_json_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(executor, "_fallback_analyze", lambda req: PacketFindings(packet_count=3))
    executor._execute(_request(enforced=False), self_test=None)
    out = capsys.readouterr().out
    decoder = json.JSONDecoder()
    _obj, end = decoder.raw_decode(out)
    assert out[end:].strip() == ""  # nothing after the single document


# ---------------------------------------------------------------------------
# PR_SET_PDEATHSIG wiring (ADR-0049 blocker 5)
# ---------------------------------------------------------------------------


def test_spawn_tshark_wires_pdeathsig(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Completed:
        returncode = 0
        stdout = b"[]"

    def _fake_run(argv: list[str], **kwargs: Any) -> Any:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Completed()

    monkeypatch.setattr(executor.subprocess, "run", _fake_run)
    out = executor._spawn_tshark(["tshark", "-r", "x.pcap"], timeout_seconds=5)

    assert out == b"[]"
    assert captured["kwargs"]["preexec_fn"] is executor._pdeathsig_preexec
    assert captured["kwargs"]["shell"] is False


def test_pdeathsig_preexec_calls_prctl(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = _FakeLibc()
    monkeypatch.setattr(executor, "_libc", lambda: libc)
    executor._pdeathsig_preexec()
    assert libc.prctl_calls == [(executor._PR_SET_PDEATHSIG, executor._SIGKILL, 0, 0, 0)]


# ---------------------------------------------------------------------------
# tshark / normalization failures map to TSHARK_FAILED
# ---------------------------------------------------------------------------


def test_tshark_failure_maps_to_distinct_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.engines.packet.sandbox import SandboxError

    def _boom(req: ExecutorRequest) -> PacketFindings:
        raise SandboxError("tshark exceeded the timeout")

    monkeypatch.setattr(executor, "_fallback_analyze", _boom)
    code = executor._execute(_request(enforced=False), self_test=None)
    assert code == ExitCode.TSHARK_FAILED


# ---------------------------------------------------------------------------
# Display-filter re-validation (defense in depth) + sanitized diagnostics
# ---------------------------------------------------------------------------


def test_hostile_filter_rejected_before_any_analysis(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened = _guard_analysis_never_runs(monkeypatch)
    hostile = "tcp; rm -rf /"

    code = executor._execute(_request(enforced=False, display_filter=hostile), self_test=None)

    assert code == ExitCode.FILTER_REJECTED
    assert opened == []
    captured = capsys.readouterr()
    # The raw hostile filter is NEVER echoed to stdout or stderr.
    assert hostile not in captured.err
    assert hostile not in captured.out
    assert captured.out == ""


def test_diagnostics_never_leak_pcap_path_on_confinement_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_path = "/data/pcaps/super-secret-capture.pcap"
    monkeypatch.setattr(executor, "_set_rlimits", lambda req: None)
    monkeypatch.setattr(
        executor, "_set_no_new_privs", lambda: (_ for _ in ()).throw(ConfinementError("x"))
    )
    monkeypatch.setattr(executor, "_install_seccomp_filter", lambda req: None)

    executor._execute(_request(enforced=True, pcap_path=secret_path), self_test=None)
    captured = capsys.readouterr()
    assert secret_path not in captured.err
    assert secret_path not in captured.out


# ---------------------------------------------------------------------------
# --self-test probe exit codes (ADR-0049 blocker 4 — the CI bite-proof)
# ---------------------------------------------------------------------------


def test_self_test_denied_when_probe_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_confine", lambda req: None)
    monkeypatch.setattr(executor, "_self_verify", lambda: True)
    monkeypatch.setattr(executor, "_assert_posture", lambda: None)
    opened = _guard_analysis_never_runs(monkeypatch)

    def _denied(kind: str) -> bool:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(executor, "_attempt_probe", _denied)

    code = executor._execute(_request(enforced=True), self_test="socket")
    assert code == ExitCode.SELFTEST_DENIED
    assert opened == []  # self-test never falls through to analysis


def test_self_test_not_confined_when_probe_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The negative control: unconfined, the SAME probe succeeds → a distinct
    NOT-confined code so a broken filter fails the gate loudly."""
    monkeypatch.setattr(executor, "_attempt_probe", lambda kind: True)
    code = executor._execute(_request(enforced=False), self_test="socket")
    assert code == ExitCode.SELFTEST_NOT_CONFINED


def test_attempt_probe_socket_succeeds_unconfined() -> None:
    # Real socket() with no confinement returns True (the probe genuinely works).
    assert executor._attempt_probe("socket") is True


def test_attempt_probe_ptrace_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_libc", lambda: _FakeLibc(ptrace_ret=-1))
    with pytest.raises(OSError):
        executor._attempt_probe("ptrace")


def test_attempt_probe_ptrace_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_libc", lambda: _FakeLibc(ptrace_ret=0))
    assert executor._attempt_probe("ptrace") is True


def test_attempt_probe_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown self-test probe"):
        executor._attempt_probe("bpf")


# ---------------------------------------------------------------------------
# main() — stdin request parsing
# ---------------------------------------------------------------------------


def test_main_parses_stdin_and_runs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = json.dumps(
        {"pcap_path": "/data/pcaps/a.pcap", "enforced": False, "top_n": 3}
    ).encode()
    monkeypatch.setattr(executor, "_read_stdin", lambda: payload)
    monkeypatch.setattr(executor, "_fallback_analyze", lambda req: PacketFindings(packet_count=9))

    code = main([])
    assert code == ExitCode.OK
    assert json.loads(capsys.readouterr().out)["packet_count"] == 9


def test_main_rejects_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_read_stdin", lambda: b"not json {")
    assert main([]) == ExitCode.USAGE


def test_main_rejects_request_missing_required_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_read_stdin", lambda: json.dumps({"enforced": False}).encode())
    assert main([]) == ExitCode.USAGE  # pcap_path missing → ValidationError


# ---------------------------------------------------------------------------
# --self-check (build-time; ADR-0049 blocker 7)
# ---------------------------------------------------------------------------


def test_self_check_ok_with_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_import_seccomp", lambda: _FakeSeccomp())
    assert main(["--self-check"]) == ExitCode.OK


def test_self_check_fails_without_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    def _missing() -> Any:
        raise ConfinementError("libseccomp binding unavailable (ImportError)")

    monkeypatch.setattr(executor, "_import_seccomp", lambda: _missing())
    assert main(["--self-check"]) == ExitCode.SELF_CHECK_FAILED
