"""Self-confining packet-analysis executor child (ADR-0049 — the executor-split).

ADR-0031 wrapped the *tshark* process in a strict seccomp profile, but that
profile is incompatible with the long-lived Celery consumer it was applied to
(the broker socket/epoll syscalls it denies). ADR-0049 resolves the contradiction
by **drawing the sandbox boundary around the untrusted work, not the Celery
machinery**: the dispatcher (the Celery consumer, ``app.workers.tasks.packet``)
spawns a fresh, short-lived ``python -m app.engines.packet.executor`` child *per
analysis job*; the child confines **itself** and only then parses the
attacker-controlled pcap.

This module is that child. Given one analysis request on **stdin** it, in the
blocker-pinned order (ADR-0049 §Design review outcome):

1. re-validates the display filter (defense in depth — the dispatcher already
   validated it, but the child never trusts its input);
2. sets resource limits (``RLIMIT_CPU`` derived from the timeout as the
   wedged-tshark backstop, ``RLIMIT_AS``/``FSIZE``/``NOFILE``/``NPROC`` bounds,
   ``RLIMIT_CORE=0``) **before** confinement;
3. sets ``PR_SET_NO_NEW_PRIVS`` (a dropped-privilege parser can never regain
   privileges via a setuid tshark);
4. loads a libseccomp filter **programmed by parsing the committed strict OCI
   JSON** (:data:`_SECCOMP_FILENAME`, byte-identical to the Compose/Helm copies —
   single source of truth, ADR-0049 blocker 3);
5. **self-verifies** ``/proc/self/status`` shows ``NoNewPrivs:\\t1`` and
   ``Seccomp:\\t2``, refusing otherwise;
6. runs the ADR-0031 §2 runtime posture backstop (non-root, no ``CAP_NET_RAW``,
   read-only rootfs);
7. **only then** spawns ``tshark`` (argv, never a shell; ``PR_SET_PDEATHSIG`` so a
   popped grandchild dies with the executor) and normalizes its output
   *in-process*, printing exactly one :class:`PacketFindings` JSON to stdout.

**Fail closed (ADR-0049 blocker 1, CRITICAL).** The confine-then-run path is taken
whenever ``enforced`` is true. If *any* confinement step fails — the libseccomp
binding is missing, a rlimit/prctl call errors, the filter will not load, or the
self-verify does not see a loaded filter — the executor exits **nonzero with a
distinct code and never opens the pcap**. The unconfined in-process fallback is
permitted **only** when the request says enforcement is off
(``packet_sandbox_posture_enforced=False`` — the eager-unit-test / Windows-dev
path); it is *never* chosen by catching an ``ImportError`` at runtime.

Contract with the dispatcher (:mod:`app.workers.tasks.packet`, T2):

- **stdin**: one JSON object — see :class:`ExecutorRequest`.
- **stdout (success)**: exit ``0``, exactly one JSON document =
  ``PacketFindings.model_dump()``.
- **failure**: nonzero exit + a short *sanitized* stderr diagnostic (never raw
  pcap bytes, child stderr verbatim, or secrets). Distinct codes — see
  :class:`ExitCode` — let the CI bite-proof (ADR-0049 §Acceptance) distinguish
  "denied as expected" from "not confined". The dispatcher maps any nonzero to
  ``SandboxError`` → the existing ``packet.analysis_failed`` audit.
"""

from __future__ import annotations

import argparse
import enum
import json
import subprocess  # noqa: S404 — argv-only, shell=False; the sandbox boundary itself
import sys
from dataclasses import dataclass
from importlib import resources
from typing import Any

from pydantic import BaseModel, ValidationError

from app.engines.packet.analysis import PacketFindings, summarize_packets
from app.engines.packet.filters import FilterValidationError, validate_capture_filter
from app.engines.packet.posture import PostureError, assert_sandbox_posture
from app.engines.packet.sandbox import DEFAULT_TSHARK_BIN, SandboxError, build_tshark_argv

__all__ = [
    "ExecutorRequest",
    "ExitCode",
    "main",
]

# --- packaged strict profile (single source of truth — ADR-0049 blocker 3) -----
#: Anchor package (has ``__init__``) + the in-package copy of the strict seccomp
#: profile, byte-identical to ``deploy/docker/seccomp`` / ``deploy/kubernetes``.
#: Loaded via :mod:`importlib.resources` so it ships as wheel package data.
_SECCOMP_ANCHOR = "app.engines.packet"
_SECCOMP_SUBDIR = "seccomp"
_SECCOMP_FILENAME = "packet-analysis-seccomp.json"

# --- rlimit / deny-action defaults ---------------------------------------------
# The dispatcher forwards the operator-tuned values from Settings in the request;
# these constants are the fail-safe fallback if a field is omitted, and MUST stay
# in step with the ``packet_sandbox_*`` defaults in ``app/core/config.py``.
_DEFAULT_RLIMIT_AS_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB — fits the 64 MB JSON parse
_DEFAULT_RLIMIT_FSIZE_BYTES = 64 * 1024 * 1024  # 64 MiB — bounds the /tmp scratch
_DEFAULT_RLIMIT_NOFILE = 256
# PER-UID (all uid-10001 tasks host-wide, incl. api/worker/beat), NOT per-tree;
# aligned with the compose pids_limit (512) — the cgroup is the primary
# fork-bomb bound, this rlimit is only a defence-in-depth backstop.
_DEFAULT_RLIMIT_NPROC = 512
_DEFAULT_DENY_ACTION = "errno"

#: Seconds added to ``timeout_seconds`` for the ``RLIMIT_CPU`` backstop, so the
#: soft-timeout (dispatcher ``killpg``) normally fires first and CPU-rlimit is the
#: hard floor for a wedged/spinning tshark (ADR-0049 blocker 4 / ADR-0023 §1).
_RLIMIT_CPU_MARGIN_SECONDS = 5

#: Defensive bound on tshark stdout (mirrors ``sandbox._MAX_OUTPUT_BYTES``).
_MAX_TSHARK_OUTPUT_BYTES = 64 * 1024 * 1024

# prctl options (``<linux/prctl.h>``) + signal number, referenced via ctypes.
_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_SIGKILL = 9

#: The child seccomp default (deny) action. ``errno`` (v1 default) makes a denied
#: syscall return ``EPERM`` — the self-test catches it and exits nonzero, proving
#: denial without risking a benign newer-glibc syscall killing the child;
#: ``kill_process`` (``SCMP_ACT_KILL_PROCESS``, SIGSYS-kill) is the follow-up once
#: the Linux green-path is proven on CI (ADR-0049 blocker 8).
_DENY_ACTION_TO_SCMP = {
    "errno": "SCMP_ACT_ERRNO",
    "kill_process": "SCMP_ACT_KILL_PROCESS",
}


class ExitCode(enum.IntEnum):
    """Distinct, documented executor exit codes (the dispatcher maps any nonzero
    to ``SandboxError``; the CI bite-proof asserts the specific codes)."""

    OK = 0
    #: stdin was not a valid request JSON, or CLI usage was wrong.
    USAGE = 64
    #: the display filter failed re-validation (defense in depth).
    FILTER_REJECTED = 65
    #: a confinement-setup step failed (binding import, rlimit, prctl, filter
    #: load) — the pcap was never opened (fail closed).
    CONFINEMENT_SETUP_FAILED = 70
    #: confinement installed but ``/proc/self/status`` did not confirm it.
    SELF_VERIFY_FAILED = 71
    #: the ADR-0031 §2 runtime posture backstop failed (root / CAP_NET_RAW / RW rootfs).
    POSTURE_FAILED = 72
    #: tshark failed to run, exited nonzero, timed out, or produced bad output.
    TSHARK_FAILED = 73
    #: ``--self-test``: the probe syscall was denied as expected (the RED leg passes).
    SELFTEST_DENIED = 80
    #: ``--self-test``: the probe syscall unexpectedly SUCCEEDED — the filter is
    #: broken; the gate must fail loudly.
    SELFTEST_NOT_CONFINED = 81
    #: ``--self-check``: the seccomp binding / profile is not build-complete.
    SELF_CHECK_FAILED = 90


class ExecutorRequest(BaseModel):
    """One analysis request, parsed from the untrusted stdin JSON.

    ``pcap_path``/``display_filter``/``tshark_bin``/``timeout_seconds``/``top_n``
    are the per-job analysis inputs; ``enforced`` is the fail-closed signal the
    dispatcher sources from ``settings.packet_sandbox_posture_enforced`` (the
    executor NEVER decides confinement by runtime detection — ADR-0049 blocker 1).
    The ``rlimit_*`` / ``deny_action`` knobs are the operator-tuned Settings values
    the dispatcher forwards; each defaults to a safe fallback so a minimal request
    still confines correctly.
    """

    pcap_path: str
    display_filter: str | None = None
    tshark_bin: str = DEFAULT_TSHARK_BIN
    timeout_seconds: float = 60.0
    top_n: int = 10
    enforced: bool = True
    rlimit_as_bytes: int = _DEFAULT_RLIMIT_AS_BYTES
    rlimit_fsize_bytes: int = _DEFAULT_RLIMIT_FSIZE_BYTES
    rlimit_nofile: int = _DEFAULT_RLIMIT_NOFILE
    rlimit_nproc: int = _DEFAULT_RLIMIT_NPROC
    deny_action: str = _DEFAULT_DENY_ACTION


class ConfinementError(RuntimeError):
    """A confinement-setup step failed; the executor must fail closed.

    Raised by any of the rlimit / no-new-privs / seccomp-filter steps. The message
    names the failed control only — never a pcap byte, secret, or filter internal.
    """


@dataclass(frozen=True)
class SyscallRule:
    """One ``syscalls[]`` group from the OCI profile: an action + its names."""

    action: str
    names: tuple[str, ...]


@dataclass(frozen=True)
class ParsedProfile:
    """The strict OCI seccomp JSON, parsed into the fields libseccomp needs."""

    default_action: str
    default_errno_ret: int
    architectures: tuple[str, ...]
    rules: tuple[SyscallRule, ...]


# ---------------------------------------------------------------------------
# Profile parsing (pure — the single source of truth is the committed JSON)
# ---------------------------------------------------------------------------


def parse_seccomp_profile(document: dict[str, Any]) -> ParsedProfile:
    """Parse the strict OCI seccomp *document* into a :class:`ParsedProfile`.

    Reads ``defaultAction``/``defaultErrnoRet``, flattens ``archMap`` (each
    architecture plus its sub-architectures), and preserves every ``syscalls[]``
    group's ``action`` + ``names``. Pure and platform-independent, so the eager
    unit suite exercises the translation without libseccomp present.
    """
    architectures: list[str] = []
    for entry in document.get("archMap", []):
        architectures.append(entry["architecture"])
        architectures.extend(entry.get("subArchitectures", []))
    rules = tuple(
        SyscallRule(action=group["action"], names=tuple(group["names"]))
        for group in document.get("syscalls", [])
    )
    return ParsedProfile(
        default_action=document["defaultAction"],
        default_errno_ret=int(document.get("defaultErrnoRet", 1)),
        architectures=tuple(architectures),
        rules=rules,
    )


def load_seccomp_profile() -> ParsedProfile:
    """Load + parse the in-package strict seccomp profile (packaged wheel data)."""
    text = (
        resources.files(_SECCOMP_ANCHOR)
        .joinpath(_SECCOMP_SUBDIR, _SECCOMP_FILENAME)
        .read_text(encoding="utf-8")
    )
    return parse_seccomp_profile(json.loads(text))


# ---------------------------------------------------------------------------
# libseccomp translation (seam: the module is imported lazily / injected in tests)
# ---------------------------------------------------------------------------


def _seccomp_action(module: Any, action: str, errno_ret: int) -> Any:
    """Map an ``SCMP_ACT_*`` string to the libseccomp action object."""
    if action == "SCMP_ACT_ALLOW":
        return module.ALLOW
    if action == "SCMP_ACT_ERRNO":
        return module.ERRNO(errno_ret)
    if action == "SCMP_ACT_KILL_PROCESS":
        return module.KILL_PROCESS
    if action == "SCMP_ACT_KILL":
        return module.KILL
    if action == "SCMP_ACT_LOG":
        return module.LOG
    if action == "SCMP_ACT_TRAP":
        return module.TRAP
    raise ConfinementError(f"unsupported seccomp action {action!r}")


def _resolve_default_action(module: Any, profile: ParsedProfile, deny_action: str) -> Any:
    """The filter's default (deny) action: the ``deny_action`` override if given,
    else the committed JSON's declared default (ADR-0049 blocker 8)."""
    scmp = _DENY_ACTION_TO_SCMP.get(deny_action, profile.default_action)
    return _seccomp_action(module, scmp, profile.default_errno_ret)


def _add_architectures(flt: Any, module: Any, architectures: tuple[str, ...]) -> None:
    """Add the profile's architectures to *flt* (the native arch is pre-added by
    ``SyscallFilter``; re-adding it or an arch this libseccomp lacks is benign).

    The two bindings signal "already present / unsupported arch" with different
    exception types: the official ``seccomp`` C binding raises
    ``ValueError``/``RuntimeError``, while the pip-installable ``pyseccomp`` ctypes
    fork surfaces the libseccomp errno as an ``OSError`` family error
    (``FileExistsError`` / ``EEXIST`` when re-adding the native arch — the CI
    ``--self-check`` regression). Tolerate all three; the native arch that matters
    for THIS kernel is already present regardless."""
    for name in architectures:
        arch = getattr(module.Arch, name.removeprefix("SCMP_ARCH_"), None)
        if arch is None:
            continue
        try:
            flt.add_arch(arch)
        except (ValueError, RuntimeError, OSError):
            continue


def build_syscall_filter(profile: ParsedProfile, module: Any, *, deny_action: str) -> Any:
    """Program a libseccomp ``SyscallFilter`` from *profile* (does NOT load it).

    Deny-by-default via :func:`_resolve_default_action`; every profile group's
    syscalls are added with the group's action. A syscall name unknown to *this*
    libseccomp build is skipped **only for an ALLOW rule** — a skipped allow just
    leaves that syscall denied by the default action (strictly safer); a skipped
    deny would be a hole, so it is re-raised. Both binding exception dialects are
    caught (``ValueError``/``RuntimeError`` from the official binding, ``OSError``
    family from the pyseccomp ctypes fork).
    """
    flt = module.SyscallFilter(defaction=_resolve_default_action(module, profile, deny_action))
    _add_architectures(flt, module, profile.architectures)
    for rule in profile.rules:
        action = _seccomp_action(module, rule.action, profile.default_errno_ret)
        allow = rule.action == "SCMP_ACT_ALLOW"
        for name in rule.names:
            try:
                flt.add_rule(action, name)
            except (ValueError, RuntimeError, OSError):
                if allow:
                    continue
                raise
    return flt


# ---------------------------------------------------------------------------
# Confinement steps (seams; POSIX-only, only reached on the enforced path)
# ---------------------------------------------------------------------------


def _import_resource() -> Any:
    """Import the POSIX ``resource`` module (seam; typed ``Any`` so the rlimit
    constants — which typeshed guards behind non-win32 — never trip mypy on the
    Windows dev host, and so tests can inject a recorder)."""
    import resource

    return resource


def _import_seccomp() -> Any:
    """Import the libseccomp Python binding (seam). Fail CLOSED: a missing binding
    with enforcement on is a confinement-setup failure, NOT a fallback trigger
    (ADR-0049 blocker 1).

    Follows pyseccomp's own documented drop-in pattern: prefer the official
    ``seccomp`` C binding (distro ``python3-seccomp``); else the pip-installable,
    API-compatible pure-python ``pyseccomp`` fork — which is the wheel the
    packet-analysis image actually ships (the official binding is not on PyPI, so
    ``import seccomp`` alone fails in the image → the CI build-time ``--self-check``
    ``ConfinementError``, exit 90). This is NOT the blocker-1 forbidden fallback:
    both names being absent still raises ``ConfinementError``; only the *binding's
    two import spellings* are tried, never a fall-through to unconfined analysis."""
    try:
        import seccomp
    except ImportError:
        try:
            import pyseccomp as seccomp
        except ImportError as exc:
            raise ConfinementError(
                f"libseccomp binding unavailable ({type(exc).__name__})"
            ) from exc
    return seccomp


def _libc() -> Any:
    """Return a ``ctypes`` handle on libc for ``prctl`` (seam; injected in tests)."""
    import ctypes

    return ctypes.CDLL(None, use_errno=True)


def _set_rlimits(request: ExecutorRequest) -> None:
    """Set resource limits BEFORE confinement (ADR-0049 order step b).

    ``RLIMIT_CPU`` (timeout + margin) is the hard backstop for a wedged/spinning
    tshark; ``RLIMIT_AS``/``FSIZE``/``NOFILE``/``NPROC`` bound memory, scratch
    writes, fds, and forks; ``RLIMIT_CORE=0`` blocks a core dump of pcap bytes.
    """
    res = _import_resource()
    cpu = max(1, int(request.timeout_seconds) + _RLIMIT_CPU_MARGIN_SECONDS)
    try:
        res.setrlimit(res.RLIMIT_CPU, (cpu, cpu))
        res.setrlimit(res.RLIMIT_AS, (request.rlimit_as_bytes, request.rlimit_as_bytes))
        res.setrlimit(res.RLIMIT_FSIZE, (request.rlimit_fsize_bytes, request.rlimit_fsize_bytes))
        res.setrlimit(res.RLIMIT_NOFILE, (request.rlimit_nofile, request.rlimit_nofile))
        res.setrlimit(res.RLIMIT_NPROC, (request.rlimit_nproc, request.rlimit_nproc))
        res.setrlimit(res.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError, OverflowError) as exc:
        raise ConfinementError(f"setting resource limits failed ({type(exc).__name__})") from exc


def _set_no_new_privs() -> None:
    """``prctl(PR_SET_NO_NEW_PRIVS, 1)`` (ADR-0049 order step c)."""
    import ctypes

    libc = _libc()
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise ConfinementError(f"prctl(PR_SET_NO_NEW_PRIVS) failed (errno {ctypes.get_errno()})")


def _install_seccomp_filter(request: ExecutorRequest) -> None:
    """Program the filter from the committed JSON and load it (ADR-0049 step d)."""
    profile = load_seccomp_profile()
    module = _import_seccomp()
    flt = build_syscall_filter(profile, module, deny_action=request.deny_action)
    try:
        flt.load()
    except Exception as exc:  # noqa: BLE001 — any load failure must fail closed
        raise ConfinementError(f"seccomp filter load failed ({type(exc).__name__})") from exc


def _confine(request: ExecutorRequest) -> None:
    """Install all confinement in the blocker-pinned order (b → c → d)."""
    _set_rlimits(request)
    _set_no_new_privs()
    _install_seccomp_filter(request)


# ---------------------------------------------------------------------------
# Self-verify (ADR-0049 order step e) + posture backstop (step f)
# ---------------------------------------------------------------------------


def _read_proc_self_status() -> str:
    """Read ``/proc/self/status`` (seam; injected in tests)."""
    with open("/proc/self/status", encoding="utf-8") as handle:
        return handle.read()


def _self_verify() -> bool:
    """Confirm the kernel shows the process confined: ``NoNewPrivs`` == 1 AND
    ``Seccomp`` == 2 (SECCOMP_MODE_FILTER). A missing/unreadable status fails
    closed (returns ``False``)."""
    try:
        status = _read_proc_self_status()
    except OSError:
        return False
    fields: dict[str, str] = {}
    for line in status.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields.get("NoNewPrivs") == "1" and fields.get("Seccomp") == "2"


def _assert_posture() -> None:
    """Run the ADR-0031 §2 runtime posture backstop (seam)."""
    assert_sandbox_posture(enforced=True)


# ---------------------------------------------------------------------------
# tshark spawn (with PR_SET_PDEATHSIG — ADR-0049 blocker 5) + normalization
# ---------------------------------------------------------------------------


def _pdeathsig_preexec() -> None:  # pragma: no cover - runs post-fork in the child, pre-exec
    """Pre-exec hook: ``prctl(PR_SET_PDEATHSIG, SIGKILL)`` so tshark dies if the
    executor dies (ADR-0049 blocker 5). Runs in the forked child before ``execve``;
    the *wiring* (that ``subprocess.run`` receives this as ``preexec_fn``) is what
    the unit suite pins — the body only ever runs on the real Linux fork."""
    _libc().prctl(_PR_SET_PDEATHSIG, _SIGKILL, 0, 0, 0)


def _spawn_tshark(argv: list[str], *, timeout_seconds: float) -> bytes:
    """Spawn tshark (argv, ``shell=False``, ``close_fds`` default) with the
    ``PR_SET_PDEATHSIG`` pre-exec hook; return its stdout bytes or raise
    :class:`SandboxError` on a nonzero exit / oversize output.
    """
    completed = subprocess.run(  # noqa: S603 — argv list, shell=False, validated inputs
        argv,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
        shell=False,
        preexec_fn=_pdeathsig_preexec,
    )
    if completed.returncode != 0:
        raise SandboxError(f"tshark exited with status {completed.returncode}")
    stdout = completed.stdout or b""
    if len(stdout) > _MAX_TSHARK_OUTPUT_BYTES:
        raise SandboxError("tshark output exceeded the sandbox size bound")
    return stdout


def _run_confined_analysis(request: ExecutorRequest) -> PacketFindings:
    """Spawn tshark under confinement and normalize its output IN THIS PROCESS.

    Mirrors :func:`app.engines.packet.sandbox.analyze_pcap` but uses
    :func:`_spawn_tshark` (PR_SET_PDEATHSIG) so the normalization
    (``json.loads`` + ``summarize_packets``) runs inside the sandbox — the
    dispatcher only ever receives small, schema-shaped findings.
    """
    argv = build_tshark_argv(
        request.pcap_path, display_filter=request.display_filter, tshark_bin=request.tshark_bin
    )
    try:
        stdout = _spawn_tshark(argv, timeout_seconds=request.timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(
            f"tshark analysis exceeded the {request.timeout_seconds:g}s sandbox timeout"
        ) from exc
    except FileNotFoundError as exc:
        raise SandboxError("tshark binary is not available in the sandbox") from exc
    try:
        packets: Any = json.loads(stdout.decode("utf-8") or "[]")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxError("tshark produced unparseable output") from exc
    if not isinstance(packets, list):
        raise SandboxError("tshark output was not a packet array")
    return summarize_packets(packets, top_n=request.top_n)


def _fallback_analyze(request: ExecutorRequest) -> PacketFindings:
    """Unconfined in-process analysis — permitted ONLY when enforcement is off
    (the eager-unit-test / Windows-dev path; ADR-0049 blocker 1)."""
    from app.engines.packet.sandbox import analyze_pcap

    return analyze_pcap(
        request.pcap_path,
        display_filter=request.display_filter,
        tshark_bin=request.tshark_bin,
        timeout_seconds=request.timeout_seconds,
        top_n=request.top_n,
    )


# ---------------------------------------------------------------------------
# Self-test probe (ADR-0049 blocker 4 — used by the CI bite-proof)
# ---------------------------------------------------------------------------


def _attempt_probe(kind: str) -> bool:
    """Attempt the *kind* probe syscall AFTER confinement is installed.

    Returns ``True`` if the syscall SUCCEEDED (only possible unconfined — the
    negative control) and raises ``OSError``/``PermissionError`` if it was denied
    (``EPERM`` under the errno deny action). Under a ``kill_process`` deny action a
    denied syscall kills the process outright, so this never returns.
    """
    if kind == "socket":
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.close()
        return True
    if kind == "ptrace":
        import ctypes

        libc = _libc()
        if libc.ptrace(0, 0, 0, 0) == -1:  # PTRACE_TRACEME
            raise OSError(ctypes.get_errno(), "ptrace denied")
        return True
    raise ValueError(f"unknown self-test probe {kind!r}")


# ---------------------------------------------------------------------------
# Diagnostics + entrypoint
# ---------------------------------------------------------------------------


def _emit_diag(message: str) -> None:
    """Write a SHORT sanitized diagnostic to stderr — never pcap bytes, child
    stderr verbatim, secrets, or the raw display filter."""
    sys.stderr.write(f"packet-executor: {message}\n")


def _read_stdin() -> bytes:
    """Read the raw request bytes from stdin (seam; injected in tests)."""
    return sys.stdin.buffer.read()


def _run_self_check() -> int:
    """Build-time ``--self-check`` (ADR-0049 blocker 7): prove the libseccomp
    binding and the packaged profile are present by parsing the JSON and BUILDING
    the filter (no ``load()`` — no kernel needed). Any failure exits nonzero so the
    image build fails on a missing wheel/library/data-file."""
    try:
        profile = load_seccomp_profile()
        module = _import_seccomp()
        build_syscall_filter(profile, module, deny_action=_DEFAULT_DENY_ACTION)
    except Exception as exc:  # noqa: BLE001 — build probe: ANY failure fails the build
        # Build-time only (no untrusted pcap data in scope), and the confinement
        # errors are already sanitized to type/step names — so surfacing the
        # message here makes a self-check failure debuggable from the build log
        # instead of an opaque "(ConfinementError)".
        _emit_diag(f"self-check failed ({type(exc).__name__}: {exc})")
        return int(ExitCode.SELF_CHECK_FAILED)
    return int(ExitCode.OK)


def _execute(request: ExecutorRequest, *, self_test: str | None) -> int:
    """Run the ordered confine-then-analyze pipeline; return an :class:`ExitCode`."""
    # (a) re-validate the display filter — defense in depth, before anything else.
    try:
        validate_capture_filter(request.display_filter)
    except FilterValidationError as exc:
        _emit_diag(f"display filter rejected ({exc.slug})")
        return int(ExitCode.FILTER_REJECTED)

    if request.enforced:
        # (b–d) confine — fail CLOSED: any failure aborts before the pcap is opened.
        try:
            _confine(request)
        except ConfinementError as exc:
            _emit_diag(f"confinement setup failed: {exc}")
            return int(ExitCode.CONFINEMENT_SETUP_FAILED)
        # (e) self-verify the kernel actually confined us.
        if not _self_verify():
            _emit_diag("self-verify failed: NoNewPrivs/Seccomp not set")
            return int(ExitCode.SELF_VERIFY_FAILED)
        # (f) runtime posture backstop.
        try:
            _assert_posture()
        except PostureError as exc:
            _emit_diag(f"posture check failed ({exc.slug})")
            return int(ExitCode.POSTURE_FAILED)

    # Self-test runs only AFTER confinement is fully installed.
    if self_test is not None:
        try:
            succeeded = _attempt_probe(self_test)
        except OSError:
            return int(ExitCode.SELFTEST_DENIED)
        return int(ExitCode.SELFTEST_NOT_CONFINED if succeeded else ExitCode.SELFTEST_DENIED)

    # (g) ONLY THEN touch the pcap: spawn tshark + normalize in-process.
    try:
        if request.enforced:
            findings = _run_confined_analysis(request)
        else:
            findings = _fallback_analyze(request)
    except (SandboxError, FilterValidationError) as exc:
        _emit_diag(f"tshark analysis failed ({type(exc).__name__})")
        return int(ExitCode.TSHARK_FAILED)

    sys.stdout.write(findings.model_dump_json())
    sys.stdout.flush()
    return int(ExitCode.OK)


def main(argv: list[str] | None = None) -> int:
    """Entrypoint for ``python -m app.engines.packet.executor``."""
    parser = argparse.ArgumentParser(prog="app.engines.packet.executor", add_help=True)
    parser.add_argument(
        "--self-test",
        choices=["socket", "ptrace"],
        default=None,
        help="after confinement, attempt a denied syscall to prove the filter bites",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="build-time check: the seccomp binding + packaged profile are present",
    )
    args = parser.parse_args(argv)

    if args.self_check:
        return _run_self_check()

    try:
        payload = json.loads(_read_stdin() or b"{}")
        request = ExecutorRequest.model_validate(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
        _emit_diag(f"invalid request ({type(exc).__name__})")
        return int(ExitCode.USAGE)

    return _execute(request, self_test=args.self_test)


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
