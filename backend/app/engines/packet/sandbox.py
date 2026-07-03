"""Sandboxed tshark invocation (M5; ADR-0023 §1 — the critical containment).

A pcap is **untrusted input** and tshark's C dissectors carry parsing CVEs, so
running tshark over an attacker-influenced file is the single most dangerous
operation in the platform. This module is the only place that spawns tshark, and
it does so under the concrete sandbox controls ADR-0023 §1 mandates:

- **argv list, never a shell** — :func:`build_tshark_argv` returns a ``list[str]``
  passed to ``subprocess.run`` with ``shell=False`` (the default). The pcap path
  and any display filter are *argv elements*, never interpolated into a command
  string, so a filename like ``"; rm -rf / #"`` or a filter containing shell
  metacharacters cannot be executed — they are inert data to the child.
- **filter whitelist** — any display filter is validated by
  :func:`app.engines.packet.filters.validate_capture_filter` *before* the argv is
  built; a rejected filter raises and no process is spawned.
- **no name resolution** — ``-n`` is always passed, so dissection performs no
  DNS/host/port lookups (no egress is triggered by analysis).
- **hard subprocess timeout** — the tshark child is bounded by
  ``settings.packet_analysis_timeout_seconds``; an oversized/slow/hostile capture
  fails the task (``subprocess.TimeoutExpired`` → :class:`SandboxError`) rather
  than wedging the worker.

The OS-level controls (no-network container, dropped capabilities, non-root,
read-only pcap mount, CPU/memory limits) are the deployment's responsibility
(Compose/K8s, ADR-0023 §1) — this module enforces the *process-launch* controls
that live in code and is the layer the unit tests pin (argv-not-shell, ``-n``
present, filter validated, timeout honored).

**Executor-split dispatch (ADR-0049).** :func:`analyze_pcap` still runs tshark
*in-process* and is kept as (a) the enforcement-off fallback the executor child
uses on a non-Linux/dev host and (b) the synchronous API analyzer's path. The
deployed Celery ``packet.analyze_capture`` path no longer parses pcap bytes here:
:func:`run_executor` is the **dispatcher** half of the split — it spawns a
short-lived, self-confining ``python -m app.engines.packet.executor`` child, reaps
it (SIGKILLing the whole process group on timeout so no wedged/popped tshark
grandchild survives — ADR-0049 blocker 4), and validates the child's stdout into a
bounded :class:`PacketFindings` (marshalling), so the dispatcher only ever handles
small, schema-shaped findings and never ``json.loads`` raw tshark output.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess  # noqa: S404 — argv-only, shell=False; the sandbox boundary itself
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import PluginError
from app.engines.packet.analysis import (
    Conversation,
    PacketFindings,
    ProtocolCount,
    summarize_packets,
)
from app.engines.packet.filters import validate_capture_filter

__all__ = [
    "DEFAULT_TSHARK_BIN",
    "SandboxError",
    "analyze_pcap",
    "build_tshark_argv",
    "parse_executor_findings",
    "run_executor",
]

#: Default tshark binary name; the worker resolves an absolute path from settings.
DEFAULT_TSHARK_BIN = "tshark"

#: Cap on bytes read from tshark stdout — a defensive bound on the JSON the child
#: can return (a hostile/huge capture is already bounded by the size cap at
#: capture time and the subprocess timeout here).
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024

# --- executor-split dispatch (ADR-0049 blockers 1/2/4 + marshalling) -----------
#: The confined-child module the dispatcher spawns (``python -m <this>``).
_EXECUTOR_MODULE = "app.engines.packet.executor"

#: Seconds added to the child's own analysis timeout for the OUTER (dispatcher)
#: subprocess bound, so the child's ``RLIMIT_CPU``/``PR_SET_PDEATHSIG`` normally
#: fire first and the dispatcher's ``killpg`` is the backstop (ADR-0049 blocker 4).
_SPAWN_TIMEOUT_MARGIN_SECONDS = 10

#: Seconds to wait for the group to die after a ``killpg`` before giving up reaping.
_REAP_TIMEOUT_SECONDS = 5

#: ``SIGKILL`` as a literal (``signal.SIGKILL`` is POSIX-only and would trip mypy
#: on the Windows dev host — the killpg path only runs on the enforced Linux tier).
_SIGKILL = 9

#: Marshalling caps on what a (possibly popped) child can push into the DB/audit/API
#: — belt-and-suspenders alongside ``packet_findings_max_bytes``. Realistic findings
#: are far smaller (top_talkers ~= top_n; protocol_hierarchy <= a handful).
_FINDINGS_MAX_ITEMS = 1000
_FINDINGS_MAX_STR = 256

#: Static exit-code -> short sanitized reason (mirrors ``executor.ExitCode``; not
#: imported to avoid a sandbox<->executor import cycle). Values are fixed strings —
#: never child-controlled — so they carry no pcap bytes / stderr / secrets.
_EXECUTOR_EXIT_REASONS = {
    64: "invalid executor request",
    65: "display filter rejected",
    70: "confinement setup failed",
    71: "confinement self-verify failed",
    72: "sandbox posture check failed",
    73: "tshark analysis failed",
    80: "self-test denied",
    81: "self-test not confined",
    90: "self-check failed",
}


class SandboxError(PluginError):
    """tshark analysis failed inside the sandbox (timeout, non-zero exit, bad output).

    Messages never embed raw packet bytes or the full untrusted filename beyond
    what is needed to identify the failure, and never re-emit child stderr that
    could carry attacker-controlled content into logs unfiltered.
    """

    title = "Packet Analysis Sandbox Failure"
    slug = "packet-analysis-sandbox-failure"


def build_tshark_argv(
    pcap_path: str | Path,
    *,
    display_filter: str | None = None,
    tshark_bin: str = DEFAULT_TSHARK_BIN,
) -> list[str]:
    """Build the tshark **argv list** for analyzing *pcap_path* (never a shell line).

    The returned list is passed verbatim to ``subprocess.run`` with the default
    ``shell=False``. ``-r <pcap_path>`` reads the (untrusted) file, ``-n``
    disables every name-resolution lookup, ``-T json`` requests machine-readable
    output, and an optional validated ``-Y <display_filter>`` constrains the
    decode. Because *pcap_path* and *display_filter* are appended as their own
    list elements, neither can introduce an extra flag or a shell command —
    that is the argv-not-shell guarantee (ADR-0023 §1).

    :raises app.engines.packet.filters.FilterValidationError: the display filter
        failed the whitelist (the argv is never built for a rejected filter).
    """
    validated = validate_capture_filter(display_filter)
    argv = [tshark_bin, "-r", str(pcap_path), "-n", "-T", "json"]
    if validated is not None:
        argv += ["-Y", validated]
    return argv


def analyze_pcap(
    pcap_path: str | Path,
    *,
    display_filter: str | None = None,
    tshark_bin: str = DEFAULT_TSHARK_BIN,
    timeout_seconds: float = 60.0,
    top_n: int = 10,
) -> PacketFindings:
    """Run tshark over *pcap_path* in the sandbox and return normalized findings.

    Spawns tshark via :func:`build_tshark_argv` with ``shell=False`` and a hard
    ``timeout_seconds`` bound, then parses its JSON into :class:`PacketFindings`
    (top talkers, protocol hierarchy, TCP anomalies). The pcap and its filter are
    treated as untrusted: the filter is whitelisted, the argv carries no shell,
    and a slow/hostile capture is killed at the timeout.

    :raises SandboxError: tshark exceeded the timeout, exited non-zero, or
        produced unparseable output.
    :raises app.engines.packet.filters.FilterValidationError: the display filter
        was rejected (raised before any subprocess is spawned).
    """
    argv = build_tshark_argv(pcap_path, display_filter=display_filter, tshark_bin=tshark_bin)
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, shell=False, validated inputs
            argv,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(
            f"tshark analysis exceeded the {timeout_seconds:g}s sandbox timeout"
        ) from exc
    except FileNotFoundError as exc:
        raise SandboxError("tshark binary is not available in the sandbox") from exc

    if completed.returncode != 0:
        raise SandboxError(f"tshark exited with status {completed.returncode}")

    stdout = completed.stdout or b""
    if len(stdout) > _MAX_OUTPUT_BYTES:
        raise SandboxError("tshark output exceeded the sandbox size bound")

    try:
        packets: Any = json.loads(stdout.decode("utf-8") or "[]")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxError("tshark produced unparseable output") from exc
    if not isinstance(packets, list):
        raise SandboxError("tshark output was not a packet array")

    return summarize_packets(packets, top_n=top_n)


# ---------------------------------------------------------------------------
# Executor-split dispatcher (ADR-0049 T2): spawn + reap the confined child,
# validate its findings. This is the deployed ``packet.analyze_capture`` path.
# ---------------------------------------------------------------------------


class _BoundedConversation(BaseModel):
    """Conversation with hard field caps for validating UNtrusted child stdout."""

    model_config = ConfigDict(extra="ignore")

    src: str = Field(max_length=_FINDINGS_MAX_STR)
    dst: str = Field(max_length=_FINDINGS_MAX_STR)
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)


class _BoundedProtocolCount(BaseModel):
    """ProtocolCount with hard field caps for validating untrusted child stdout."""

    model_config = ConfigDict(extra="ignore")

    protocol: str = Field(max_length=_FINDINGS_MAX_STR)
    packets: int = Field(ge=0)


class _BoundedFindings(BaseModel):
    """Length-bounded mirror of :class:`PacketFindings` used to validate the child.

    The executor child is the blast-radius process; a popped dissector could emit
    arbitrary JSON on stdout. This model enforces caps on list lengths and string
    field lengths so nothing unbounded reaches the DB/audit/API even if the child
    is compromised. Extra keys are ignored (a compromised child cannot smuggle
    fields), and the whole document is size-capped upstream.
    """

    model_config = ConfigDict(extra="ignore")

    packet_count: int = Field(default=0, ge=0)
    top_talkers: list[_BoundedConversation] = Field(
        default_factory=list, max_length=_FINDINGS_MAX_ITEMS
    )
    protocol_hierarchy: list[_BoundedProtocolCount] = Field(
        default_factory=list, max_length=_FINDINGS_MAX_ITEMS
    )
    tcp_resets: int = Field(default=0, ge=0)
    tcp_retransmissions: int = Field(default=0, ge=0)


def parse_executor_findings(stdout: bytes, *, max_bytes: int) -> PacketFindings:
    """Validate the executor child's stdout into a bounded :class:`PacketFindings`.

    The dispatcher never trusts the child's stdout unchecked (ADR-0049 marshalling
    must-address): the bytes are capped at a TIGHT findings-sized *max_bytes* (NOT
    the 64 MB raw-tshark cap), JSON-parsed, then validated against
    :class:`_BoundedFindings` (hard caps on list lengths and string fields) before
    anything reaches the DB/audit/API. Raw child bytes never enter the raised
    message or any log — only the static failure reason.

    :raises SandboxError: the output exceeded *max_bytes*, was not valid UTF-8
        JSON, or failed the bounded schema (a compromised/oversized child).
    """
    if len(stdout) > max_bytes:
        raise SandboxError("packet executor findings exceeded the size bound")
    try:
        payload: Any = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxError("packet executor produced unparseable findings") from exc
    try:
        bounded = _BoundedFindings.model_validate(payload)
    except ValidationError as exc:
        raise SandboxError("packet executor findings failed schema validation") from exc
    return PacketFindings(
        packet_count=bounded.packet_count,
        top_talkers=[Conversation(**c.model_dump()) for c in bounded.top_talkers],
        protocol_hierarchy=[ProtocolCount(**p.model_dump()) for p in bounded.protocol_hierarchy],
        tcp_resets=bounded.tcp_resets,
        tcp_retransmissions=bounded.tcp_retransmissions,
    )


def _child_env() -> dict[str, str]:
    """Minimal env allowlist for the executor child (ADR-0049 blocker 2, CRITICAL).

    Only ``PATH``/``TMPDIR``/``LANG``/``LC_*`` cross into the blast radius — never
    ``NETOPS_*`` secret material, the DB/broker URLs, or KEK vars. Combined with
    ``close_fds`` on the spawn (the live Redis/PG sockets do not cross the fork),
    a popped dissector inherits no credential from the dispatcher.
    """
    env: dict[str, str] = {}
    for key in ("PATH", "TMPDIR", "LANG"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    for key, value in os.environ.items():
        if key.startswith("LC_"):
            env[key] = value
    env.setdefault("PATH", os.defpath)
    return env


def _kill_process_group(proc: Any) -> None:
    """SIGKILL the child's whole process group (ADR-0049 blocker 4, MAJOR).

    The child is spawned with ``start_new_session=True`` so it leads its own
    process group; killing the group takes down a wedged/popped ``tshark``
    grandchild that would otherwise outlive the dispatcher's timeout. ``os.killpg``
    /``os.getpgid`` are POSIX-only (resolved dynamically so mypy does not flag them
    on the Windows dev host, and tests can inject them); a non-POSIX host or an
    already-reaped group falls back to a best-effort single-process kill.
    """
    killpg = getattr(os, "killpg", None)
    getpgid = getattr(os, "getpgid", None)
    if killpg is not None and getpgid is not None:
        try:
            killpg(getpgid(proc.pid), _SIGKILL)
            return
        except OSError:
            pass
    with contextlib.suppress(OSError):
        proc.kill()


def _spawn_and_reap(
    argv: list[str], *, request_bytes: bytes, timeout_seconds: float
) -> tuple[int, bytes]:
    """Spawn the executor child, feed it *request_bytes* on stdin, and reap it.

    Env-minimal + ``close_fds`` (blocker 2) and ``start_new_session=True`` so the
    child leads its own group; on the OUTER timeout the whole group is SIGKILLed
    (blocker 4) and a :class:`SandboxError` is raised. The child's stderr is
    captured but NEVER re-emitted (it is untrusted — ADR-0049 marshalling).
    """
    proc = subprocess.Popen(  # noqa: S603 — argv list, shell=False, minimal env, close_fds
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_child_env(),
        close_fds=True,
        start_new_session=True,
    )
    try:
        stdout, _stderr = proc.communicate(input=request_bytes, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(proc)
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.communicate(timeout=_REAP_TIMEOUT_SECONDS)
        raise SandboxError(
            f"packet executor exceeded the {timeout_seconds:g}s sandbox timeout"
        ) from exc
    returncode = proc.returncode
    if returncode is None:  # pragma: no cover — communicate() always sets it
        returncode = 1
    return returncode, stdout or b""


def run_executor(
    pcap_path: str | Path,
    *,
    display_filter: str | None = None,
    tshark_bin: str = DEFAULT_TSHARK_BIN,
    timeout_seconds: float = 60.0,
    top_n: int = 10,
    rlimit_as_bytes: int,
    rlimit_fsize_bytes: int,
    rlimit_nofile: int,
    rlimit_nproc: int,
    deny_action: str,
    max_output_bytes: int,
) -> PacketFindings:
    """Dispatch one analysis job to the confined executor child and return findings.

    The ADR-0049 dispatcher half: builds the pinned request JSON, spawns
    ``python -m app.engines.packet.executor`` (its own session, minimal env,
    ``close_fds``), reaps it — SIGKILLing the group on timeout — and validates the
    child's stdout into a bounded :class:`PacketFindings`. ``enforced`` is pinned
    ``True`` in the request because the dispatcher only spawns the child on the
    enforced tier (the enforcement-off dev/unit path stays in-process via
    :func:`analyze_pcap`); the executor still re-decides fail-closed from the same
    flag (ADR-0049 blocker 1). The dispatcher NEVER ``json.loads`` raw tshark
    output — that normalization runs inside the sandbox (the child).

    :raises SandboxError: the child exited nonzero (mapped to a static reason), the
        outer timeout fired (group killed), or its stdout failed the bounded schema.
    """
    request = {
        "pcap_path": str(pcap_path),
        "display_filter": display_filter,
        "tshark_bin": tshark_bin,
        "timeout_seconds": timeout_seconds,
        "top_n": top_n,
        "enforced": True,
        "rlimit_as_bytes": rlimit_as_bytes,
        "rlimit_fsize_bytes": rlimit_fsize_bytes,
        "rlimit_nofile": rlimit_nofile,
        "rlimit_nproc": rlimit_nproc,
        "deny_action": deny_action,
    }
    request_bytes = json.dumps(request).encode("utf-8")
    argv = [sys.executable, "-m", _EXECUTOR_MODULE]
    returncode, stdout = _spawn_and_reap(
        argv,
        request_bytes=request_bytes,
        timeout_seconds=timeout_seconds + _SPAWN_TIMEOUT_MARGIN_SECONDS,
    )
    if returncode != 0:
        reason = _EXECUTOR_EXIT_REASONS.get(returncode, "executor failed")
        raise SandboxError(f"packet executor: {reason} (exit {returncode})")
    return parse_executor_findings(stdout, max_bytes=max_output_bytes)
