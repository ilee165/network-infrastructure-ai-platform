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
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404 — argv-only, shell=False; the sandbox boundary itself
from pathlib import Path
from typing import Any

from app.core.errors import PluginError
from app.engines.packet.analysis import PacketFindings, summarize_packets
from app.engines.packet.filters import validate_capture_filter

__all__ = [
    "DEFAULT_TSHARK_BIN",
    "SandboxError",
    "analyze_pcap",
    "build_tshark_argv",
]

#: Default tshark binary name; the worker resolves an absolute path from settings.
DEFAULT_TSHARK_BIN = "tshark"

#: Cap on bytes read from tshark stdout — a defensive bound on the JSON the child
#: can return (a hostile/huge capture is already bounded by the size cap at
#: capture time and the subprocess timeout here).
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


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
