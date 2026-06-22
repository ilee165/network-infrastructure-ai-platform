"""Sandbox runtime posture hook (ADR-0031 §2 — the ``wf-implementer`` half of W3).

The declarative half of the packet-sandbox (ADR-0031) hardens the
``packet-analysis`` Pod at the deployment layer: non-root, ``capabilities.drop:
[ALL]`` with no ``add``, ``readOnlyRootFilesystem: true``, a ``Localhost`` seccomp
profile, and a default-deny egress NetworkPolicy. That posture is only real if it
is actually applied; a misconfigured Deployment (a values override, a hand-edited
manifest, a dev ``docker run`` without the controls) would let the analysis worker
run unconfined and silently parse untrusted pcap bytes with root/NET_RAW.

This module is the **runtime backstop** ADR-0031 §2 mandates: at the start of
every analysis task the worker asserts the expected posture and **refuses to spawn
tshark** if any check fails, so a misconfigured deployment *fails closed* rather
than silently running unconfined (the ADR-0031 §7 exit criterion). It is the code
counterpart to the conftest/OPA policy-as-test that asserts the same controls on
the rendered chart — two independent layers, neither relied on alone.

Three checks, all read-only and Linux-``/proc``-based (a non-Linux host has none
of these controls and is treated as a failure when enforcement is on):

- **effective UID ≠ 0** (``os.geteuid``) — a dissector exploit must not land as
  root.
- **no ``CAP_NET_RAW`` in the permitted set** (``/proc/self/status`` ``CapPrm``) —
  the parser reads a *file*, never a socket; a raw socket would hand a dissector
  CVE network reach for free.
- **read-only root filesystem** (``/proc/self/mounts`` — the ``/`` mount carries
  the ``ro`` option) — no writable code/lib paths.

No secret, pcap byte, or credential is read or emitted here; failure messages name
only the posture control that failed.
"""

from __future__ import annotations

import os

from app.core.errors import PluginError

__all__ = [
    "CAP_NET_RAW_BIT",
    "PostureError",
    "assert_sandbox_posture",
]

#: Capability bit number for ``CAP_NET_RAW`` (``<linux/capability.h>``). The
#: ``/proc/self/status`` ``CapPrm`` field is a 64-bit hex mask; bit 13 is NET_RAW.
CAP_NET_RAW_BIT = 13


class PostureError(PluginError):
    """The analysis worker's runtime sandbox posture is not the expected one.

    Raised before any tshark process is spawned so a misconfigured deployment
    fails closed (ADR-0031 §2/§7). The message names only the failed posture
    control — never a credential, pcap byte, or path beyond ``/proc`` self-paths.
    """

    title = "Packet Sandbox Posture Failure"
    slug = "packet-sandbox-posture-failure"


def _effective_uid() -> int:
    """Effective UID of the worker process (seam: patched in tests).

    ``os.geteuid`` is POSIX-only; on a platform without it (a non-Linux dev host)
    the sandbox controls do not exist, so the absence is reported as UID 0 (root)
    — the fail-closed answer when posture enforcement is on.
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return 0
    return geteuid()


def _read_proc(path: str) -> str:
    """Read a ``/proc`` self-file as text (seam: patched in tests).

    A missing/unreadable file (non-Linux host, or ``/proc`` not mounted) returns
    an empty string, which every check below treats as a posture failure.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def _permitted_cap_mask() -> int:
    """Parse the permitted-capability bitmask from ``/proc/self/status`` ``CapPrm``.

    Returns ``-1`` (all bits set) when the field is absent/unparseable so the
    NET_RAW check fails closed rather than reading a missing file as "no caps".
    """
    for line in _read_proc("/proc/self/status").splitlines():
        if line.startswith("CapPrm:"):
            try:
                return int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return -1
    return -1


def _has_cap_net_raw() -> bool:
    """Whether ``CAP_NET_RAW`` is in the process's permitted capability set."""
    return bool(_permitted_cap_mask() & (1 << CAP_NET_RAW_BIT))


def _root_is_read_only() -> bool:
    """Whether the ``/`` mount is mounted read-only (``ro`` option, ``/proc/self/mounts``)."""
    for line in _read_proc("/proc/self/mounts").splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "/":
            options = fields[3].split(",")
            return "ro" in options
    return False


def assert_sandbox_posture(*, enforced: bool = True) -> None:
    """Assert the analysis worker's OS-isolation posture; raise if it is wrong.

    Called at the start of :func:`app.workers.tasks.packet.analyze_capture` before
    any tshark process is spawned. When *enforced* is false (the eager
    unit-test/CI runner, where the sandbox OS controls are not applied) the hook
    is a no-op. When true it verifies all three ADR-0031 §2 controls and raises
    :class:`PostureError` on the first failure, naming only the failed control.

    :raises PostureError: the effective UID is root, ``CAP_NET_RAW`` is in the
        permitted set, or the root filesystem is writable.
    """
    if not enforced:
        return

    failures: list[str] = []
    if _effective_uid() == 0:
        failures.append("effective UID is 0 (root); the parser must run non-root")
    if _has_cap_net_raw():
        failures.append("CAP_NET_RAW is in the permitted set; the parser must hold no capabilities")
    if not _root_is_read_only():
        failures.append("root filesystem is writable; readOnlyRootFilesystem must be set")

    if failures:
        raise PostureError(
            "refusing to spawn tshark — sandbox posture check failed (ADR-0031 §2): "
            + "; ".join(failures)
        )
