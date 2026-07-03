#!/usr/bin/env python3
"""ADR-0049 §Acceptance TIMEOUT leg: prove the dispatcher's process-group kill
reaps a wedged executor and its ``tshark`` grandchild (blocker 4 / ADR-0023 §1).

This driver runs INSIDE the packet-analysis image on CI (it imports the real
``app.engines.packet.sandbox``); it is not part of the eager unit suite because it
needs a real POSIX fork + ``killpg`` on Linux. It exercises the actual dispatcher
spawn/reap seam — :func:`app.engines.packet.sandbox._spawn_and_reap` — with:

- ``tshark_bin`` pointed at :file:`wedge_tshark.sh`, which records its PID and
  sleeps 600s;
- a LARGE inner (child) ``timeout_seconds`` so the executor's own tshark timeout
  never fires;
- a SMALL OUTER dispatcher timeout, so the dispatcher's ``killpg`` — not the
  child's self-cleanup — is the reaper under test.

``enforced`` is ``False`` so this leg isolates the group-kill mechanism from
seccomp/posture (which the GREEN/RED legs cover): the child spawns the wedge via
the in-process fallback and blocks; the dispatcher SIGKILLs the whole group.

Exit 0 iff the dispatcher raised the timeout ``SandboxError`` AND the wedge
grandchild PID is gone (or a reaped zombie) afterwards; nonzero (with a short
diagnostic) otherwise.
"""

from __future__ import annotations

import json
import os
import sys
import time

from app.engines.packet import sandbox

#: Fixed PID path shared with :file:`wedge_tshark.sh` (see that file for why it is
#: not env-derived) — on the writable tmpfs the container mounts at ``/tmp/pyshark``.
_PIDFILE = "/tmp/pyshark/grandchild.pid"
_WEDGE = "/ci/wedge_tshark.sh"

_OUTER_TIMEOUT_SECONDS = 3.0
#: Must exceed the outer timeout so the child's own tshark timeout never fires and
#: the dispatcher's process-group SIGKILL is unambiguously the reaper under test.
_INNER_TIMEOUT_SECONDS = 600.0


def _pid_alive(pid: int) -> bool:
    """Whether *pid* is a live (non-zombie) process.

    Reads ``/proc/<pid>/stat`` and inspects the state field: a missing entry means
    gone; state ``Z`` means a reaped-pending zombie — dead for our purposes. Using
    ``/proc`` state (not ``kill(pid, 0)``) is deliberate: a zombie still answers
    signal 0, which would falsely read as "alive".
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
            data = handle.read()
    except FileNotFoundError:
        return False
    # The comm field is parenthesized and may contain spaces/')' — split on the
    # LAST ')' so the state char is the first token after it.
    state = data.rpartition(")")[2].split()[0]
    return state != "Z"


def _wait_for(predicate, timeout: float, interval: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def main() -> int:
    try:
        os.remove(_PIDFILE)
    except FileNotFoundError:
        pass

    request = {
        "pcap_path": "/tmp/pyshark/none.pcap",  # never opened — the wedge ignores argv
        "display_filter": None,
        "tshark_bin": _WEDGE,
        "timeout_seconds": _INNER_TIMEOUT_SECONDS,
        "top_n": 5,
        "enforced": False,
        "rlimit_as_bytes": 2 * 1024 * 1024 * 1024,
        "rlimit_fsize_bytes": 64 * 1024 * 1024,
        "rlimit_nofile": 256,
        "rlimit_nproc": 64,
        "deny_action": "errno",
    }
    argv = [sys.executable, "-m", "app.engines.packet.executor"]

    started = time.monotonic()
    try:
        sandbox._spawn_and_reap(
            argv,
            request_bytes=json.dumps(request).encode("utf-8"),
            timeout_seconds=_OUTER_TIMEOUT_SECONDS,
            # Mirrors the packet_findings_max_bytes default (config.py); the wedge
            # writes nothing, so only the timeout path is under test here.
            max_output_bytes=256 * 1024,
        )
    except sandbox.SandboxError:
        pass
    else:
        sys.stderr.write("FAIL: dispatcher did not raise the outer-timeout SandboxError\n")
        return 1
    elapsed = time.monotonic() - started

    # The wedge MUST have actually started (recorded its PID) — otherwise there was
    # no grandchild to reap and the leg proves nothing.
    if not _wait_for(lambda: os.path.exists(_PIDFILE), timeout=5.0):
        sys.stderr.write("FAIL: wedge grandchild never started; the timeout leg proved nothing\n")
        return 1
    with open(_PIDFILE, encoding="utf-8") as handle:
        grandchild_pid = int(handle.read().strip())

    if not _wait_for(lambda: not _pid_alive(grandchild_pid), timeout=10.0):
        sys.stderr.write(
            f"FAIL: orphan tshark grandchild pid={grandchild_pid} survived the "
            "dispatcher process-group kill\n"
        )
        return 1

    sys.stdout.write(
        f"OK: dispatcher killpg reaped grandchild pid={grandchild_pid} "
        f"after the {elapsed:.1f}s outer timeout\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
