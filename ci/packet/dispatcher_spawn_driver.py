#!/usr/bin/env python3
"""ADR-0049 §Acceptance DISPATCH leg: prove the REAL dispatcher->child spawn seam
works UNDER the DEPLOYED dispatcher seccomp profile (review F2).

The GREEN leg runs ``python -m app.engines.packet.executor`` as PID 1 (no
dispatcher spawn), and the TIMEOUT leg drives ``_spawn_and_reap`` with container
``seccomp=unconfined`` — so neither exercises the one seam the enforced tier
lives or dies on: the dispatcher, itself confined by
``packet-analysis-dispatcher-seccomp.json``, calling ``subprocess.Popen`` with
``start_new_session=True`` (CPython issues ``setsid()`` in the forked child —
the exact syscall the F1 gap EPERM'd) and reaping a schema-valid
``PacketFindings`` from the confined child. This driver runs INSIDE the
packet-analysis image with the committed dispatcher profile applied at the
container level (the CI leg passes ``--security-opt seccomp=<dispatcher
profile>``, NOT unconfined) and drives the production entrypoint —
:func:`app.engines.packet.sandbox.run_executor` — over the real fixture pcap.

On success it prints the findings JSON on stdout for the bare-runner
``assert_findings.py`` check; any spawn denial / confinement failure raises
``SandboxError`` -> traceback -> nonzero exit -> RED leg.

The tuning values mirror the ``config.py`` defaults (hardcoded like
``timeout_reap_driver.py`` so the driver stays hermetic — no settings/env
machinery inside the throwaway CI container).
"""

from __future__ import annotations

import sys

from app.engines.packet.sandbox import run_executor

#: The read-only fixture mount the CI leg binds the generated one-packet pcap to.
_PCAP = "/data/pcaps/tiny.pcap"


def main() -> int:
    findings = run_executor(
        _PCAP,
        display_filter=None,
        tshark_bin="tshark",
        timeout_seconds=30.0,
        top_n=5,
        rlimit_as_bytes=2 * 1024 * 1024 * 1024,
        rlimit_fsize_bytes=64 * 1024 * 1024,
        rlimit_nofile=256,
        rlimit_nproc=64,
        deny_action="errno",
        max_output_bytes=256 * 1024,
    )
    sys.stdout.write(findings.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
