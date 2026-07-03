"""Packet-analysis engine (M5; ADR-0023, D14).

Pure logic over the persistence layer, filename/argv construction, and the
sandboxed tshark boundary — Celery wiring lives in
:mod:`app.workers.tasks.packet`, never here (the engine never imports the worker
layer; REPO-STRUCTURE §3.2). Three concerns:

- **capture orchestration** (:mod:`.capture`): argv/CLI builders for worker-side
  ``tcpdump`` and ``eos`` device monitor-session capture (argv lists, never shell
  strings), the mandatory duration/size caps, pcap-metadata ingest, and the
  retention/tombstone helpers (ADR-0023 §2/§3/§4).
- **sandbox** (:mod:`.sandbox`): the only place tshark is spawned — argv list,
  ``shell=False``, ``-n`` (no name resolution), whitelisted display filter, hard
  subprocess timeout (ADR-0023 §1 — the critical containment control).
- **filters** (:mod:`.filters`): the BPF/display-filter whitelist that rejects
  injection attempts before any argv is built, and **analysis** (:mod:`.analysis`):
  normalized, LLM-safe findings (no raw payload bytes).
"""

from app.engines.packet.analysis import (
    Conversation,
    PacketFindings,
    ProtocolCount,
    summarize_packets,
)
from app.engines.packet.capture import (
    DEFAULT_PCAP_DIR,
    MAX_DURATION_SECONDS,
    MAX_SIZE_BYTES,
    CaptureSpec,
    build_eos_capture_commands,
    build_eos_finalize_commands,
    build_tcpdump_argv,
    expired_capture_ids,
    ingest_capture,
    pcap_path_for,
    tombstone_capture,
    validate_interface,
)
from app.engines.packet.filters import (
    FilterValidationError,
    validate_capture_filter,
)
from app.engines.packet.posture import (
    PostureError,
    assert_sandbox_posture,
)
from app.engines.packet.sandbox import (
    SandboxError,
    analyze_pcap,
    build_tshark_argv,
    parse_executor_findings,
    run_executor,
)

__all__ = [
    "DEFAULT_PCAP_DIR",
    "MAX_DURATION_SECONDS",
    "MAX_SIZE_BYTES",
    "CaptureSpec",
    "Conversation",
    "FilterValidationError",
    "PacketFindings",
    "PostureError",
    "ProtocolCount",
    "SandboxError",
    "analyze_pcap",
    "assert_sandbox_posture",
    "build_eos_capture_commands",
    "build_eos_finalize_commands",
    "build_tcpdump_argv",
    "build_tshark_argv",
    "expired_capture_ids",
    "ingest_capture",
    "parse_executor_findings",
    "pcap_path_for",
    "run_executor",
    "summarize_packets",
    "tombstone_capture",
    "validate_capture_filter",
    "validate_interface",
]
