"""Audit→SIEM export pipeline (ADR-0045).

A standalone, strictly-downstream-of-commit pipeline that streams every committed
``audit_log`` row to the customer SIEM at-least-once, in ADR-0038 ``seq`` order, over
a vendor-neutral transport set (RFC5424 syslog + ArcSight CEF over TLS, or generic
HTTPS/JSON), driven by a durable ``seq`` cursor (gap-free across restarts) with a
bounded buffer + retry on sink outage (never drops a row, never blocks the audit
write) and an ``audit_export_lag_seconds`` SLI gauge.
"""

from app.services.audit.export.cursor import (
    advance_cursor,
    current_exported_seq,
    load_cursor,
    read_unexported,
)
from app.services.audit.export.formatters import format_cef, format_https_json, format_syslog
from app.services.audit.export.pipeline import CycleResult, export_cycle, run_export_loop
from app.services.audit.export.record import ExportRecord
from app.services.audit.export.runner import build_sink
from app.services.audit.export.sinks import (
    HttpsJsonSink,
    Sink,
    SinkDeliveryError,
    TcpTlsSink,
    build_sink_tls_context,
)

__all__ = [
    "CycleResult",
    "ExportRecord",
    "HttpsJsonSink",
    "Sink",
    "SinkDeliveryError",
    "TcpTlsSink",
    "advance_cursor",
    "build_sink",
    "build_sink_tls_context",
    "current_exported_seq",
    "export_cycle",
    "format_cef",
    "format_https_json",
    "format_syslog",
    "load_cursor",
    "read_unexported",
    "run_export_loop",
]
