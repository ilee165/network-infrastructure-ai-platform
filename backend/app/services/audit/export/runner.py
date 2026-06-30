"""Audit→SIEM export worker entrypoint (ADR-0045) — ``python -m app.services.audit.export``.

Builds the configured sink + the runtime DB sessionmaker and drives the long-running
:func:`app.services.audit.export.pipeline.run_export_loop`. Deployed as a dedicated
long-running Deployment (NOT a CronJob — the export is continuous near-real-time
streaming) on the same Python-bearing backend image, with a Prometheus ``/metrics``
HTTP server exposing the ``audit_export_lag_seconds`` gauge (the §6 SLI W3-T3 alerts
on) and a default-deny egress NetworkPolicy that re-permits ONLY the configured SIEM
endpoint (ADR-0045 §5 / ADR-0041 posture).

Secure by default: the bearer token is read from settings as a ``SecretStr`` and
handed to the HTTPS sink only — never logged, never in an exception. The startup
banner names the format + endpoint host (not the token).
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db import create_engine, create_sessionmaker
from app.services.audit.export.pipeline import run_export_loop
from app.services.audit.export.sinks import (
    HttpsJsonSink,
    Sink,
    TcpTlsSink,
    build_sink_tls_context,
)

_logger = get_logger(__name__)


def build_sink(settings: Settings) -> Sink:
    """Construct the SIEM sink for the configured transport (ADR-0045 §1).

    ``syslog``/``cef`` → the RFC5425 TLS syslog sink (``audit_export_host``/``_port``);
    ``https-json`` → the HTTPS/JSON push sink (``audit_export_endpoint`` + optional
    bearer token). All over a verified TLS context (TLS-only export, ADR-0045 §1).
    Raises ``ValueError`` on a misconfigured/absent endpoint — fail closed, never a
    silent no-export.
    """
    fmt = settings.audit_export_format
    if fmt is None:
        raise ValueError("audit_export_format is unset — the exporter is disabled")
    tls = build_sink_tls_context(settings)
    if fmt in ("syslog", "cef"):
        if not settings.audit_export_host:
            raise ValueError(
                f"audit_export_format={fmt!r} requires NETOPS_AUDIT_EXPORT_HOST "
                "(the SIEM syslog/CEF collector host)"
            )
        return TcpTlsSink(
            host=settings.audit_export_host, port=settings.audit_export_port, tls_context=tls
        )
    # https-json
    if not settings.audit_export_endpoint:
        raise ValueError(
            "audit_export_format='https-json' requires NETOPS_AUDIT_EXPORT_ENDPOINT "
            "(the SIEM HTTPS/JSON collector URL)"
        )
    token = (
        settings.audit_export_bearer_token.get_secret_value()
        if settings.audit_export_bearer_token is not None
        else None
    )
    return HttpsJsonSink(
        endpoint=settings.audit_export_endpoint, tls_context=tls, bearer_token=token
    )


def _maybe_start_metrics_server(settings: Settings) -> None:
    """Expose ``audit_export_lag_seconds`` on the worker metrics port (best-effort).

    Mirrors the Celery worker's metrics-server pattern: a tiny ``prometheus_client``
    HTTP server on :attr:`Settings.worker_metrics_port`. Graceful — a missing
    ``prometheus_client`` or an already-bound port logs and continues (the export
    must run even if the metrics endpoint cannot bind).
    """
    try:
        from prometheus_client import start_http_server
    except ImportError:
        _logger.info("audit.export.metrics_server_skipped", reason="prometheus_client_absent")
        return
    try:
        start_http_server(settings.worker_metrics_port)
    except OSError as exc:
        _logger.warning(
            "audit.export.metrics_server_unavailable",
            port=settings.worker_metrics_port,
            reason_class=type(exc).__name__,
        )
        return
    _logger.info("audit.export.metrics_server_started", port=settings.worker_metrics_port)


async def _main() -> int:
    """Build the sink + sessionmaker and run the export loop until SIGTERM/SIGINT."""
    settings = get_settings()
    if settings.audit_export_format is None:
        _logger.warning(
            "audit.export.disabled",
            reason="NETOPS_AUDIT_EXPORT_FORMAT unset — exporter is a no-op (no SIEM configured)",
        )
        return 0
    sink = build_sink(settings)
    _maybe_start_metrics_server(settings)
    # Host name only (never the token / full endpoint with creds) in the banner.
    _logger.info(
        "audit.export.started",
        fmt=settings.audit_export_format,
        host=settings.audit_export_host or settings.audit_export_endpoint,
        batch_size=settings.audit_export_batch_size,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        # add_signal_handler is unavailable on Windows / a restricted loop — degrade
        # to no-op there (the K8s SIGTERM path is the prod case).
        with contextlib.suppress(NotImplementedError):  # pragma: no cover
            loop.add_signal_handler(sig, stop.set)

    engine = create_engine(settings)
    try:
        maker = create_sessionmaker(engine)
        await run_export_loop(sessionmaker=maker, sink=sink, settings=settings, stop=stop)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via run_export_loop in tests
    sys.exit(asyncio.run(_main()))
