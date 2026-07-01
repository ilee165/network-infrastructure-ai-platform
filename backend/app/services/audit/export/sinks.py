"""SIEM sink transports — where an exported record actually goes (ADR-0045 §1).

A :class:`Sink` ACKs a batch of pre-formatted payloads or RAISES on failure; the
pipeline advances the durable cursor ONLY on a clean ACK (at-least-once, ADR-0045
§2). All three vendor-neutral transports run over TLS (ADR-0045 §1 — no cleartext
export of the audit spine):

* :class:`TcpTlsSink` — RFC5425 TLS-transported syslog/CEF, octet-counted framing
  (``MSG-LEN SP SYSLOG-MSG``), to a configured ``host:port``. Used for both the
  ``syslog`` and ``cef`` formats (CEF is carried over the same syslog TLS transport,
  ADR-0045 §1).
* :class:`HttpsJsonSink` — POSTs the canonical JSON body to a configured HTTPS
  collector endpoint (TLS, bearer/mTLS as configured).

Secure by default: a sink NEVER logs or repr's a payload body (the records are
secret-free by construction, but a bearer token / endpoint is config, never echoed
into a log line or an exception message). A connect/handshake/HTTP error is raised
as a coarse :class:`SinkDeliveryError` carrying only a transport class + status —
never the payload, never the token.

HOST-LIMITATION (L1): the real socket/TLS/HTTP I/O cannot run on the unit-test
host (no SIEM, no network egress under the default-deny posture). The real call
shape is pinned by a CONTRACT test (``tests/services/test_audit_export.py`` —
``test_*_sink_contract``) that asserts the exact stdlib calls + TLS context the prod
path makes; the live end-to-end delivery rides the W4 enforcing-CNI kind cluster
(ADR-0045 §5, named for the build). The pipeline's at-least-once / no-gap proofs run
against an in-memory fault-injectable sink AND on real PG (the cursor durability is
the load-bearing half and IS exercised live).
"""

from __future__ import annotations

import contextlib
import ssl
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from app.core.config import Settings


class SinkDeliveryError(RuntimeError):
    """A SIEM sink failed to deliver a batch — coarse, secret-free.

    Carries only a short transport/status class so the pipeline can log the failure
    class and retry (ADR-0045 §3 — buffer + retry, never drop). It NEVER carries the
    payload, the endpoint credential, or the record content.
    """


@runtime_checkable
class Sink(Protocol):
    """A SIEM delivery transport: ACK a batch of formatted payloads, or raise.

    ``deliver`` must be all-or-raise per batch: it returns ``None`` only when EVERY
    payload in *payloads* is acknowledged by the sink, and raises
    :class:`SinkDeliveryError` otherwise. The pipeline advances the cursor only on a
    clean return, so a partial/failed batch leaves the cursor un-advanced and the
    rows are re-read on the next cycle (at-least-once, ADR-0045 §2).
    """

    async def deliver(self, payloads: list[str]) -> None:
        """Deliver *payloads* in order; return on full ACK, raise on any failure."""
        ...


def build_sink_tls_context(settings: Settings) -> ssl.SSLContext:
    """Build the client TLS context for a SIEM sink (ADR-0045 §1 — TLS-only export).

    Verifies the SIEM SERVER cert against the configured CA bundle (or the system
    trust store when none is configured) and, when a client cert/key pair is
    configured, PRESENTS it for mutual TLS. Fail-closed: a configured client cert
    without its key (or vice-versa) raises — never silently downgrades to one-way
    TLS (the ADR-0039 §4 client-layer posture, applied to the export egress).
    """
    cafile = str(settings.audit_export_ca_cert) if settings.audit_export_ca_cert else None
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    cert = settings.audit_export_client_cert
    key = settings.audit_export_client_key
    if (cert is None) != (key is None):
        raise ValueError(
            "NETOPS_AUDIT_EXPORT_CLIENT_CERT and NETOPS_AUDIT_EXPORT_CLIENT_KEY must "
            "be set together (mutual TLS requires both the client cert and its key)"
        )
    if cert is not None and key is not None:
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return context


def _octet_framed(message: str) -> bytes:
    """Frame a syslog message per RFC5425 octet-counting: ``MSG-LEN SP SYSLOG-MSG``.

    The TLS syslog transport (RFC5425) uses octet-counted framing so a record that
    contains a newline (e.g. inside the redacted ``detail`` JSON) cannot be split
    into two messages — the length prefix is authoritative.
    """
    body = message.encode("utf-8")
    return f"{len(body)} ".encode("ascii") + body


class TcpTlsSink:
    """RFC5425 TLS-transported syslog/CEF sink (octet-counted framing), ADR-0045 §1.

    Opens a TLS connection to ``host:port`` per ``deliver`` call (a SIEM syslog
    collector), writes each octet-framed payload, and returns only once all bytes are
    flushed. A connect / TLS-handshake / write error raises :class:`SinkDeliveryError`
    (coarse class only — never the payload). The same sink carries both the
    ``syslog`` and ``cef`` formats (CEF over the syslog TLS transport, ADR-0045 §1).
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_context: ssl.SSLContext,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._tls = tls_context
        self._timeout = timeout_seconds

    async def deliver(self, payloads: list[str]) -> None:
        import asyncio

        # Bound BOTH the TLS connect and the write/drain (same posture as the HTTPS
        # sink's timeout): a slow/stalled SIEM must not hang the exporter loop forever
        # (which freezes the lag gauge — no refresh, no alert). A timeout is a delivery
        # FAILURE, not a stall: convert it to SinkDeliveryError so the batch is retried
        # next cycle (buffer + retry, never drop — ADR-0045 §3), never a wedged loop.
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._host, self._port, ssl=self._tls, server_hostname=self._host
                ),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise SinkDeliveryError("syslog-tls connect timed out") from exc
        except (OSError, ssl.SSLError) as exc:
            raise SinkDeliveryError(f"syslog-tls connect failed: {type(exc).__name__}") from exc
        try:
            for payload in payloads:
                writer.write(_octet_framed(payload))
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
        except TimeoutError as exc:
            raise SinkDeliveryError("syslog-tls write timed out") from exc
        except (OSError, ssl.SSLError) as exc:
            raise SinkDeliveryError(f"syslog-tls write failed: {type(exc).__name__}") from exc
        finally:
            writer.close()
            # A close-time error after a successful drain does not un-deliver the
            # batch; swallow it so a clean write is not re-reported as a failure.
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()


class HttpsJsonSink:
    """Generic HTTPS/JSON push sink — POSTs each canonical JSON body (ADR-0045 §1).

    POSTs every payload to the configured HTTPS collector endpoint over TLS, with an
    optional bearer token (config — never logged). Returns only when every POST
    returns a 2xx; a non-2xx or a transport error raises :class:`SinkDeliveryError`
    (status/class only, never the body or the token). Uses ``httpx`` (a prod dep).
    """

    def __init__(
        self,
        *,
        endpoint: str,
        tls_context: ssl.SSLContext,
        bearer_token: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._tls = tls_context
        self._bearer_token = bearer_token
        self._timeout = timeout_seconds

    async def deliver(self, payloads: list[str]) -> None:
        import httpx

        headers = {"Content-Type": "application/json"}
        if self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        try:
            async with httpx.AsyncClient(verify=self._tls, timeout=self._timeout) as client:
                for payload in payloads:
                    response = await client.post(
                        self._endpoint, content=payload.encode("utf-8"), headers=headers
                    )
                    if response.status_code // 100 != 2:
                        # Status code only — never the response body (could echo the
                        # request) or the token.
                        raise SinkDeliveryError(f"https-json POST returned {response.status_code}")
        except httpx.HTTPError as exc:
            raise SinkDeliveryError(f"https-json transport failed: {type(exc).__name__}") from exc
