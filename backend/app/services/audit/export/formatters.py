"""The three vendor-neutral export transports' serializers (ADR-0045 §1).

Each formatter is a PURE function of an already-redacted :class:`ExportRecord` —
the export is a *serialization* of one canonical record, not three different
records (ADR-0045 §1). The field mapping is FIXED here (the "W3-T1 implementation
notes" the ADR defers to) and bounded by the per-transport sentinel-secret leak
test (ADR-0045 §4): a CEF extension or JSON key that accidentally carried ``detail``
plaintext would be caught.

Transports (all carried over TLS by the sink layer — these functions emit the
on-wire bytes/string, the TLS is the sink's concern):

* ``syslog`` — RFC5424 with a structured-data block. PRI = facility ``audit`` (13,
  ``log audit``) × 8 + severity ``notice`` (5) = 109. The audit fields go into one
  SD-ELEMENT ``netopsAudit@<PEN>`` so the SIEM can index them; ``seq`` is the dedup
  key SD-PARAM.
* ``cef`` — ArcSight CEF:0 header + an extension dictionary. ``seq`` maps to the CEF
  ``externalId`` (the SIEM dedup key); the audit action is the CEF ``name`` + a
  stable ``signatureId``.
* ``https-json`` — the canonical audit JSON object (:meth:`ExportRecord.as_json_dict`)
  serialized compactly; the body the HTTPS sink POSTs.

Secure by default: every formatter draws ONLY from the secret-free
:class:`ExportRecord` fields; ``detail`` is rendered as compact JSON (it is
secret-free by the audit-writer contract, ADR-0032 §5). No formatter re-reads a
credential or adds a field outside the canonical set.
"""

from __future__ import annotations

import json
import socket
from typing import Final

from app.services.audit.chain import _rfc3339_utc
from app.services.audit.export.record import ExportRecord

#: Private Enterprise Number placeholder for the RFC5424 SD-ID / CEF device vendor.
#: A documented project-local constant (NOT an IANA-assigned PEN — assignment is a
#: GA/customer step); it only needs to be stable and unique within the SIEM tenant.
_NETOPS_PEN: Final = "53595"

#: RFC5424 syslog PRI = facility 13 (log audit) * 8 + severity 5 (notice) = 109.
#: The audit stream is an integrity/compliance feed → the ``log audit`` facility.
_SYSLOG_PRI: Final = 109
_SYSLOG_VERSION: Final = "1"
#: APP-NAME field of the RFC5424 header — the emitting application.
_SYSLOG_APP_NAME: Final = "netops-audit"

#: CEF header constants (ArcSight CEF:0). Device Vendor / Product / Version identify
#: the platform; the per-event Signature ID + Name + Severity complete the header.
_CEF_VERSION: Final = "0"
_CEF_DEVICE_VENDOR: Final = "NetOps"
_CEF_DEVICE_PRODUCT: Final = "AINetworkOpsPlatform"
_CEF_DEVICE_VERSION: Final = "1.0"
#: CEF severity 0-10; audit events are informational-integrity → 4 (low-medium).
_CEF_SEVERITY: Final = "4"


def _detail_json(record: ExportRecord) -> str:
    """Compact, deterministic JSON of the secret-free ``detail`` (``{}`` when None)."""
    return json.dumps(
        record.detail if record.detail is not None else {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _cef_escape_header(value: str) -> str:
    r"""Escape a CEF *header* field: ``\`` and ``|`` are escaped (CEF spec)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value: str) -> str:
    r"""Escape a CEF *extension* value: ``\`` ``=`` and newlines are escaped (CEF spec)."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _sd_escape(value: str) -> str:
    r"""Escape an RFC5424 SD-PARAM value: ``"`` ``\`` and ``]`` are escaped (RFC5424 §6.3.3)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_syslog(record: ExportRecord, *, hostname: str | None = None) -> str:
    """Serialize *record* as an RFC5424 syslog message with a structured-data block.

    ``<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG``. The audit
    fields populate one SD-ELEMENT (``netopsAudit@<PEN>``); ``seq`` is both the
    MSGID and an SD-PARAM so the SIEM can dedup on it (ADR-0045 §2). The redacted
    ``detail`` is carried as a compact-JSON SD-PARAM (secret-free, ADR-0032 §5).
    """
    host = hostname or socket.gethostname()
    ts = _rfc3339_utc(record.created_at)
    sd_params = [
        ("seq", str(record.seq)),
        ("auditId", str(record.id)),
        ("actor", record.actor),
        ("action", record.action),
        ("targetType", record.target_type),
        ("targetId", record.target_id or "-"),
        ("requestId", str(record.request_id) if record.request_id is not None else "-"),
        (
            "reasoningTraceId",
            str(record.reasoning_trace_id) if record.reasoning_trace_id is not None else "-",
        ),
        ("detail", _detail_json(record)),
    ]
    sd_body = " ".join(f'{name}="{_sd_escape(value)}"' for name, value in sd_params)
    structured_data = f"[netopsAudit@{_NETOPS_PEN} {sd_body}]"
    # MSG is a short human-readable summary; the authoritative fields are the SD.
    msg = f"audit action={record.action} actor={record.actor}"
    return (
        f"<{_SYSLOG_PRI}>{_SYSLOG_VERSION} {ts} {host} {_SYSLOG_APP_NAME} - "
        f"{record.seq} {structured_data} {msg}"
    )


def format_cef(record: ExportRecord) -> str:
    """Serialize *record* as an ArcSight CEF:0 line (header + extension dictionary).

    ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension``. The audit
    ``action`` is the CEF Name and the stable Signature ID; ``seq`` maps to the
    ``externalId`` extension — the SIEM dedup key (ADR-0045 §2). The redacted
    ``detail`` rides a ``cs1`` custom string (secret-free, ADR-0032 §5).
    """
    signature_id = _cef_escape_header(record.action)
    name = _cef_escape_header(record.action)
    header = (
        f"CEF:{_CEF_VERSION}|{_CEF_DEVICE_VENDOR}|{_CEF_DEVICE_PRODUCT}|"
        f"{_CEF_DEVICE_VERSION}|{signature_id}|{name}|{_CEF_SEVERITY}"
    )
    ext_pairs = [
        ("externalId", str(record.seq)),
        ("rt", _rfc3339_utc(record.created_at)),
        ("suser", record.actor),
        ("act", record.action),
        ("cat", record.target_type),
        ("deviceCustomDate1Label", "auditCreatedAt"),
        ("cs1Label", "detail"),
        ("cs1", _detail_json(record)),
        ("cs2Label", "auditId"),
        ("cs2", str(record.id)),
    ]
    if record.target_id is not None:
        ext_pairs.append(("destinationServiceName", record.target_id))
    if record.request_id is not None:
        ext_pairs.append(("requestClientApplication", str(record.request_id)))
    if record.reasoning_trace_id is not None:
        ext_pairs.append(("cs3Label", "reasoningTraceId"))
        ext_pairs.append(("cs3", str(record.reasoning_trace_id)))
    extension = " ".join(f"{key}={_cef_escape_extension(value)}" for key, value in ext_pairs)
    return f"{header}|{extension}"


def format_https_json(record: ExportRecord) -> str:
    """Serialize *record* as the compact canonical-JSON body for the HTTPS sink.

    The exact bytes POSTed to the HTTPS/JSON collector (ADR-0045 §1): the
    already-redacted :meth:`ExportRecord.as_json_dict` object, sorted-key + compact.
    ``seq`` is a top-level key → the SIEM dedup key.
    """
    return json.dumps(
        record.as_json_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
