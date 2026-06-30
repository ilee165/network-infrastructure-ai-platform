"""The canonical exported audit record — one already-redacted serialization source.

ADR-0045 §1 §4: an exported record is a *serialization* of the **already-redacted**
``audit_log`` row, not a new record. Every transport (syslog / CEF / HTTPS-JSON)
formats THIS one projection, so redaction is inherited from the in-DB audit row and
is never re-implemented per transport: the export adds no field that re-introduces a
secret and never re-reads the credential vault or any plaintext source.

The projected field set is exactly the secret-free, immutable audit columns the
hash chain already covers (:data:`app.services.audit.chain.CANONICAL_FIELDS`) — the
``detail`` dict is carried as-stored (callers keep it secret-free, the audit-writer
contract, ADR-0032 §5). ``seq`` (the ADR-0038 monotonic append-order key) is the
stable per-row dedup key the SIEM deduplicates on (at-least-once → exactly-once
*effect*, ADR-0045 §2); it is included in EVERY transport payload.

Secure by default: no ``prev_hash`` / ``entry_hash`` (chain outputs, not events) and
no column outside the canonical secret-free set ever enters an exported record.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.services.audit.chain import _rfc3339_utc

if TYPE_CHECKING:
    from app.models.audit import AuditLog


@dataclass(frozen=True, slots=True)
class ExportRecord:
    """One audit row projected onto the export-safe field set (ADR-0045 §1/§4).

    Built ONLY from the already-redacted, immutable audit columns. ``seq`` is the
    SIEM dedup key (never NULL here — the pipeline reads ``seq IS NOT NULL`` rows
    only, mirroring the ADR-0038 verifier). ``created_at`` is the commit timestamp
    used both for the syslog/CEF event time and as the lag-SLI basis.
    """

    seq: int
    id: uuid.UUID
    created_at: datetime
    actor: str
    action: str
    target_type: str
    target_id: str | None
    request_id: uuid.UUID | None
    reasoning_trace_id: uuid.UUID | None
    detail: dict[str, Any] | None

    @classmethod
    def from_row(cls, row: AuditLog) -> ExportRecord:
        """Project an :class:`~app.models.audit.AuditLog` row onto the export record.

        ``row.seq`` must be non-NULL — the pipeline filters NULL-``seq`` pre-chain
        rows out of the export stream (ADR-0045 §2, mirroring the verifier), so a
        NULL here is a programming error, not a runtime input.
        """
        if row.seq is None:
            raise ValueError(
                "ExportRecord requires a non-NULL seq "
                "(NULL-seq pre-chain rows are excluded from export)"
            )
        return cls(
            seq=int(row.seq),
            id=row.id,
            created_at=row.created_at,
            actor=row.actor,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            request_id=row.request_id,
            reasoning_trace_id=row.reasoning_trace_id,
            detail=row.detail,
        )

    def as_json_dict(self) -> dict[str, Any]:
        """Return the canonical JSON object for the HTTPS/JSON transport (ADR-0045 §1).

        UUIDs → canonical strings, ``created_at`` → fixed-precision RFC 3339 UTC
        (the same rendering the hash canonicalizer uses), ``detail`` as-stored. This
        is the exact body POSTed to the HTTPS collector and the source the syslog /
        CEF formatters draw their fields from.
        """
        return {
            "seq": self.seq,
            "id": str(self.id),
            "created_at": _rfc3339_utc(self.created_at),
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "request_id": str(self.request_id) if self.request_id is not None else None,
            "reasoning_trace_id": (
                str(self.reasoning_trace_id) if self.reasoning_trace_id is not None else None
            ),
            "detail": self.detail,
        }
