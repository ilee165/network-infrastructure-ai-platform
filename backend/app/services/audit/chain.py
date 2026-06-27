"""Audit-log hash-chain primitives (ADR-0038 §1/§2/§5).

The append-only ``audit_log`` is made **tamper-evident** by a per-entry hash
chain: every row carries ``prev_hash`` (the predecessor's ``entry_hash``) and
``entry_hash = SHA-256(canonical(entry_fields) || prev_hash)``. The first row
chains from a fixed :data:`GENESIS_HASH`. Both hashes are the raw 32-byte SHA-256
digest (``bytea`` on PostgreSQL / ``BLOB`` on SQLite) — there is exactly ONE
on-disk format; hex is a presentation concern only (logs / metrics), never the
stored or hashed form (ADR-0038 §1).

This module is the single canonicalizer shared by the **application audit
writer** (which writes the chain on every append, ADR-0038 §3) and the **daily
verification job / verifier** (which recomputes it, ADR-0038 §4) — so the two can
never drift. The byte-exact canonical form (sorted keys, no insignificant
whitespace, UTF-8, RFC 3339 UTC ``created_at`` at fixed precision) is the
load-bearing requirement: a non-deterministic form would false-alarm the verifier
(ADR-0038 §2, Negative).

Secure by default (ADR-0038 §5 / ADR-0032 §5): the hashed canonical form covers
ONLY the already-secret-free audit columns — ``id``, ``seq``, ``created_at``,
``actor``, ``action``, ``target_type``, ``target_id``, ``request_id``,
``reasoning_trace_id`` and the structured ``detail``. Mutable / server-defaulted /
secret-bearing columns do not participate; callers never place secret material in
``detail`` (the audit writer contract). :data:`CANONICAL_FIELDS` names the exact
participating set so a test can assert no secret column was added to the hash.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from app.models.audit import AuditLog

#: Width of a SHA-256 digest in bytes — the on-disk width of both hash columns.
HASH_LEN: Final = 32

#: Fixed genesis seed the FIRST audit entry chains from (ADR-0038 §1). A constant
#: (not a random per-deployment value) so an independent verifier reproduces the
#: whole chain from the schema alone. 32 zero bytes — a deliberate, documented
#: sentinel distinct from any real SHA-256 ``entry_hash`` only by position (entry
#: 1 alone uses it); the chain's integrity rests on the digests, not on the seed
#: being secret.
GENESIS_HASH: Final = b"\x00" * HASH_LEN

#: The EXACT immutable fields that participate in the canonical hashed form
#: (ADR-0038 §2). Ordered here for documentation; the canonical JSON sorts keys
#: independently. A test pins this set so no secret-bearing / mutable column can be
#: folded into the hash silently (ADR-0038 §5). ``created_at`` is rendered as a
#: fixed-precision RFC 3339 UTC string; everything else is its JSON-native form.
#:
#: ``seq`` (the monotonic append-order key, W4-T1 A4) is included BECAUSE it is the
#: chain's ORDER key AND the verifier's incremental keyset boundary
#: (``verify.py`` resumes strictly after ``anchor.seq``). If ``seq`` did not
#: participate in ``entry_hash``, a privileged actor could mutate the ``seq`` of an
#: already-checkpointed row without breaking its hash — silently shifting the
#: keyset boundary so the incremental walk SKIPS entries (PR #76 round-2 #5). With
#: ``seq`` hashed, any tampered ``seq`` breaks ``entry_hash`` and is detected.
#: ``seq`` is app-assigned BEFORE the insert (under the append advisory lock) so it
#: is known when the hash is computed (single INSERT, no insert-then-UPDATE).
CANONICAL_FIELDS: Final = (
    "id",
    "seq",
    "created_at",
    "actor",
    "action",
    "target_type",
    "target_id",
    "request_id",
    "reasoning_trace_id",
    "detail",
)


def _rfc3339_utc(value: datetime) -> str:
    """Render *value* as a fixed-precision RFC 3339 UTC timestamp (ADR-0038 §2).

    The byte-exact form: convert to UTC, drop the tz object in favour of a literal
    ``Z`` suffix, and ALWAYS emit microsecond precision (6 digits) so a timestamp
    that happens to land on a whole second hashes identically to the verifier's
    recompute. A naive datetime is rejected — the audit columns are tz-aware UTC by
    construction (:class:`app.models.mixins.UtcDateTime`); a naive value here would
    be an ambiguous instant and silently break the chain.
    """
    if value.tzinfo is None:
        raise ValueError("audit created_at must be tz-aware UTC for canonical hashing")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _jsonable(value: Any) -> Any:
    """Coerce a canonical-field value into a deterministically JSON-serializable form.

    ``uuid.UUID`` → its canonical lower-case string; ``datetime`` → fixed-precision
    RFC 3339 UTC; everything else (``str``/``None``/the JSON-native ``detail`` dict)
    passes through unchanged. ``detail`` is hashed as-stored — callers must keep it
    secret-free (the audit writer contract, ADR-0032 §5).
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return _rfc3339_utc(value)
    return value


def canonical_fields(entry: AuditLog) -> dict[str, Any]:
    """Project *entry* onto the :data:`CANONICAL_FIELDS` (secret-free) dict.

    Reads ONLY the immutable, secret-free columns named in :data:`CANONICAL_FIELDS`
    — never ``prev_hash``/``entry_hash`` (the chain outputs) or any column outside
    that set. Values are coerced via :func:`_jsonable` so the result is
    deterministically serializable.
    """
    return {field: _jsonable(getattr(entry, field)) for field in CANONICAL_FIELDS}


def canonical_bytes(entry: AuditLog) -> bytes:
    """Serialize *entry*'s canonical fields to the byte-exact hashed form (ADR-0038 §2).

    Canonical JSON: sorted keys, no insignificant whitespace (compact separators),
    UTF-8, non-ASCII preserved (``ensure_ascii=False``). This is the EXACT byte
    sequence fed to SHA-256 — the writer and the verifier both call it, so the
    chain cannot drift between the two paths.
    """
    return json.dumps(
        canonical_fields(entry),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_entry_hash(entry: AuditLog, prev_hash: bytes) -> bytes:
    """Return ``SHA-256(canonical(entry) || prev_hash)`` — the 32-byte chain digest.

    *prev_hash* is the predecessor entry's ``entry_hash`` (or :data:`GENESIS_HASH`
    for the first entry). The predecessor's digest is mixed in AFTER the canonical
    bytes so reordering or deleting any link changes every downstream ``entry_hash``
    — which is what the verifier detects (ADR-0038 §1).
    """
    if len(prev_hash) != HASH_LEN:
        raise ValueError(f"prev_hash must be {HASH_LEN} raw bytes, got {len(prev_hash)}")
    digest = hashlib.sha256()
    digest.update(canonical_bytes(entry))
    digest.update(prev_hash)
    return digest.digest()


def hex_short(digest: bytes) -> str:
    """Hex-encode the FIRST 8 bytes of *digest* for a log/metric label (ADR-0038 §1).

    A presentation-only helper: hashes are stored and compared as raw bytes; only
    log lines and metrics ever render hex, and a short prefix is enough to correlate
    a break without dumping the full digest.
    """
    return digest[:8].hex()
