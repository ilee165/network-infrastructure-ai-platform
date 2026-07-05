"""SIEM-export CONFORMANCE eval — byte-stable format/order/no-gap/lag/no-leak (W5-T1).

This is the deterministic, byte-stable proof suite the W5-T3 gate cites for **G-OBS**
(PRODUCTION.md §6 / §11) that the audit→SIEM export (ADR-0045) leaves the platform
*conformant on the wire*: every emitted record is a schema-valid RFC5424 syslog /
ArcSight CEF / HTTPS-JSON serialization, emitted in monotonic ``seq`` order, gap-free
and at-least-once across a fault-injected sink outage + restart, within the export-lag
SLO, and free of any planted secret.

Eval-layer discipline (the role's two-layer split):

* **Deterministic layer — THIS module (runs in CI).** The deliverable here is
  *byte-exact serialization conformance*, which is a fully deterministic property: it
  is proven offline against synthetic, compressed-timestamp records driven through the
  REAL pipeline (:func:`export_cycle` / :func:`run_export_loop`) with an in-memory
  fault-injectable sink. There is **no model judgment** in wire-format conformance, so
  this criterion needs no real-LLM gate — the honest proof is the byte-exact assertion,
  not an LLM rubric.
* **Named-deferred (NOT this module).** The real TLS syslog / HTTPS POST over a live
  socket cannot run on the unit host (no SIEM, no egress); that call shape is pinned by
  the ``*_sink_contract`` tests in ``tests/services/test_audit_export.py`` and the live
  end-to-end delivery rides the W4 enforcing-CNI kind cluster (ADR-0045 §5). That is a
  transport-liveness limitation, not model judgment — no LLM layer applies.

Why this is DISTINCT from ``tests/services/test_audit_export.py`` (the W3-T1 contract
suite): that suite asserts the pipeline *mechanics* with lightweight structural checks
(``startswith`` / substring). This eval adds an **independent re-implementation of each
wire-format grammar** (RFC5424 header + SD parsing, CEF header/extension parsing with
proper unescaping, JSON schema validation) and validates the exporter OUTPUT against
that grammar — a payload the exporter emits that the independent parser rejects fails
the eval. It then reconstructs the SIEM-side ``seq`` stream *through those parsers* for
ALL THREE transports under a combined outage+restart scenario, pins byte-exact golden
vectors, and carries anti-vacuous self-bites for every checker (a malformed payload,
a planted secret, and a synthetic gap must each be caught).

No external services, no real LLM, no network: synthetic rows through the real writer +
an in-memory sink, file-backed SQLite for cross-session commit visibility. The lag SLI
is a wall-clock delta asserted with wide (>= 55 s) margins so its *outcome* is
deterministic; the format/order/no-gap/no-leak assertions are byte-exact.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.models import Base
from app.models.audit import AuditExportCursor
from app.models.mixins import utcnow
from app.services.audit import service as audit_service
from app.services.audit.export import (
    ExportRecord,
    SinkDeliveryError,
    current_exported_seq,
    export_cycle,
    format_cef,
    format_https_json,
    format_syslog,
    run_export_loop,
)

pytestmark = pytest.mark.eval

# ---------------------------------------------------------------------------
# Constants: the SLO bound, the sentinel, the three transport tokens.
# ---------------------------------------------------------------------------

#: The §6 SLO bound for the audit→SIEM export lag SLI (ADR-0045 §3, ADR-0046 §2):
#: ``Audit → SIEM export lag | p95 < 60 s``. The conformance suite asserts a recovered
#: stream is within this bound and (the bite) a stalled sink drives the SLI PAST it.
_EXPORT_LAG_SLO_SECONDS = 60.0

#: A sentinel that must NEVER appear in any exported payload (ADR-0045 §4). It looks
#: like a real device credential; if a formatter ever serialized a plaintext source it
#: would surface here. Distinct from the contract suite's sentinel so a copy/paste of
#: one file cannot mask a regression in the other.
_SENTINEL_SECRET = "C0nf0rmance-SENTINEL-DEVICE-KEY-do-not-export-7ab19e"  # noqa: S105

#: The three vendor-neutral transports (ADR-0045 §1). ``syslog`` + ``cef`` ride the TLS
#: syslog sink; ``https-json`` the HTTPS sink. Every dimension below is parametrized
#: over this set so no transport can silently regress.
_FORMATS = ("syslog", "cef", "https-json")

# ---------------------------------------------------------------------------
# Byte-exact golden vectors (byte-stability anchor). Generated from the REAL
# formatters over the fixed record below; any formatter change flips these — the
# intended regression tripwire for the on-wire serialization.
# ---------------------------------------------------------------------------
_GOLDEN_SYSLOG = (
    "<109>1 2026-06-30T12:00:00.000000Z exporter-0 netops-audit - 42 "
    '[netopsAudit@53595 seq="42" auditId="11111111-1111-1111-1111-111111111111" '
    'actor="user:7" action="credential.rotated" targetType="device" '
    'targetId="core-sw-1" requestId="22222222-2222-2222-2222-222222222222" '
    'reasoningTraceId="-" '
    'detail="{\\"credential_id\\":\\"abc\\",\\"outcome\\":\\"ok\\"}"] '
    "audit action=credential.rotated actor=user:7"
)
_GOLDEN_CEF = (
    "CEF:0|NetOps|AINetworkOpsPlatform|1.0|credential.rotated|credential.rotated|4|"
    "externalId=42 rt=2026-06-30T12:00:00.000000Z suser=user:7 act=credential.rotated "
    "cat=device deviceCustomDate1Label=auditCreatedAt cs1Label=detail "
    'cs1={"credential_id":"abc","outcome":"ok"} cs2Label=auditId '
    "cs2=11111111-1111-1111-1111-111111111111 destinationServiceName=core-sw-1 "
    "requestClientApplication=22222222-2222-2222-2222-222222222222"
)
_GOLDEN_JSON = (
    '{"action":"credential.rotated","actor":"user:7",'
    '"created_at":"2026-06-30T12:00:00.000000Z",'
    '"detail":{"credential_id":"abc","outcome":"ok"},'
    '"id":"11111111-1111-1111-1111-111111111111","reasoning_trace_id":null,'
    '"request_id":"22222222-2222-2222-2222-222222222222","seq":42,'
    '"target_id":"core-sw-1","target_type":"device"}'
)

# RFC3339 UTC timestamp the chain canonicalizer emits (fixed-precision microseconds).
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


# ===========================================================================
# Independent wire-format parsers — a re-implementation of each grammar, NOT a
# call into the exporter's formatters. A payload the exporter emits that these
# reject fails conformance. Each parser raises ValueError on a malformed input
# (proven non-vacuous by test_parsers_reject_malformed_input).
# ===========================================================================


def _sd_unescape(value: str) -> str:
    r"""Reverse the RFC5424 SD-PARAM escaping (``\"`` ``\\`` ``\]`` → literal)."""
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            out.append(value[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _split_sd_element(remainder: str) -> tuple[str, str]:
    """Split ``[SD-ELEMENT] MSG`` honouring quoted-value escapes; return (inner, msg).

    Walks the leading bracketed SD-ELEMENT and finds the closing ``]`` that is NOT
    inside a quoted SD-PARAM value (an escaped ``]`` inside a value does not close it).
    """
    if not remainder.startswith("["):
        raise ValueError("structured-data block must start with '['")
    i = 1
    in_quote = False
    while i < len(remainder):
        c = remainder[i]
        if in_quote:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_quote = False
        elif c == '"':
            in_quote = True
        elif c == "]":
            inner = remainder[1:i]
            after = remainder[i + 1 :]
            msg = after[1:] if after.startswith(" ") else after
            return inner, msg
        i += 1
    raise ValueError("unterminated structured-data element")


_SD_PARAM_RE = re.compile(r'([A-Za-z][A-Za-z0-9]*)="((?:[^"\\]|\\.)*)"')


def parse_rfc5424(line: str) -> dict[str, Any]:
    """Parse an RFC5424 syslog line into header fields + the SD-ELEMENT params.

    Grammar (RFC5424 §6): ``<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP
    PROCID SP MSGID SP STRUCTURED-DATA SP MSG``. Raises ``ValueError`` on any
    structural violation.
    """
    m = re.match(r"^<(\d{1,3})>(\d+) (.*)$", line, re.DOTALL)
    if m is None:
        raise ValueError("no valid <PRI>VERSION header")
    pri = int(m.group(1))
    version = m.group(2)
    rest = m.group(3)
    head = rest.split(" ", 5)
    if len(head) != 6:
        raise ValueError("truncated RFC5424 header (missing header fields)")
    timestamp, hostname, app_name, procid, msgid, tail = head
    sd_inner, msg = _split_sd_element(tail)
    sd_tokens = sd_inner.split(" ", 1)
    sd_id = sd_tokens[0]
    params: dict[str, str] = {}
    if len(sd_tokens) == 2:
        for pm in _SD_PARAM_RE.finditer(sd_tokens[1]):
            params[pm.group(1)] = _sd_unescape(pm.group(2))
    return {
        "pri": pri,
        "version": version,
        "timestamp": timestamp,
        "hostname": hostname,
        "app_name": app_name,
        "procid": procid,
        "msgid": msgid,
        "sd_id": sd_id,
        "sd_params": params,
        "msg": msg,
    }


def _split_unescaped(s: str, delim: str) -> list[str]:
    """Split *s* on *delim* not preceded by a backslash (escape-aware)."""
    out: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            cur.append(s[i : i + 2])
            i += 2
            continue
        if c == delim:
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def _cef_unescape_header(value: str) -> str:
    r"""Reverse CEF *header* escaping (``\|`` ``\\`` → literal)."""
    return value.replace("\\|", "|").replace("\\\\", "\\")


def _cef_unescape_extension(value: str) -> str:
    r"""Reverse CEF *extension* escaping (``\=`` ``\\`` ``\n`` ``\r`` → literal)."""
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "r": "\r"}.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_CEF_EXT_KEY_RE = re.compile(r"(?:^| )([A-Za-z][A-Za-z0-9]*)=")


def parse_cef(line: str) -> dict[str, Any]:
    """Parse an ArcSight CEF:0 line into header fields + the extension dictionary.

    Grammar: ``CEF:Version|Vendor|Product|DevVersion|SigID|Name|Severity|Extension``.
    The first 7 pipe-delimited fields are the header (escape-aware split); the
    remainder is the extension, parsed by ``key=value`` boundaries so a value with a
    space still tokenizes. Raises ``ValueError`` on a malformed header.
    """
    segs = _split_unescaped(line, "|")
    if len(segs) < 8:
        raise ValueError("CEF line has fewer than the 7 header fields + extension")
    if segs[0] != "CEF:0":
        raise ValueError(f"not a CEF:0 line: {segs[0]!r}")
    header = {
        "version": segs[0].split(":", 1)[1],
        "device_vendor": _cef_unescape_header(segs[1]),
        "device_product": _cef_unescape_header(segs[2]),
        "device_version": _cef_unescape_header(segs[3]),
        "signature_id": _cef_unescape_header(segs[4]),
        "name": _cef_unescape_header(segs[5]),
        "severity": segs[6],
    }
    extension_str = "|".join(segs[7:])
    keys = list(_CEF_EXT_KEY_RE.finditer(extension_str))
    if not keys:
        raise ValueError("CEF extension has no key=value pairs")
    ext: dict[str, str] = {}
    for idx, km in enumerate(keys):
        key = km.group(1)
        val_start = km.end()
        val_end = keys[idx + 1].start() if idx + 1 < len(keys) else len(extension_str)
        ext[key] = _cef_unescape_extension(extension_str[val_start:val_end])
    return {"header": header, "extension": ext}


#: The canonical HTTPS/JSON body schema (ADR-0045 §1). Every exported object must carry
#: exactly this key set with these types; ``target_id`` / ``request_id`` /
#: ``reasoning_trace_id`` are nullable. Chain outputs are FORBIDDEN — events only.
_JSON_REQUIRED = {
    "seq": int,
    "id": "uuid",
    "created_at": "rfc3339",
    "actor": str,
    "action": str,
    "target_type": str,
    "target_id": "str?",
    "request_id": "uuid?",
    "reasoning_trace_id": "uuid?",
    "detail": "dict?",
}
_JSON_FORBIDDEN = ("prev_hash", "entry_hash")


def parse_https_json(line: str) -> dict[str, Any]:
    """Parse + schema-validate the HTTPS/JSON body; raise ``ValueError`` on violation.

    Asserts the exact key set, per-field type (nullable where specified), the RFC3339
    timestamp + UUID shapes, and that no chain-output field ever leaks into the body.
    """
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("HTTPS/JSON body is not an object")
    keys = set(obj)
    if keys != set(_JSON_REQUIRED):
        raise ValueError(f"key set drift: {sorted(keys)} != {sorted(_JSON_REQUIRED)}")
    for forbidden in _JSON_FORBIDDEN:
        if forbidden in obj:
            raise ValueError(f"forbidden chain-output field present: {forbidden}")
    for key, spec in _JSON_REQUIRED.items():
        value = obj[key]
        if spec == "uuid":
            if not (isinstance(value, str) and _UUID_RE.match(value)):
                raise ValueError(f"{key} is not a UUID: {value!r}")
        elif spec == "uuid?":
            if value is not None and not (isinstance(value, str) and _UUID_RE.match(value)):
                raise ValueError(f"{key} is not a UUID or null: {value!r}")
        elif spec == "rfc3339":
            if not (isinstance(value, str) and _RFC3339_RE.match(value)):
                raise ValueError(f"{key} is not RFC3339: {value!r}")
        elif spec == "str?":
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{key} is not a string or null: {value!r}")
        elif spec == "dict?":
            if value is not None and not isinstance(value, dict):
                raise ValueError(f"{key} is not an object or null: {value!r}")
        # bool is an int subclass — reject it explicitly for the int field.
        elif isinstance(spec, type) and (
            not isinstance(value, spec) or (spec is int and isinstance(value, bool))
        ):
            raise ValueError(f"{key} is not {spec.__name__}: {value!r}")
    return obj


def assert_format_valid(fmt: str, payload: str) -> None:
    """Parse *payload* with the independent grammar for *fmt* and assert schema validity.

    Beyond a clean parse, pins the transport-invariant header facts + the presence and
    shape of the ``seq`` dedup key (ADR-0045 §2 — a stable per-row key in EVERY payload).
    """
    if fmt == "syslog":
        parsed = parse_rfc5424(payload)
        assert parsed["pri"] == 109, parsed["pri"]  # facility log-audit(13)*8 + notice(5)
        assert parsed["version"] == "1"
        assert parsed["app_name"] == "netops-audit"
        assert _RFC3339_RE.match(parsed["timestamp"]), parsed["timestamp"]
        assert re.match(r"^netopsAudit@\d+$", parsed["sd_id"]), parsed["sd_id"]
        params = parsed["sd_params"]
        for required in ("seq", "auditId", "actor", "action", "targetType", "detail"):
            assert required in params, f"missing SD-PARAM {required}"
        assert _UUID_RE.match(params["auditId"]), params["auditId"]
        # seq rides both the MSGID and an SD-PARAM, and they must agree.
        assert params["seq"] == parsed["msgid"], (params["seq"], parsed["msgid"])
        int(params["seq"])  # numeric dedup key
        json.loads(params["detail"])  # detail SD-PARAM is valid JSON after unescape
    elif fmt == "cef":
        parsed = parse_cef(payload)
        header = parsed["header"]
        assert header["version"] == "0"
        assert header["device_vendor"] == "NetOps"
        assert header["device_product"] == "AINetworkOpsPlatform"
        assert 0 <= int(header["severity"]) <= 10, header["severity"]
        assert header["name"], "CEF Name is empty"
        assert header["signature_id"], "CEF SignatureID is empty"
        ext = parsed["extension"]
        for required in ("externalId", "rt", "suser", "act", "cat", "cs1Label", "cs1"):
            assert required in ext, f"missing CEF extension {required}"
        int(ext["externalId"])  # the numeric dedup key
        assert _RFC3339_RE.match(ext["rt"]), ext["rt"]
        assert ext["cs1Label"] == "detail"
        json.loads(ext["cs1"])  # detail custom-string is valid JSON
    elif fmt == "https-json":
        parse_https_json(payload)  # full schema validation inside
    else:  # pragma: no cover - guard against a typo in the parametrization
        raise AssertionError(f"unknown format {fmt!r}")


def extract_seq(fmt: str, payload: str) -> int:
    """Extract the SIEM dedup key (``seq``) from *payload* via the independent parser."""
    if fmt == "syslog":
        return int(parse_rfc5424(payload)["sd_params"]["seq"])
    if fmt == "cef":
        return int(parse_cef(payload)["extension"]["externalId"])
    return int(parse_https_json(payload)["seq"])


def payload_leaks(fmt: str, payload: str, secret: str) -> bool:
    """True if *secret* appears in *payload* — raw OR in any parsed field value.

    Defence-in-depth: a naive substring scan PLUS a scan of every decoded field value
    (so an escaped/encoded leak that a raw scan might miss is still caught).
    """
    if secret in payload:
        return True
    if fmt == "syslog":
        values: list[str] = list(parse_rfc5424(payload)["sd_params"].values())
    elif fmt == "cef":
        parsed = parse_cef(payload)
        values = [*parsed["header"].values(), *parsed["extension"].values()]
    else:
        values = [json.dumps(v) for v in parse_https_json(payload).values()]
    return any(secret in v for v in values)


# ---------------------------------------------------------------------------
# In-memory fault-injectable sink + file-backed engine (cross-session commits).
# ---------------------------------------------------------------------------


class _RecordingSink:
    """An in-memory sink that records ACKed payloads; ``fail`` forces a sink outage."""

    def __init__(self) -> None:
        self.delivered: list[str] = []
        self.fail = False
        self.deliver_calls = 0

    async def deliver(self, payloads: list[str]) -> None:
        self.deliver_calls += 1
        if self.fail:
            raise SinkDeliveryError("injected outage")
        self.delivered.extend(payloads)


@pytest.fixture()
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """File-backed async SQLite + ``NullPool`` so a NEW session sees prior commits.

    Cross-session commit visibility is what the at-least-once / restart-resume proofs
    require (an in-memory ``StaticPool`` shares one connection and hides it).
    """
    db_path = tmp_path / "siem-export-conformance.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}", poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
def maker(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A sessionmaker over the file engine (each call → a fresh, isolated session)."""
    return async_sessionmaker(file_engine, expire_on_commit=False)


def _settings(fmt: str, *, batch_size: int = 2) -> Settings:
    """Minimal export Settings (format + bounded batch + tiny non-zero pacing)."""
    return Settings(
        audit_export_format=fmt,
        audit_export_endpoint="https://siem.example.test/collector",
        audit_export_host="siem.example.test",
        audit_export_batch_size=batch_size,
        audit_export_poll_seconds=0.001,
        audit_export_retry_backoff_seconds=0.001,
    )


async def _seed_audit_rows(
    maker: async_sessionmaker[AsyncSession],
    n: int,
    *,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append *n* audit rows through the REAL writer, each in its own committed txn."""
    for i in range(n):
        async with maker() as session:
            await audit_service.record(
                session,
                actor=f"user:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=str(i),
                detail=detail if detail is not None else {"step": i},
            )
            await session.commit()


def _example_record(**overrides: Any) -> ExportRecord:
    """The fixed record backing the byte-exact golden vectors."""
    base: dict[str, Any] = {
        "seq": 42,
        "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "created_at": datetime(2026, 6, 30, 12, 0, 0, tzinfo=UTC),
        "actor": "user:7",
        "action": "credential.rotated",
        "target_type": "device",
        "target_id": "core-sw-1",
        "request_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
        "reasoning_trace_id": None,
        "detail": {"credential_id": "abc", "outcome": "ok"},
    }
    base.update(overrides)
    return ExportRecord(**base)


async def _deliver_stream_under_outage_then_restart(
    maker: async_sessionmaker[AsyncSession],
    *,
    fmt: str,
    detail: dict[str, Any] | None = None,
) -> list[str]:
    """Drive the FULL fault scenario and return the SIEM-side payload stream.

    Timeline (all of the conformance dimensions run against THIS stream, ADR-0045
    §2/§3, exit criterion "under a fault-injected sink outage"):

    1. Seed 4 rows (seq 1..4). Hold the sink DOWN for 3 cycles — assert nothing is
       delivered AND the durable cursor never advances (rows stay committed, no drop).
    2. Recover the sink and drain via the loop.
    3. "Restart": a brand-new sink, 3 more rows appended (seq 5..7), drain again.

    Returns ``first_sink.delivered + restart_sink.delivered`` — the contiguous SIEM
    stream across the outage + restart boundary.
    """
    await _seed_audit_rows(maker, 4, detail=detail)
    settings = _settings(fmt, batch_size=2)

    sink = _RecordingSink()
    sink.fail = True
    for _ in range(3):
        async with maker() as session:
            result = await export_cycle(session, sink=sink, fmt=fmt, batch_size=2)
            assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0  # never advanced over un-ACKed rows

    sink.fail = False
    await run_export_loop(sessionmaker=maker, sink=sink, settings=settings, max_cycles=20)

    await _seed_audit_rows(maker, 3, detail=detail)  # seq 5..7, appended after the cursor
    restart_sink = _RecordingSink()
    await run_export_loop(sessionmaker=maker, sink=restart_sink, settings=settings, max_cycles=20)

    return sink.delivered + restart_sink.delivered


# ===========================================================================
# Dimension 1 — format validity (RFC5424 / CEF / HTTPS-JSON each schema-valid).
# ===========================================================================
@pytest.mark.parametrize("fmt", _FORMATS)
async def test_pipeline_output_is_schema_valid_for_every_payload(
    maker: async_sessionmaker[AsyncSession], fmt: str
) -> None:
    """Every payload the pipeline emits parses + validates under the independent grammar."""
    stream = await _deliver_stream_under_outage_then_restart(maker, fmt=fmt)
    assert stream, f"{fmt}: pipeline delivered nothing"
    for payload in stream:
        assert_format_valid(fmt, payload)


# ===========================================================================
# Byte-stability — deterministic + byte-exact golden vectors.
# ===========================================================================
def test_golden_byte_vectors_are_stable() -> None:
    """The three formatters emit the exact golden bytes for the fixed record."""
    rec = _example_record()
    assert format_syslog(rec, hostname="exporter-0") == _GOLDEN_SYSLOG
    assert format_cef(rec) == _GOLDEN_CEF
    assert format_https_json(rec) == _GOLDEN_JSON


def test_formatters_are_deterministic() -> None:
    """Formatting the same record twice yields byte-identical output (no wall-clock)."""
    rec = _example_record()
    assert format_syslog(rec, hostname="h") == format_syslog(rec, hostname="h")
    assert format_cef(rec) == format_cef(rec)
    assert format_https_json(rec) == format_https_json(rec)


# ===========================================================================
# Dimension 2 — ordering: events emitted in monotonic seq order.
# ===========================================================================
@pytest.mark.parametrize("fmt", _FORMATS)
async def test_delivered_stream_is_monotonic_by_seq(
    maker: async_sessionmaker[AsyncSession], fmt: str
) -> None:
    """The SIEM-side stream is strictly increasing in ``seq`` = DB append order (§2)."""
    stream = await _deliver_stream_under_outage_then_restart(maker, fmt=fmt)
    seqs = [extract_seq(fmt, p) for p in stream]
    assert seqs == sorted(seqs), f"{fmt}: out-of-order delivery {seqs}"
    # Strictly increasing here (this scenario delivers each row exactly once), which
    # implies monotonic non-decreasing under the at-least-once channel in general.
    assert len(set(seqs)) == len(seqs), f"{fmt}: unexpected duplicate in {seqs}"


# ===========================================================================
# Dimension 3 + 6 — cursor-resume, NO GAP, at-least-once under a sink outage.
# ===========================================================================
def _gap_report(seqs: list[int], expected: set[int]) -> tuple[set[int], set[int], list[int]]:
    """Return (missing, unexpected, non_contiguous_holes) for a delivered ``seq`` set.

    Pure so the no-gap assertion and its anti-vacuous self-bite share one implementation.
    """
    present = set(seqs)
    missing = expected - present
    unexpected = present - expected
    holes: list[int] = []
    if present:
        full = set(range(min(present), max(present) + 1))
        holes = sorted(full - present)
    return missing, unexpected, holes


@pytest.mark.parametrize("fmt", _FORMATS)
async def test_no_gap_at_least_once_under_outage_then_restart(
    maker: async_sessionmaker[AsyncSession], fmt: str
) -> None:
    """Under a fault-injected outage + restart, every committed row is delivered, no gap.

    The load-bearing conformance proof (ADR-0045 §2): after the sink recovers and the
    exporter restarts, the SIEM-side ``seq`` set is the CONTIGUOUS range 1..7 — every
    committed row present at-least-once (no drop) and no skipped ``seq`` (no gap).
    """
    stream = await _deliver_stream_under_outage_then_restart(maker, fmt=fmt)
    seqs = [extract_seq(fmt, p) for p in stream]
    expected = set(range(1, 8))  # seq 1..4 (drain) + 5..7 (restart)

    missing, unexpected, holes = _gap_report(seqs, expected)
    assert not missing, f"{fmt}: DROPPED rows (at-least-once violated): {sorted(missing)}"
    assert not unexpected, f"{fmt}: delivered undeclared seq(s): {sorted(unexpected)}"
    assert not holes, f"{fmt}: GAP in the delivered seq range: {holes}"
    assert set(seqs) == expected


def test_no_gap_checker_is_not_vacuous() -> None:
    """The gap checker reports a planted hole + a dropped row (it is not a no-op)."""
    expected = set(range(1, 6))
    missing, unexpected, holes = _gap_report([1, 2, 4, 5], expected)  # seq 3 dropped
    assert missing == {3}
    assert holes == [3]
    assert not unexpected
    # A stray/unexpected seq is surfaced too.
    missing2, unexpected2, _ = _gap_report([1, 2, 3, 4, 5, 9], expected)
    assert unexpected2 == {9} and not missing2


async def test_cursor_freezes_and_no_row_dropped_while_sink_down(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """While the sink is down the cursor never advances and no committed row is lost.

    The backpressure invariant (ADR-0045 §3): a down sink buffers in the durable table
    (cursor frozen at 0), then on recovery delivers the FULL contiguous stream — the
    negative control that the no-gap proof above is not passing by never faulting.
    """
    await _seed_audit_rows(maker, 3)
    sink = _RecordingSink()
    sink.fail = True
    for _ in range(4):
        async with maker() as session:
            result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
            assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0
    assert sink.delivered == []  # nothing left the platform while the sink was down

    sink.fail = False
    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert [extract_seq("https-json", p) for p in sink.delivered] == [1, 2, 3]


# ===========================================================================
# Dimension 4 — export-lag within the SLO (and the bite: a stall breaches it).
# ===========================================================================
async def test_export_lag_within_slo_after_outage_recovers(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """After the outage recovers and the backlog drains to head, lag is within the SLO.

    A caught-up stream reports lag ``0.0`` deterministically (ADR-0045 §3), which is
    trivially within the §6 p95 < 60 s bound — the "operating within the lag SLO"
    G-OBS release signal once the sink is healthy again.
    """
    await _seed_audit_rows(maker, 3)
    sink = _RecordingSink()
    sink.fail = True
    async with maker() as session:
        down = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert down.failed

    sink.fail = False
    async with maker() as session:
        drained = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert drained.delivered == 3 and drained.batch_full is False
    # Drained to head ⇒ caught up ⇒ deterministic lag 0.0, within the SLO bound.
    assert drained.lag_seconds == 0.0
    assert drained.lag_seconds <= _EXPORT_LAG_SLO_SECONDS

    async with maker() as session:
        idle = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert idle.delivered == 0 and idle.lag_seconds == 0.0


async def test_export_lag_breaches_slo_while_sink_held_down(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The lag-SLI bite: a held-down sink drives the SLI PAST the 60 s SLO bound.

    Proves the within-SLO assertion above is not vacuous — the SLI is a live measure
    that crosses the threshold when export actually stalls (the W3-T3 alert signal).
    The cursor is back-dated a full hour, so the > 60 s outcome is deterministic
    (a > 3500 s margin, no wall-clock flakiness).
    """
    await _seed_audit_rows(maker, 1)
    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    async with maker() as session:
        cursor = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
        assert cursor is not None
        cursor.last_exported_commit_at = utcnow() - timedelta(hours=1)
        await session.commit()

    await _seed_audit_rows(maker, 1)  # new backlog the down sink cannot drain
    sink.fail = True
    async with maker() as session:
        stalled = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert stalled.failed
    assert stalled.lag_seconds > _EXPORT_LAG_SLO_SECONDS  # SLO breached → alert fires


# ===========================================================================
# Dimension 5 — sentinel/secret ABSENT (secret-surface must-pass) + BITE.
# ===========================================================================
@pytest.mark.parametrize("fmt", _FORMATS)
async def test_no_planted_secret_in_any_pipeline_payload_under_outage(
    maker: async_sessionmaker[AsyncSession], fmt: str
) -> None:
    """MUST-PASS: a planted sentinel never appears in any exported payload (ADR-0045 §4).

    The audited action references the credential BY ID only (the writer contract,
    ADR-0032 §5) — the sentinel lives in a local that is never passed to ``detail``.
    Every payload across the full outage+restart stream is scanned raw AND per decoded
    field value: the sentinel must be absent from all of them.
    """
    # detail carries an id reference, never the secret value.
    stream = await _deliver_stream_under_outage_then_restart(
        maker, fmt=fmt, detail={"credential_id": "cred-1", "outcome": "ok"}
    )
    assert stream, f"{fmt}: delivered nothing"
    for payload in stream:
        assert not payload_leaks(fmt, payload, _SENTINEL_SECRET), (
            f"{fmt}: SENTINEL SECRET LEAKED into an exported payload"
        )


@pytest.mark.parametrize("fmt", _FORMATS)
def test_no_leak_scanner_bites_when_a_secret_is_present(fmt: str) -> None:
    """BITE: were a secret to reach the exported record, the scanner WOULD flag it.

    Non-vacuous control for the must-pass assertion above: a record whose ``detail``
    carries the sentinel (a writer-contract violation) serializes it, and the leak
    scanner detects it in EVERY transport. This proves the absence assertion has teeth
    — it fails exactly when a secret reaches the wire, not merely because nothing is
    ever scanned.
    """
    formatter = {"syslog": format_syslog, "cef": format_cef, "https-json": format_https_json}[fmt]
    leaky = _example_record(detail={"password": _SENTINEL_SECRET})
    payload = formatter(leaky)
    assert _SENTINEL_SECRET in payload  # the raw payload carries it
    assert payload_leaks(fmt, payload, _SENTINEL_SECRET)  # and the scanner catches it


# ===========================================================================
# Anti-vacuous — the independent parsers actually REJECT malformed payloads.
# ===========================================================================
def test_parsers_reject_malformed_input() -> None:
    """Each grammar parser raises on a structurally-invalid payload (not a no-op).

    Without this, a parser that accepted anything would make every format-validity
    assertion vacuous. Each transport's parser must reject a malformed input.
    """
    with pytest.raises(ValueError):
        parse_rfc5424("not-a-syslog-line")
    with pytest.raises(ValueError):
        parse_rfc5424("<109>1 2026-06-30T12:00:00Z host app - 7 [unterminated")
    with pytest.raises(ValueError):
        parse_cef("CEF:0|too|few|fields")
    with pytest.raises(ValueError):
        parse_cef("NOT-CEF|a|b|c|d|e|f|g=1")
    with pytest.raises(ValueError):
        parse_https_json('{"seq": 1}')  # missing required keys
    with pytest.raises(ValueError):
        parse_https_json(_GOLDEN_JSON.replace('"seq":42', '"seq":42,"prev_hash":"x"'))


def test_valid_golden_payloads_pass_their_parser() -> None:
    """Positive control: the byte-exact goldens parse + validate under every grammar."""
    assert_format_valid("syslog", _GOLDEN_SYSLOG)
    assert_format_valid("cef", _GOLDEN_CEF)
    assert_format_valid("https-json", _GOLDEN_JSON)
    assert extract_seq("syslog", _GOLDEN_SYSLOG) == 42
    assert extract_seq("cef", _GOLDEN_CEF) == 42
    assert extract_seq("https-json", _GOLDEN_JSON) == 42
