"""Opt-in LIVE SpatiumDDI DDI golden-path test (T6).

This is the live-lab twin of ``test_spatiumddi_ddi_golden_path.py`` (the
deterministic, mock-backed CI variant). It drives the *same* end-to-end DDI
golden path (CLAUDE.md DDI mission / MVP §7 criterion 1) but against a **real,
self-hosted SpatiumDDI instance** instead of an ``httpx.MockTransport`` — proving
the wiring works against the genuine REST surface, default group/zone
bootstrapping, and token-scope enforcement that only a running instance exhibits
(ADR-0024 §6 open questions):

    seed a (soon-to-be-stale) DNS record on the live appliance
      -> the REAL plugin mutator returns a vendor-neutral ChangeRequestDraft
         (NO inline write — the capability is built over a no-I/O client)
      -> the framework gate persists it as a ddi_record ChangeRequest DRAFT
      -> a DIFFERENT user approves it (four-eyes, server-side)
      -> the Automation Agent executes it via the REAL SpatiumClient over HTTP
      -> the record is verified changed (post-write re-read, read-after-write)
      -> the delete -> RESTORE inverse lands (soft-delete delete-inverse, §3)
      -> the audit chain links reasoning_trace -> CR -> audit_log
         (requester != approver != executor, before/after, reasoning trace).

**This test NEVER runs in CI.** It is gated by ``@pytest.mark.integration`` AND a
``skipif`` keyed on the ``SPATIUMDDI_BASE_URL`` / ``SPATIUMDDI_TOKEN`` environment
variables, which CI never sets — so it is *collected but skipped* under the
standard ``pytest`` gate run. To run it against a lab instance, bring SpatiumDDI
up (see ``deploy/spatiumddi/README.md``), mint a least-privilege resource-scoped
token, and export:

    SPATIUMDDI_BASE_URL   scheme + host[:port] of the appliance (``/api/v1`` is
                          appended by ``SpatiumClient``); e.g. ``https://sddi.lab``
    SPATIUMDDI_TOKEN      the raw ``sddi_<token>`` bearer (a SECRET — never logged,
                          never committed; minted once via POST /api/v1/api-tokens)
    SPATIUMDDI_GROUP_ID   the DNS server-group id holding the test zone
    SPATIUMDDI_ZONE_ID    the test zone id (the resource the token is scoped to)
    SPATIUMDDI_VERIFY     optional: "0"/"false" to disable TLS verify for a
                          self-signed lab cert (default: verify ON)

The test is self-cleaning: it creates its own throw-away A record, exercises the
update + delete/restore paths against it, and permanently removes it at the end
(``permanent=true``) so a re-run starts clean. The only secret anywhere — the
bearer token — rides the ``Authorization`` header inside ``SpatiumClient`` and is
asserted absent from every audit-detail blob (parity with the mock variant).
"""

from __future__ import annotations

import contextlib
import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.automation.agent import AutomationAgent
from app.agents.automation.executors import DdiChangeResult
from app.agents.framework.approval import ApprovalRequest, ChangeRequestGate
from app.core.security import Role
from app.models import (
    Approval,
    ApprovalDecision,
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.plugins.base import ChangeRequestDraft, ChangeVerb
from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials
from app.plugins.vendors.spatiumddi.plugin import (
    RESOURCE_DNS_RECORD,
    VENDOR_ID,
    SpatiumContext,
    SpatiumDdiDns,
)
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord
from app.services.audit import service as audit
from app.services.change_requests import ChangeRequestService

# --- env-var gate: the test is collected-but-SKIPPED unless a live SpatiumDDI is
#     configured. CI never sets these, so this never runs (and never fails) in CI.
_BASE_URL = os.environ.get("SPATIUMDDI_BASE_URL", "").strip()
_TOKEN = os.environ.get("SPATIUMDDI_TOKEN", "").strip()
_GROUP_ID = os.environ.get("SPATIUMDDI_GROUP_ID", "").strip()
_ZONE_ID = os.environ.get("SPATIUMDDI_ZONE_ID", "").strip()
_VERIFY = os.environ.get("SPATIUMDDI_VERIFY", "1").strip().lower() not in {"0", "false", "no"}

_LIVE_CONFIGURED = bool(_BASE_URL and _TOKEN and _GROUP_ID and _ZONE_ID)
_SKIP_REASON = (
    "opt-in live lab gate: set SPATIUMDDI_BASE_URL, SPATIUMDDI_TOKEN, "
    "SPATIUMDDI_GROUP_ID and SPATIUMDDI_ZONE_ID to run against a real "
    "self-hosted SpatiumDDI (see deploy/spatiumddi/README.md). Skipped in CI."
)

# Both markers apply: `integration` classifies it as a compose/lab test, and the
# `skipif` is the mechanism that actually keeps it out of the unbounded CI run
# (the CI gate runs `pytest` with no `-m` filter, so the marker alone would NOT
# exclude it — the env-var skipif does).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _LIVE_CONFIGURED, reason=_SKIP_REASON),
]

_RECORD_NAME = f"netops-golden-{uuid.uuid4().hex[:8]}"
_STALE_IP = "10.99.0.10"  # the value we seed then treat as "stale"
_CORRECT_IP = "10.99.0.60"  # the corrected value the change must land


# ---------------------------------------------------------------------------
# In-memory CR/audit spine (offline) — identical posture to the mock variant.
# The DDI write path is the only thing that talks to the real appliance; the
# ChangeRequest lifecycle + audit chain live in a throw-away SQLite DB.
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def service(sessionmaker: async_sessionmaker[AsyncSession]) -> ChangeRequestService:
    return ChangeRequestService(sessionmaker)


async def _seed_user(maker: async_sessionmaker[AsyncSession], *, role_name: str) -> uuid.UUID:
    async with maker() as session:
        role = RoleRow(name=f"{role_name}-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
        session.add(user)
        await session.commit()
        return user.id


# ---------------------------------------------------------------------------
# Live SpatiumClient against the configured appliance.
# ---------------------------------------------------------------------------


@pytest.fixture()
async def live_client() -> AsyncIterator[SpatiumClient]:
    creds = SpatiumCredentials(appliance_id="live-lab", token=_TOKEN)
    client = SpatiumClient(base_url=_BASE_URL, credentials=creds, verify=_VERIFY)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture()
async def seeded_record(live_client: SpatiumClient) -> AsyncIterator[str]:
    """Create a throw-away A record on the live zone; hard-delete it on teardown.

    Yields the new record's id (its immutable PK / ``object_ref``). The record is
    permanently removed in teardown (``permanent=true``) so the trash stays clean
    and a re-run starts fresh — even if the test body soft-deletes/restores it.
    """
    created = await live_client.add_record(
        _GROUP_ID,
        _ZONE_ID,
        {"name": _RECORD_NAME, "record_type": "A", "value": _STALE_IP, "ttl": 3600},
    )
    record_id = str(created["id"])
    try:
        yield record_id
    finally:
        # Permanent cleanup regardless of the body's final state (live or trashed).
        # Best-effort teardown: a cleanup failure must never mask a real result.
        with contextlib.suppress(Exception):
            await live_client.delete_record(_GROUP_ID, _ZONE_ID, record_id, permanent=True)


# ---------------------------------------------------------------------------
# A faithful live DdiChangeExecutor — the golden-path equivalent of the Wave-5
# production SpatiumDDI executor (ADR-0024 §4): reconstruct verb + path from the
# draft, apply via the REAL client, verify with a read-after-write, and route the
# restore sentinel to the trash-restore endpoint (NOT a plain object-create).
# ---------------------------------------------------------------------------


class _LiveSpatiumDdiExecutor:
    def __init__(self, client: SpatiumClient, *, expected_value: str | None = None) -> None:
        self._client = client
        self._expected = expected_value
        self.applied: list[ChangeRequestDraft] = []

    async def apply(self, cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
        self.applied.append(draft)
        body = dict(draft.body)
        group_id = body.get("group_id", _GROUP_ID)
        zone_id = body.get("zone_id", _ZONE_ID)

        # -- restore sentinel: a soft-delete inverse, NOT a plain create -------
        if (
            draft.verb is ChangeVerb.CREATE
            and draft.object_ref is not None
            and body.get("restore") == "true"
        ):
            resp = await self._client.restore_trash(draft.resource, draft.object_ref)
            rows = await self._client.get_records(group_id, zone_id)
            verified = any(str(r.get("id")) == draft.object_ref for r in rows)
            return DdiChangeResult(
                verified=verified and bool(resp.get("restored")),
                object_ref=draft.object_ref,
                rolled_back=False,
            )

        if draft.verb is ChangeVerb.UPDATE and draft.object_ref is not None:
            await self._client.modify_record(group_id, zone_id, draft.object_ref, body)
            rows = await self._client.get_records(group_id, zone_id)
            live = next((r for r in rows if str(r.get("id")) == draft.object_ref), None)
            verified = live is not None and str(live.get("value")) == self._expected
            return DdiChangeResult(
                verified=verified, object_ref=draft.object_ref, rolled_back=False
            )

        if draft.verb is ChangeVerb.DELETE and draft.object_ref is not None:
            await self._client.delete_record(group_id, zone_id, draft.object_ref)
            rows = await self._client.get_records(group_id, zone_id)
            verified = all(str(r.get("id")) != draft.object_ref for r in rows)
            return DdiChangeResult(
                verified=verified, object_ref=draft.object_ref, rolled_back=False
            )

        return DdiChangeResult(verified=False, object_ref=draft.object_ref, rolled_back=False)


# ---------------------------------------------------------------------------
# Helpers: the genuine plugin mutator (no inline I/O) + gate serialization.
# ---------------------------------------------------------------------------


def _context() -> SpatiumContext:
    return SpatiumContext(dns_group_ids=(_GROUP_ID,), zone_id=_ZONE_ID)


def _no_io_dns_cap() -> SpatiumDdiDns:
    """A DNS capability whose client explodes on any HTTP call.

    Proves the draft a mutation returns is data-only: building it performs NO
    inline write (the write is the Automation Agent's job on an approved CR).
    """
    import httpx  # local import: only the no-I/O guard transport needs it.

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"mutation performed inline I/O: {request.method} {request.url.path}")

    http = httpx.AsyncClient(transport=httpx.MockTransport(explode))
    client = SpatiumClient(
        base_url="https://no-io.invalid",
        credentials=SpatiumCredentials(appliance_id="no-io", token="sddi_unused"),  # noqa: S106
        client=http,
    )
    return SpatiumDdiDns(client, uuid.uuid4(), _context())


def _normalized(value: str, *, object_ref: str | None = None) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=uuid.uuid4(),
        collected_at=datetime.now(UTC),
        source_vendor=VENDOR_ID,
        name=_RECORD_NAME,
        record_type=DnsRecordType.A,
        value=value,
        ttl=3600,
        zone=_ZONE_ID,
        object_ref=object_ref,
    )


def _approval_request_from_draft(draft: ChangeRequestDraft, *, tool_name: str) -> ApprovalRequest:
    return ApprovalRequest(
        tool_name=tool_name,
        arguments=draft.model_dump(mode="json"),
        kind=ChangeRequestKind.DDI_RECORD,
        target_refs={"object_ref": draft.object_ref, "resource": draft.resource},
    )


async def _audit_rows(maker: async_sessionmaker[AsyncSession], cr_id: uuid.UUID) -> list[AuditLog]:
    async with maker() as session:
        return list(
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.target_id == str(cr_id))
                    .order_by(AuditLog.created_at)
                )
            )
            .scalars()
            .all()
        )


async def _draft_to_approved_cr(
    service: ChangeRequestService,
    draft: ChangeRequestDraft,
    requester: uuid.UUID,
    approver: uuid.UUID,
    *,
    trace_id: uuid.UUID,
    tool_name: str,
) -> uuid.UUID:
    gate = ChangeRequestGate(
        service,
        requester_id=requester,
        actor_role=Role.ENGINEER,
        reasoning_trace_id=trace_id,
    )
    decision = await gate.authorize(_approval_request_from_draft(draft, tool_name=tool_name))
    cr_id = uuid.UUID(decision.change_request_id)
    await service.submit(cr_id, actor_id=requester, actor_role=Role.ENGINEER)
    await service.approve(cr_id, actor_id=approver, actor_role=Role.ENGINEER)
    return cr_id


def _assert_full_audit_chain(rows: list[AuditLog]) -> None:
    actions = [r.action for r in rows]
    assert audit.CHANGE_REQUEST_CREATED in actions
    assert audit.CHANGE_REQUEST_DRAFT_TO_PENDING in actions
    assert audit.CHANGE_REQUEST_PENDING_TO_APPROVED in actions
    assert audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING in actions
    assert audit.AUTOMATION_CHANGE_APPLIED in actions
    assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in actions


def _assert_four_eyes_and_trace(
    rows: list[AuditLog], *, requester: uuid.UUID, approver: uuid.UUID, trace_id: uuid.UUID
) -> None:
    created = next(r for r in rows if r.action == audit.CHANGE_REQUEST_CREATED)
    approved = next(r for r in rows if r.action == audit.CHANGE_REQUEST_PENDING_TO_APPROVED)
    executed = next(r for r in rows if r.action == audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING)
    assert created.actor == f"user:{requester}"
    assert approved.actor == f"user:{approver}"
    assert created.actor != approved.actor  # four-eyes: requester != approver
    assert executed.actor == "agent:automation"  # ... != executor
    for row in (created, approved, executed):
        assert row.reasoning_trace_id == trace_id
    # The bearer token must never appear in any audit-detail blob (secret hygiene).
    assert _TOKEN not in json.dumps([str(r.detail) for r in rows])


# ---------------------------------------------------------------------------
# The live golden path.
# ---------------------------------------------------------------------------


class TestSpatiumDdiLiveGoldenPath:
    async def test_live_update_stale_to_verified_with_audit_chain(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        live_client: SpatiumClient,
        seeded_record: str,
    ) -> None:
        record_id = seeded_record
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()

        # 0. The live appliance starts with the (now-stale) seeded value.
        rows = await live_client.get_records(_GROUP_ID, _ZONE_ID)
        live = next(r for r in rows if str(r.get("id")) == record_id)
        assert str(live["value"]) == _STALE_IP

        # 1. The REAL plugin mutator returns a vendor-neutral draft — no inline I/O.
        draft = _no_io_dns_cap().modify_record(
            record_id,
            _normalized(_CORRECT_IP, object_ref=record_id),
            current=_normalized(_STALE_IP, object_ref=record_id),
        )
        assert draft.verb is ChangeVerb.UPDATE
        assert draft.object_ref == record_id

        # 2. Persist as a DRAFT, submit, then a DIFFERENT user approves (four-eyes).
        cr_id = await _draft_to_approved_cr(
            service, draft, requester, approver, trace_id=trace_id, tool_name="modify_dns_record"
        )
        assert (await service.get(cr_id)).state is ChangeRequestState.APPROVED

        # 3. The Automation Agent executes via the REAL SpatiumClient over HTTP.
        executor = _LiveSpatiumDdiExecutor(live_client, expected_value=_CORRECT_IP)
        agent = AutomationAgent(change_request_service=service, ddi_executor=executor)
        result = await agent.execute(cr_id)

        # 4. The record is verified changed on the live appliance (read-after-write).
        assert result.state is ChangeRequestState.COMPLETED
        rows = await live_client.get_records(_GROUP_ID, _ZONE_ID)
        live = next(r for r in rows if str(r.get("id")) == record_id)
        assert str(live["value"]) == _CORRECT_IP

        # 5. The full audit chain + four-eyes identity + secret hygiene.
        audit_rows = await _audit_rows(sessionmaker, cr_id)
        _assert_full_audit_chain(audit_rows)
        _assert_four_eyes_and_trace(
            audit_rows, requester=requester, approver=approver, trace_id=trace_id
        )

        async with sessionmaker() as session:
            approvals = (
                (await session.execute(select(Approval).where(Approval.change_request_id == cr_id)))
                .scalars()
                .all()
            )
        assert len(approvals) == 1
        assert approvals[0].actor_id == approver
        assert approvals[0].decision is ApprovalDecision.APPROVE

    async def test_live_delete_then_restore_inverse_lands(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        live_client: SpatiumClient,
        seeded_record: str,
    ) -> None:
        """A live soft-delete golden path: the approved DELETE soft-removes the row,
        then its RESTORE inverse (ADR-0024 §3) brings the ORIGINAL row (same id)
        back from trash — proving the inverse is a trash RESTORE, not a re-create."""
        record_id = seeded_record
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()

        # Build the DELETE draft via the genuine mutator (its inverse is a RESTORE).
        delete_draft = _no_io_dns_cap().delete_record(
            record_id, current=_normalized(_STALE_IP, object_ref=record_id)
        )
        assert delete_draft.inverse is not None
        assert delete_draft.inverse.verb is ChangeVerb.CREATE
        assert dict(delete_draft.inverse.body).get("restore") == "true"
        assert delete_draft.inverse.resource == RESOURCE_DNS_RECORD

        # Approve + execute the soft DELETE through the spine.
        delete_cr = await _draft_to_approved_cr(
            service, delete_draft, requester, approver, trace_id=trace_id, tool_name="delete_record"
        )
        agent = AutomationAgent(
            change_request_service=service, ddi_executor=_LiveSpatiumDdiExecutor(live_client)
        )
        del_result = await agent.execute(delete_cr)
        assert del_result.state is ChangeRequestState.COMPLETED

        # The row is soft-deleted: gone from the live zone, present in trash.
        live_rows = await live_client.get_records(_GROUP_ID, _ZONE_ID)
        assert all(str(r.get("id")) != record_id for r in live_rows)
        trash = await live_client.list_trash(type_=RESOURCE_DNS_RECORD)
        assert any(str(t.get("id")) == record_id for t in trash)

        del_rows = await _audit_rows(sessionmaker, delete_cr)
        _assert_full_audit_chain(del_rows)
        _assert_four_eyes_and_trace(
            del_rows, requester=requester, approver=approver, trace_id=trace_id
        )

        # Execute the RESTORE inverse as its own approved CR.
        restore_draft = delete_draft.inverse
        restore_cr = await _draft_to_approved_cr(
            service,
            restore_draft,
            requester,
            approver,
            trace_id=trace_id,
            tool_name="restore_record",
        )
        restore_executor = _LiveSpatiumDdiExecutor(live_client)
        agent2 = AutomationAgent(change_request_service=service, ddi_executor=restore_executor)
        restore_result = await agent2.execute(restore_cr)

        # The ORIGINAL row is back, same id and value (RESTORE, not a re-create).
        assert restore_result.state is ChangeRequestState.COMPLETED
        live_rows = await live_client.get_records(_GROUP_ID, _ZONE_ID)
        restored = next((r for r in live_rows if str(r.get("id")) == record_id), None)
        assert restored is not None
        assert str(restored["value"]) == _STALE_IP

        restore_rows = await _audit_rows(sessionmaker, restore_cr)
        _assert_full_audit_chain(restore_rows)
        _assert_four_eyes_and_trace(
            restore_rows, requester=requester, approver=approver, trace_id=trace_id
        )
