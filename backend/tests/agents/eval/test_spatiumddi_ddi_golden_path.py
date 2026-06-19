"""SpatiumDDI DDI golden-path integration test vs a deterministic REST mock (T5).

The DDI golden path (CLAUDE.md DDI mission / MVP §7 criterion 1), proved a second
time against the **SpatiumDDI** REST surface — offline, deterministic, no running
instance — mirroring ``test_m5_ddi_golden_path.py`` (the Infoblox WAPI variant):

    DDI Agent finds a stale DNS record
      -> a mutation produces a vendor-neutral ChangeRequestDraft (NO inline write)
      -> the framework gate persists it as a ddi_record ChangeRequest draft
      -> a DIFFERENT user approves it (four-eyes, server-side)
      -> the Automation Agent executes it via the REAL SpatiumClient over the mock
      -> the record is verified changed (post-write re-read, read-after-write)
      -> the audit chain links reasoning_trace -> CR -> audit_log
         (requester != approver != executor, before/after, reasoning trace).

This wires the REAL seams end to end — nothing about the decision path is faked:

* ``app.plugins.vendors.spatiumddi.plugin.SpatiumDdiDns.modify_record`` /
  ``.delete_record`` (T2) are the genuine mutators — they return a
  :class:`~app.plugins.base.ChangeRequestDraft` and perform NO HTTP I/O (the
  capability is built over a no-I/O client so an inline write would explode).
* ``app.agents.framework.approval.ChangeRequestGate`` turns the draft into a
  persistent ``ddi_record`` ChangeRequest — the change is NEVER applied inline.
* ``app.services.change_requests.ChangeRequestService`` enforces four-eyes: the
  approver must differ from the requester, server-side, on by default.
* ``app.agents.automation.AutomationAgent.execute`` is the sole executor; it
  reconstructs the draft from the approved CR payload (the production
  ``_draft_from_payload``) and applies it through a ``DdiChangeExecutor`` that
  drives the REAL ``SpatiumClient`` (T1) over an ``httpx.MockTransport``.

The SpatiumDDI mock is **stateful** and speaks the ADR-0024 REST shapes verbatim
(``PUT /api/v1/dns/groups/{gid}/zones/{zid}/records/{rid}`` mutates the in-memory
record; the verify GET reads it back; ``DELETE`` is a SOFT delete that moves the
row to a trash dict; ``POST /api/v1/admin/trash/dns_record/{rid}/restore`` undoes
it), so "record verified changed" / "record restored" are genuine read-after-write
assertions, not scripted booleans. The record/zone fixtures are the same
**source-derived** JSON the plugin unit tests use (``tests/plugins/fixtures/
spatiumddi/``, labeled "source-derived, not live-recorded", ADR-0024 §5), so the
mock's initial state matches the documented API.

Two golden paths are exercised:

1. **update** — a stale A record is corrected; the write lands and verifies.
2. **delete -> RESTORE inverse** — the SpatiumDDI-distinctive contract (ADR-0024
   §3): ``dns_record`` is a SOFT-delete type, so the draft's delete *inverse* is a
   trash RESTORE (``POST /admin/trash/dns_record/{id}/restore``), NOT a re-create.
   The executor routes the restore sentinel to the trash endpoint and the re-query
   confirms the ORIGINAL row (same id) is back — re-create would have minted a new
   id and orphaned the trash row.

Layer note: this is the deterministic CI layer (unit-only backend job). It proves
the control flow / wiring of the SpatiumDDI write path — NOT model judgment. The
*routing* decision that a "change the DNS record" request reaches the DDI draft
path (not the Automation executor) is proved at the control-flow level in
``tests/agents/test_eight_way_routing.py`` and at the real-LLM level in
``test_routing_eval.py`` (held-out, opt-in). The only secret anywhere here is the
obviously-fake SpatiumDDI bearer token sentinel.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
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
    SOFT_DELETE_RESOURCE_TYPES,
    VENDOR_ID,
    SpatiumContext,
    SpatiumDdiDns,
)
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord
from app.services.audit import service as audit
from app.services.change_requests import ChangeRequestService

pytestmark = pytest.mark.eval

# --- source-derived fixtures (ADR-0024 §5), shared with the plugin unit tests --
_FIXTURES = Path(__file__).parents[2] / "plugins" / "fixtures" / "spatiumddi"

# The SpatiumDDI addressing triple (group -> zone -> record), matching the
# source-derived fixtures' ids. A DNS record's full key is this triple.
_GROUP_ID = "11111111-1111-1111-1111-111111111111"
_ZONE_ID = "22222222-2222-2222-2222-222222222222"
_RECORD_ID = "33333333-3333-3333-3333-333333333333"  # the "www" A record fixture

_RECORD_NAME = "www"
_RECORD_ZONE = "example.com"
_STALE_IP = "10.0.0.10"  # the fixture's current (now-stale) value
_CORRECT_IP = "10.0.0.60"  # the corrected value the change must land

#: A clearly-fake SpatiumDDI bearer token — never a real secret (task constraint).
_FAKE_TOKEN = "sddi_FAKE-token-golden-path-zzz"  # noqa: S105 — obviously-fake sentinel
_FAKE_CREDS = SpatiumCredentials(appliance_id="golden-lab", token=_FAKE_TOKEN)

_CONTEXT = SpatiumContext(dns_group_ids=(_GROUP_ID,), zone_id=_ZONE_ID)


def _load(name: str) -> Any:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# In-memory DB (CR lifecycle + audit) — offline, no Postgres.
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
# Stateful SpatiumDDI REST mock (ADR-0024 source-derived paths/bodies).
#
# Holds the source-derived records keyed by id; serves the documented REST
# surface so the verify is a genuine read-after-write:
#   GET    /dns/groups/{gid}/zones/{zid}/records            -> live records list
#   GET    /dns/groups/{gid}/zones/{zid}/records/{rid}      -> one record (verify)
#   PUT    /dns/groups/{gid}/zones/{zid}/records/{rid}      -> update (record_type
#                                                              immutable; value/ttl)
#   DELETE /dns/groups/{gid}/zones/{zid}/records/{rid}?permanent=false
#                                                           -> SOFT delete -> trash
#   POST   /admin/trash/dns_record/{rid}/restore           -> the delete-inverse
# Every response is the SpatiumDDI JSON shape; no secret ever appears in it.
# ---------------------------------------------------------------------------


class _SpatiumMock:
    """A minimal stateful SpatiumDDI REST appliance over ``httpx.MockTransport``.

    Records are keyed by id (the immutable PK). Soft delete moves the row into the
    ``trash`` dict and out of ``records``; a restore moves it back atomically — so
    a restored row keeps its ORIGINAL id (the read-after-write the golden path
    asserts). The recorded requests are retained so the test can prove the executor
    really drove the REST API and never leaked the bearer token.
    """

    def __init__(self) -> None:
        records = {str(r["id"]): dict(r) for r in _load("records.json")}
        self.records: dict[str, dict[str, Any]] = records
        self.trash: dict[str, dict[str, Any]] = {}
        self.requests: list[httpx.Request] = []
        self._batch_seq = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        # The bearer token must ride the Authorization header and NOTHING else.
        assert request.url.path.find(_FAKE_TOKEN) == -1  # noqa: S101
        path = request.url.path.split("/api/v1", 1)[1]
        method = request.method

        # -- admin trash restore (the soft-delete inverse) --------------------
        if method == "POST" and path.startswith("/admin/trash/") and path.endswith("/restore"):
            return self._restore(path)

        # -- record collection / item ----------------------------------------
        records_prefix = f"/dns/groups/{_GROUP_ID}/zones/{_ZONE_ID}/records"
        if path == records_prefix and method == "GET":
            return httpx.Response(200, json=list(self.records.values()))
        if path.startswith(records_prefix + "/"):
            record_id = path[len(records_prefix) + 1 :]
            if method == "GET":
                row = self.records.get(record_id)
                return (
                    httpx.Response(200, json=dict(row))
                    if row is not None
                    else httpx.Response(404, json={"detail": "not found"})
                )
            if method == "PUT":
                return self._update(record_id, request)
            if method == "DELETE":
                return self._soft_delete(record_id, request)
        return httpx.Response(405, json={"detail": "method not allowed"})

    def _update(self, record_id: str, request: httpx.Request) -> httpx.Response:
        row = self.records.get(record_id)
        if row is None:
            return httpx.Response(404, json={"detail": "not found"})
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        # record_type is immutable server-side (ADR-0024 §1) — ignore it if sent.
        for field in ("value", "ttl", "name", "priority", "weight", "port"):
            if field in body and body[field] is not None:
                row[field] = body[field]
        return httpx.Response(200, json=dict(row))

    def _soft_delete(self, record_id: str, request: httpx.Request) -> httpx.Response:
        permanent = request.url.params.get("permanent", "false") == "true"
        row = self.records.pop(record_id, None)
        if row is None:
            return httpx.Response(404, json={"detail": "not found"})
        if not permanent:
            self._batch_seq += 1
            row = {**row, "deletion_batch_id": str(uuid.uuid4())}
            self.trash[record_id] = row
        return httpx.Response(204)

    def _restore(self, path: str) -> httpx.Response:
        # /admin/trash/{type}/{row_id}/restore
        parts = path.strip("/").split("/")
        type_, row_id = parts[2], parts[3]
        row = self.trash.pop(row_id, None)
        if row is None:
            # 409 in the real API on an active-row clash; 404 when nothing to undo.
            return httpx.Response(404, json={"detail": "nothing to restore"})
        restored = {k: v for k, v in row.items() if k != "deletion_batch_id"}
        self.records[row_id] = restored  # original id preserved (NOT a re-create)
        batch_id = str(row.get("deletion_batch_id") or uuid.uuid4())
        assert type_ == RESOURCE_DNS_RECORD  # noqa: S101 — routed by resource type
        return httpx.Response(200, json={"batch_id": batch_id, "restored": 1})


def _spatium_client(mock: _SpatiumMock) -> SpatiumClient:
    transport = httpx.MockTransport(mock.handler)
    http = httpx.AsyncClient(transport=transport)
    return SpatiumClient(
        base_url="https://sddi.golden-lab.example",
        credentials=_FAKE_CREDS,
        client=http,
    )


# ---------------------------------------------------------------------------
# A faithful DdiChangeExecutor that drives the REAL SpatiumClient over the mock.
#
# This is the golden-path equivalent of the production Wave-5 SpatiumDDI executor
# (ADR-0024 §4): it reconstructs the verb + path from the draft, applies the write
# through the real client, and verifies with a read-after-write. It implements the
# documented restore-sentinel routing (executors.DdiChangeExecutor docstring /
# plugin._restore_inverse): a CREATE draft with a non-None object_ref AND a
# ("restore","true") body entry routes to POST /admin/trash/{resource}/{id}/restore,
# NOT to a plain object-create.
# ---------------------------------------------------------------------------


class _SpatiumDdiExecutor:
    """Applies a SpatiumDDI ``ChangeRequestDraft`` via the real client + verify."""

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
            # Verify: the row is readable again by its ORIGINAL id (restore, not
            # a re-create that would have minted a new id).
            row = await self._client.get_records(group_id, zone_id)
            verified = any(str(r.get("id")) == draft.object_ref for r in row)
            return DdiChangeResult(
                verified=verified and bool(resp.get("restored")),
                object_ref=draft.object_ref,
                rolled_back=False,
            )

        if draft.verb is ChangeVerb.UPDATE and draft.object_ref is not None:
            await self._client.modify_record(group_id, zone_id, draft.object_ref, body)
            row = await self._client.get_records(group_id, zone_id)
            live = next((r for r in row if str(r.get("id")) == draft.object_ref), None)
            verified = live is not None and str(live.get("value")) == self._expected
            return DdiChangeResult(
                verified=verified, object_ref=draft.object_ref, rolled_back=False
            )

        if draft.verb is ChangeVerb.DELETE and draft.object_ref is not None:
            await self._client.delete_record(group_id, zone_id, draft.object_ref)
            row = await self._client.get_records(group_id, zone_id)
            verified = all(str(r.get("id")) != draft.object_ref for r in row)
            return DdiChangeResult(
                verified=verified, object_ref=draft.object_ref, rolled_back=False
            )

        return DdiChangeResult(verified=False, object_ref=draft.object_ref, rolled_back=False)


# ---------------------------------------------------------------------------
# Helpers building the REAL draft via the plugin, then the CR via the gate.
# ---------------------------------------------------------------------------


def _no_io_dns_cap() -> SpatiumDdiDns:
    """A DNS capability whose client explodes on any HTTP call.

    Proves the draft a mutation returns is data-only — no inline write happens at
    draft time (the write is the Automation Agent's job on an approved CR).
    """

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"mutation performed inline I/O: {request.method} {request.url.path}")

    http = httpx.AsyncClient(transport=httpx.MockTransport(explode))
    client = SpatiumClient(
        base_url="https://sddi.golden-lab.example", credentials=_FAKE_CREDS, client=http
    )
    return SpatiumDdiDns(client, uuid.uuid4(), _CONTEXT)


def _normalized(name: str, value: str) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=uuid.uuid4(),
        collected_at=datetime.now(UTC),
        source_vendor=VENDOR_ID,
        name=name,
        record_type=DnsRecordType.A,
        value=value,
        ttl=3600,
        zone=_RECORD_ZONE,
        object_ref=_RECORD_ID,
    )


def _approval_request_from_draft(draft: ChangeRequestDraft, *, tool_name: str) -> ApprovalRequest:
    """Serialize a real plugin draft into the gate's ApprovalRequest.

    The gate stores ``arguments`` verbatim as the CR ``payload`` (ADR-0020 §2);
    ``AutomationAgent._draft_from_payload`` reconstructs the draft from it. We use
    the draft's own JSON dump (``body``/``inverse.body`` become JSON list-of-pairs),
    which is exactly what ``_coerce_draft`` coerces back into tuple pairs — so the
    draft the executor applies is the same one the plugin produced, round-tripped
    through the persisted CR.
    """
    return ApprovalRequest(
        tool_name=tool_name,
        arguments=draft.model_dump(mode="json"),
        kind=ChangeRequestKind.DDI_RECORD,
        target_refs={"object_ref": draft.object_ref, "resource": draft.resource},
    )


# ---------------------------------------------------------------------------
# The golden path.
# ---------------------------------------------------------------------------


class TestSpatiumDdiGoldenPath:
    def test_modify_record_is_draft_only_no_inline_write(self) -> None:
        """The genuine mutator returns a draft and performs NO HTTP I/O.

        The capability is built over a client that raises on any request; the
        update therefore proves the capability layer is write-incapable — there is
        no DDI write path that skips the CR spine (ADR-0024 §4)."""
        cap = _no_io_dns_cap()
        prior = _normalized(_RECORD_NAME, _STALE_IP)
        changes = _normalized(_RECORD_NAME, _CORRECT_IP)
        draft = cap.modify_record(_RECORD_ID, changes, current=prior)
        assert draft.verb is ChangeVerb.UPDATE
        assert draft.resource == RESOURCE_DNS_RECORD
        assert draft.object_ref == _RECORD_ID
        assert dict(draft.body)["value"] == _CORRECT_IP
        # The inverse restores the prior value (record_type immutable -> value/ttl).
        assert draft.inverse is not None
        assert dict(draft.inverse.body)["value"] == _STALE_IP

    def test_delete_record_inverse_is_restore_not_recreate(self) -> None:
        """dns_record is a SOFT-delete type: the delete-inverse is a trash RESTORE
        (verb CREATE + same object_ref + restore sentinel), NOT a re-create — the
        SpatiumDDI-distinctive contract vs Infoblox (ADR-0024 §3)."""
        cap = _no_io_dns_cap()
        draft = cap.delete_record(_RECORD_ID, current=_normalized(_RECORD_NAME, _STALE_IP))
        assert draft.verb is ChangeVerb.DELETE
        assert draft.inverse is not None
        # The inverse is a RESTORE: a CREATE pinned to the existing id with the
        # restore sentinel, against a soft-delete resource type.
        assert draft.inverse.verb is ChangeVerb.CREATE
        assert draft.inverse.object_ref == _RECORD_ID
        assert draft.inverse.resource in SOFT_DELETE_RESOURCE_TYPES
        assert dict(draft.inverse.body).get("restore") == "true"

    async def test_full_golden_path_stale_to_verified_with_audit_chain(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()

        # --- 0. The mock starts with the stale fixture record (.10). ----------
        mock = _SpatiumMock()
        assert mock.records[_RECORD_ID]["value"] == _STALE_IP

        # --- 1. The DDI Agent proposes the correction. The REAL plugin mutator
        #        returns a vendor-neutral draft (no inline write). The framework
        #        gate persists it as a ddi_record ChangeRequest DRAFT.
        cap = _no_io_dns_cap()
        draft = cap.modify_record(
            _RECORD_ID,
            _normalized(_RECORD_NAME, _CORRECT_IP),
            current=_normalized(_RECORD_NAME, _STALE_IP),
        )
        gate = ChangeRequestGate(
            service,
            requester_id=requester,
            actor_role=Role.ENGINEER,
            reasoning_trace_id=trace_id,
        )
        decision = await gate.authorize(
            _approval_request_from_draft(draft, tool_name="modify_dns_record")
        )
        assert decision.change_request_created is True
        assert decision.approved is False  # a draft is NOT an approval
        cr_id = uuid.UUID(decision.change_request_id)
        assert (await service.get(cr_id)).state is ChangeRequestState.DRAFT

        # --- 2. Submit, then a DIFFERENT user approves (four-eyes, server-side).
        await service.submit(cr_id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr_id, actor_id=approver, actor_role=Role.ENGINEER)
        assert (await service.get(cr_id)).state is ChangeRequestState.APPROVED

        # --- 3. The Automation Agent executes via the REAL SpatiumClient/mock. -
        client = _spatium_client(mock)
        executor = _SpatiumDdiExecutor(client, expected_value=_CORRECT_IP)
        agent = AutomationAgent(change_request_service=service, ddi_executor=executor)
        result = await agent.execute(cr_id)

        # --- 4. The record is verified changed on the appliance (read-after-write).
        assert result.state is ChangeRequestState.COMPLETED
        assert (await service.get(cr_id)).state is ChangeRequestState.COMPLETED
        assert mock.records[_RECORD_ID]["value"] == _CORRECT_IP  # REST state mutated
        assert len(executor.applied) == 1
        # The draft reconstructed from the CR payload carried the correction.
        applied = executor.applied[0]
        assert applied.verb is ChangeVerb.UPDATE
        assert applied.object_ref == _RECORD_ID
        assert dict(applied.body)["value"] == _CORRECT_IP
        # The verify GET really re-read the appliance (a write + a read happened).
        methods = [r.method for r in mock.requests]
        assert "PUT" in methods and "GET" in methods

        # --- 5. The full audit chain is reconstructable. ----------------------
        rows = await _audit_rows(sessionmaker, cr_id)
        actions = [r.action for r in rows]
        assert audit.CHANGE_REQUEST_CREATED in actions
        assert audit.CHANGE_REQUEST_DRAFT_TO_PENDING in actions
        assert audit.CHANGE_REQUEST_PENDING_TO_APPROVED in actions
        assert audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING in actions
        assert audit.AUTOMATION_CHANGE_APPLIED in actions
        assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in actions

        created = next(r for r in rows if r.action == audit.CHANGE_REQUEST_CREATED)
        approved = next(r for r in rows if r.action == audit.CHANGE_REQUEST_PENDING_TO_APPROVED)
        executed = next(r for r in rows if r.action == audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING)
        # requester != approver != executor (the four-eyes chain).
        assert created.actor == f"user:{requester}"
        assert approved.actor == f"user:{approver}"
        assert created.actor != approved.actor
        assert executed.actor == "agent:automation"
        # Every transition carries the originating reasoning-trace link.
        for row in (created, approved, executed):
            assert row.reasoning_trace_id == trace_id

        # The approvals row records the distinct approver (four-eyes evidence).
        async with sessionmaker() as session:
            approvals = (
                (await session.execute(select(Approval).where(Approval.change_request_id == cr_id)))
                .scalars()
                .all()
            )
        assert len(approvals) == 1
        assert approvals[0].actor_id == approver
        assert approvals[0].decision is ApprovalDecision.APPROVE

        # No bearer token ever appeared in the audit detail (secret hygiene).
        blob = json.dumps([str(r.detail) for r in rows])
        assert _FAKE_TOKEN not in blob

    async def test_full_golden_path_delete_then_restore_inverse_lands(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A soft-delete golden path: the four-eyes-approved DELETE removes the row,
        then its RESTORE inverse (the soft-delete delete-inverse, ADR-0024 §3) is
        executed and the ORIGINAL row (same id) comes back — proving the inverse is
        a trash RESTORE, not a re-create that would mint a new id.

        The full audit chain (all 6 lifecycle actions) and four-eyes actor identity
        (requester != approver != executor) are verified for BOTH the delete CR and
        the restore CR, and no bearer token appears in any audit-detail blob.
        """
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()
        mock = _SpatiumMock()
        client = _spatium_client(mock)

        # --- Build + approve + execute the DELETE (soft) through the spine. ----
        delete_draft = _no_io_dns_cap().delete_record(
            _RECORD_ID, current=_normalized(_RECORD_NAME, _STALE_IP)
        )
        delete_cr = await _draft_to_approved_cr(
            service, sessionmaker, delete_draft, requester, approver, trace_id=trace_id
        )
        agent = AutomationAgent(
            change_request_service=service, ddi_executor=_SpatiumDdiExecutor(client)
        )
        del_result = await agent.execute(delete_cr)
        assert del_result.state is ChangeRequestState.COMPLETED
        # The row is soft-deleted: gone from live, present in trash (recoverable).
        assert _RECORD_ID not in mock.records
        assert _RECORD_ID in mock.trash

        # --- Audit chain for the DELETE CR. ------------------------------------
        del_rows = await _audit_rows(sessionmaker, delete_cr)
        del_actions = [r.action for r in del_rows]
        assert audit.CHANGE_REQUEST_CREATED in del_actions
        assert audit.CHANGE_REQUEST_DRAFT_TO_PENDING in del_actions
        assert audit.CHANGE_REQUEST_PENDING_TO_APPROVED in del_actions
        assert audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING in del_actions
        assert audit.AUTOMATION_CHANGE_APPLIED in del_actions
        assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in del_actions

        del_created = next(r for r in del_rows if r.action == audit.CHANGE_REQUEST_CREATED)
        del_approved = next(
            r for r in del_rows if r.action == audit.CHANGE_REQUEST_PENDING_TO_APPROVED
        )
        del_executed = next(
            r for r in del_rows if r.action == audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING
        )
        # Four-eyes: requester != approver != executor.
        assert del_created.actor == f"user:{requester}"
        assert del_approved.actor == f"user:{approver}"
        assert del_created.actor != del_approved.actor
        assert del_executed.actor == "agent:automation"
        # Every transition carries the originating reasoning-trace link.
        for row in (del_created, del_approved, del_executed):
            assert row.reasoning_trace_id == trace_id
        # No bearer token in any audit-detail blob (secret hygiene).
        del_blob = json.dumps([str(r.detail) for r in del_rows])
        assert _FAKE_TOKEN not in del_blob

        # --- Now execute the RESTORE inverse as its own approved CR. -----------
        restore_draft = delete_draft.inverse
        assert restore_draft is not None
        assert restore_draft.verb is ChangeVerb.CREATE
        assert dict(restore_draft.body).get("restore") == "true"  # the sentinel
        restore_cr = await _draft_to_approved_cr(
            service, sessionmaker, restore_draft, requester, approver, trace_id=trace_id
        )
        restore_executor = _SpatiumDdiExecutor(client)
        agent2 = AutomationAgent(change_request_service=service, ddi_executor=restore_executor)
        restore_result = await agent2.execute(restore_cr)

        # --- The ORIGINAL row is back, same id (RESTORE, not re-create). -------
        assert restore_result.state is ChangeRequestState.COMPLETED
        assert _RECORD_ID in mock.records
        assert _RECORD_ID not in mock.trash
        assert mock.records[_RECORD_ID]["value"] == _STALE_IP  # original value intact
        # The executor routed to the trash-restore endpoint, not an object-create.
        restore_paths = [r.url.path for r in mock.requests if r.method == "POST"]
        assert any(
            p.endswith(f"/admin/trash/{RESOURCE_DNS_RECORD}/{_RECORD_ID}/restore")
            for p in restore_paths
        )

        # --- Audit chain for the RESTORE CR. -----------------------------------
        restore_rows = await _audit_rows(sessionmaker, restore_cr)
        restore_actions = [r.action for r in restore_rows]
        assert audit.CHANGE_REQUEST_CREATED in restore_actions
        assert audit.CHANGE_REQUEST_DRAFT_TO_PENDING in restore_actions
        assert audit.CHANGE_REQUEST_PENDING_TO_APPROVED in restore_actions
        assert audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING in restore_actions
        assert audit.AUTOMATION_CHANGE_APPLIED in restore_actions
        assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in restore_actions

        rest_created = next(r for r in restore_rows if r.action == audit.CHANGE_REQUEST_CREATED)
        rest_approved = next(
            r for r in restore_rows if r.action == audit.CHANGE_REQUEST_PENDING_TO_APPROVED
        )
        rest_executed = next(
            r for r in restore_rows if r.action == audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING
        )
        # Four-eyes: requester != approver != executor.
        assert rest_created.actor == f"user:{requester}"
        assert rest_approved.actor == f"user:{approver}"
        assert rest_created.actor != rest_approved.actor
        assert rest_executed.actor == "agent:automation"
        # Every transition carries the originating reasoning-trace link.
        for row in (rest_created, rest_approved, rest_executed):
            assert row.reasoning_trace_id == trace_id
        # No bearer token in any audit-detail blob (secret hygiene).
        restore_blob = json.dumps([str(r.detail) for r in restore_rows])
        assert _FAKE_TOKEN not in restore_blob


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


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
    maker: async_sessionmaker[AsyncSession],
    draft: ChangeRequestDraft,
    requester: uuid.UUID,
    approver: uuid.UUID,
    *,
    trace_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Persist *draft* as a CR, submit it, and four-eyes-approve it (approver != requester).

    *trace_id* is stored on the CR (and propagated to every audit row) so callers
    can assert the reasoning_trace -> CR -> audit_log linkage required by the spec.
    """
    gate = ChangeRequestGate(
        service,
        requester_id=requester,
        actor_role=Role.ENGINEER,
        reasoning_trace_id=trace_id,
    )
    decision = await gate.authorize(
        _approval_request_from_draft(draft, tool_name="ddi_record_change")
    )
    cr_id = uuid.UUID(decision.change_request_id)
    await service.submit(cr_id, actor_id=requester, actor_role=Role.ENGINEER)
    await service.approve(cr_id, actor_id=approver, actor_role=Role.ENGINEER)
    return cr_id
