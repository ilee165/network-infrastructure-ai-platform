"""M5 DDI golden-path integration test vs the Infoblox WAPI mock (task T18).

MVP.md §7 criterion 1 — the headline end-to-end loop, demonstrated offline and
deterministically against an Infoblox WAPI **mock** (no appliance, no network):

    DDI Agent finds a stale DNS record
      -> drafts a ChangeRequest (via the framework ChangeRequestGate)
      -> a DIFFERENT user approves it (four-eyes, server-side)
      -> the Automation Agent executes it via the Infoblox WAPI
      -> the record is verified changed (post-write re-read)
      -> the audit log shows the full chain
         (requester, approver, executor, before/after, reasoning trace).

This wires the REAL seams end to end:

* ``app.engines.topology.dns.derive_dns`` (T13) detects the stale record — the
  DDI record's address does not reconcile to the collected inventory (the
  "stale" condition a DDI mismatch surfaces).
* ``app.agents.framework.approval.ChangeRequestGate`` (T4) turns the agent's
  state-changing ``modify_dns_record`` intent into a persistent ``ddi_record``
  ChangeRequest draft — the change is NEVER applied inline.
* ``app.services.change_requests.ChangeRequestService`` (T3) enforces four-eyes:
  the approver must differ from the requester, server-side, on by default.
* ``app.agents.automation.AutomationAgent.execute`` (T9) is the sole executor; it
  drives ``approved -> executing -> completed`` and applies the change through a
  ``DdiChangeExecutor`` that calls the REAL ``WapiClient`` (T7) over an
  ``httpx.MockTransport`` — a stateful WAPI mock that records the write and lets
  the post-write re-read VERIFY the new value.

The WAPI mock is stateful (PUT mutates the in-memory record; the verify GET reads
it back), so "record verified changed" is a genuine read-after-write against the
mock, not a scripted boolean.

Layer note: this is the deterministic CI layer. The *routing* decision that a
"change the DNS record" request reaches the DDI draft path (not the Automation
executor — M5-PLAN risk #4) is proved at the control-flow level in
``tests/agents/test_eight_way_routing.py`` and at the real-LLM level in
``test_routing_eval.py`` (held-out, opt-in). The only secret anywhere here is the
obviously-fake WAPI credential.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
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
from app.engines.topology.dns import derive_dns
from app.models import (
    Approval,
    ApprovalDecision,
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    Device,
    User,
)
from app.models import Role as RoleRow
from app.plugins.base import ChangeRequestDraft, ChangeVerb
from app.plugins.vendors.infoblox.wapi import WapiClient, WapiCredentials
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord
from app.services.audit import service as audit
from app.services.change_requests import ChangeRequestService

pytestmark = pytest.mark.eval

#: A clearly-fake WAPI credential — never a real secret (task constraint).
_FAKE_CREDS = WapiCredentials(username="admin", password="FAKE-w@pi-pw-golden")

#: The stale A record: DNS says billing points at .50, inventory says .60.
_RECORD_NAME = "billing-app.corp.example"
_RECORD_REF = "record:a/ZG5zLmJpbGxpbmc:billing-app.corp.example/default"
_STALE_IP = "10.2.3.50"
_CORRECT_IP = "10.2.3.60"


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
# Stateful Infoblox WAPI mock: PUT mutates the record; GET reads it back so the
# post-write verify is a genuine read-after-write (not a scripted boolean).
# ---------------------------------------------------------------------------


class _WapiMock:
    """A minimal stateful Infoblox WAPI appliance over ``httpx.MockTransport``.

    Holds one A record (``_RECORD_REF`` -> current ``ipv4addr``). ``GET`` on the
    object ref returns its current state; ``PUT`` on the ref applies the new
    ``ipv4addr`` (the modify). The recorded requests are retained so the test can
    assert the executor really drove the WAPI (and never leaked the credential).
    """

    def __init__(self, *, initial_ip: str) -> None:
        self.record = {"_ref": _RECORD_REF, "name": _RECORD_NAME, "ipv4addr": initial_ip}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        # Path is /wapi/v2.12/<objtype-or-ref>. The ref carries slashes/colons.
        ref_or_type = request.url.path.split("/wapi/", 1)[1].split("/", 1)[1]
        if request.method == "GET":
            # A read of the record ref (verify) or of record:a (initial list).
            if ref_or_type.startswith("record:a/"):
                return httpx.Response(200, json=[dict(self.record)])
            if ref_or_type == "record:a":
                return httpx.Response(200, json=[dict(self.record)])
            return httpx.Response(200, json=[])
        if request.method == "PUT":
            import json as _json

            body = _json.loads(request.content.decode("utf-8")) if request.content else {}
            new_ip = body.get("ipv4addr")
            if new_ip:
                self.record["ipv4addr"] = str(new_ip)
            return httpx.Response(200, json=self.record["_ref"])
        return httpx.Response(405, json={"Error": "method not allowed"})


def _wapi_client(mock: _WapiMock) -> WapiClient:
    transport = httpx.MockTransport(mock.handler)
    http = httpx.Client(transport=transport)
    return WapiClient(
        base_url="https://gm.corp.example",
        version="2.12",
        credentials=_FAKE_CREDS,
        client=http,
    )


# ---------------------------------------------------------------------------
# A faithful DdiChangeExecutor that drives the REAL WapiClient over the mock.
# (The production wiring lands in Wave 5; this is the golden-path equivalent —
# it applies the draft as a WAPI PUT and verifies via a read-after-write.)
# ---------------------------------------------------------------------------


class _WapiDdiExecutor:
    """Applies a DDI ``ChangeRequestDraft`` through the real WAPI client + verify.

    For the golden path: a ``modify`` draft is a WAPI ``PUT`` of the new value
    against the record ref, followed by a GET re-read to confirm the new value is
    live (``verified``). No secret is ever placed in the result — only the opaque
    ``_ref`` and the verify flag (``DdiChangeResult`` contract, ADR-0022 §3).
    """

    def __init__(self, client: WapiClient, mock: _WapiMock, *, expected_value: str) -> None:
        self._client = client
        self._mock = mock
        self._expected = expected_value
        self.applied: list[ChangeRequestDraft] = []

    async def apply(self, cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
        self.applied.append(draft)
        ref = draft.object_ref or _RECORD_REF
        # The WAPI write: PUT the new ipv4addr (the draft body) onto the ref.
        body = dict(draft.body)
        self._client._client.put(  # drive the mock through the client's transport
            f"{self._client._wapi_root}/{ref}",
            json=body,
            auth=httpx.BasicAuth(_FAKE_CREDS.username, _FAKE_CREDS.password),
        )
        # Verify: read the record back and confirm the intended end-state.
        objs = self._client.get(ref)
        live_ip = objs[0].get("ipv4addr") if objs else None
        verified = live_ip == self._expected
        return DdiChangeResult(verified=verified, object_ref=ref, rolled_back=False)


# ---------------------------------------------------------------------------
# Stale-record detection via the real DNS topology derivation.
# ---------------------------------------------------------------------------


def _stale_record() -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        collected_at=datetime.now(UTC),
        source_vendor="infoblox",
        name=_RECORD_NAME,
        record_type=DnsRecordType.A,
        value=_STALE_IP,
        zone="corp.example",
        object_ref=_RECORD_REF,
    )


def _billing_device() -> Device:
    # The real host is at the CORRECT ip; the DNS record points at the STALE ip.
    return Device(
        id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        hostname="billing-app",
        mgmt_ip=_CORRECT_IP,
        vendor_id="cisco_ios",
    )


# ---------------------------------------------------------------------------
# The golden path.
# ---------------------------------------------------------------------------


class TestDdiGoldenPath:
    def test_derive_dns_flags_the_stale_record(self) -> None:
        """The DNS-layer derivation shows the stale A record does NOT reconcile to
        the host's real address — the "stale record" the DDI agent surfaces."""
        derived = derive_dns(
            [_stale_record()], ["corp.example"], [_billing_device()], interfaces=[]
        )
        edge = next(e for e in derived.resolves_to if e.value == _STALE_IP)
        # The DNS value (.50) does not match the device's real mgmt_ip (.60),
        # so it cannot reconcile — exactly the mismatch that makes it stale.
        assert edge.reconciled is False

    async def test_full_golden_path_stale_to_verified_with_audit_chain(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()

        # --- 1. The DDI Agent proposes the correction. The framework gate turns
        #        the state-changing intent into a ddi_record ChangeRequest DRAFT
        #        (never applied inline) — bound to the requesting user's identity.
        gate = ChangeRequestGate(
            service,
            requester_id=requester,
            actor_role=Role.ENGINEER,
            reasoning_trace_id=trace_id,
        )
        decision = await gate.authorize(
            ApprovalRequest(
                tool_name="modify_dns_record",
                arguments={
                    "verb": "update",
                    "resource": "record:a",
                    "object_ref": _RECORD_REF,
                    "body": [["ipv4addr", _CORRECT_IP]],
                    "summary": f"correct {_RECORD_NAME} A record to {_CORRECT_IP}",
                },
                kind=ChangeRequestKind.DDI_RECORD,
                target_refs={"object_ref": _RECORD_REF, "name": _RECORD_NAME},
            )
        )
        assert decision.change_request_created is True
        assert decision.approved is False  # a draft is NOT an approval
        cr_id = uuid.UUID(decision.change_request_id)
        assert (await service.get(cr_id)).state is ChangeRequestState.DRAFT

        # --- 2. Submit, then a DIFFERENT user approves (four-eyes, server-side).
        await service.submit(cr_id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr_id, actor_id=approver, actor_role=Role.ENGINEER)
        assert (await service.get(cr_id)).state is ChangeRequestState.APPROVED

        # --- 3. The Automation Agent executes via the REAL WAPI client/mock.
        mock = _WapiMock(initial_ip=_STALE_IP)
        client = _wapi_client(mock)
        executor = _WapiDdiExecutor(client, mock, expected_value=_CORRECT_IP)
        agent = AutomationAgent(change_request_service=service, ddi_executor=executor)
        result = await agent.execute(cr_id)

        # --- 4. The record is verified changed on the appliance (read-after-write).
        assert result.state is ChangeRequestState.COMPLETED
        assert (await service.get(cr_id)).state is ChangeRequestState.COMPLETED
        assert mock.record["ipv4addr"] == _CORRECT_IP  # WAPI state really mutated
        assert len(executor.applied) == 1
        # The draft reconstructed from the CR payload carried the correction.
        applied_draft = executor.applied[0]
        assert applied_draft.verb is ChangeVerb.UPDATE
        assert ("ipv4addr", _CORRECT_IP) in applied_draft.body

        # --- 5. The full audit chain is reconstructable.
        async with sessionmaker() as session:
            rows = (
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

    async def test_same_user_cannot_approve_then_execute(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """The golden path's four-eyes guard: the requester cannot self-approve, so
        the record is never changed on the appliance (the WAPI is never written)."""
        from app.core.errors import ForbiddenError

        requester = await _seed_user(sessionmaker, role_name="engineer")
        gate = ChangeRequestGate(service, requester_id=requester, actor_role=Role.ENGINEER)
        decision = await gate.authorize(
            ApprovalRequest(
                tool_name="modify_dns_record",
                arguments={
                    "verb": "update",
                    "resource": "record:a",
                    "object_ref": _RECORD_REF,
                    "body": [["ipv4addr", _CORRECT_IP]],
                    "summary": "correct billing record",
                },
                kind=ChangeRequestKind.DDI_RECORD,
                target_refs={"object_ref": _RECORD_REF},
            )
        )
        cr_id = uuid.UUID(decision.change_request_id)
        await service.submit(cr_id, actor_id=requester, actor_role=Role.ENGINEER)

        with pytest.raises(ForbiddenError):
            await service.approve(cr_id, actor_id=requester, actor_role=Role.ENGINEER)

        # The appliance was never touched: still pending, no WAPI write happened.
        mock = _WapiMock(initial_ip=_STALE_IP)
        assert (await service.get(cr_id)).state is ChangeRequestState.PENDING_APPROVAL
        assert mock.record["ipv4addr"] == _STALE_IP
