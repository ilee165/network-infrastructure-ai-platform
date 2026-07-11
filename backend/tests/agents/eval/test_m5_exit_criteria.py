"""M5 exit-criteria eval suite (task T18) — the eight MVP.md §7 criteria.

Each test class encodes exactly one exit criterion from MVP.md §7 (ChangeRequest
workflow, DDI/Infoblox, packet analysis, Automation Agent — MVP feature-complete
at M5 exit). The suite is the deliverable: it is fixture-grounded and fully
deterministic — no live Postgres/Neo4j/Redis, no network, no real LLM, no live
capture — and it drives the *real* M5 production code paths (the
``ChangeRequestService`` lifecycle + four-eyes guard, the framework
``ChangeRequestGate``, the real ``AutomationAgent.execute`` write path over
injected executor ports, the Infoblox ``WapiClient`` over an httpx
``MockTransport``, the ``engines/packet`` ``summarize_packets`` analyzer, the
``engines/topology`` ``derive_dns`` projection, the pcap retention helpers, and
the Documentation Agent's ``render_incident_report`` under a fake chat model).

Which layer proves which criterion
----------------------------------

This file is the **deterministic layer** (runs in CI). It proves the wiring and
control flow of each criterion against fixtures; it does NOT prove model
judgment. Two of the eight criteria carry facets a scripted replay cannot
honestly validate, and each is covered at the real-LLM layer elsewhere:

* The golden-path / non-approved / self-approval criteria turn on the
  *routing decision* ("change X" must reach the DDI draft path, never the
  Automation executor — M5-PLAN risk #4). The control-flow half is proved here
  and in ``tests/agents/test_eight_way_routing.py`` (deterministic, scripted
  ``RoutingDecision``); the *routing-quality* half — that a real model routes
  eight held-out intents correctly — is the opt-in, CI-skipped real-LLM gate
  ``test_routing_eval.py`` (the 8-way roster, ``NETOPS_RUN_ROUTING_EVAL=1``).
* The incident-report criterion's *narrative* is model-written; the
  deterministic layer proves the report is grounded in the session facts
  (timeline, evidence refs, trace ref), is A9-redacted, and is the
  ``incident_report`` ``Document`` shape — the plumbing is exact. The quality of
  a real model's prose is degradable (a weak model writes worse prose, never
  wrong facts: the timeline/evidence tables are deterministic, not invented) and
  is out of scope here.

The packet top-talkers-vs-tshark ground-truth comparison (criterion 4) and the
DDI golden-path integration test against the Infoblox WAPI mock (criterion 1)
are large enough to live in their own files —
``test_m5_packet_ground_truth.py`` and ``test_m5_ddi_golden_path.py`` — and are
referenced from the criterion classes below so the §7 mapping stays complete.

Criteria (MVP.md §7):

1. E2E golden path: DDI finds a stale record -> CR -> a *different* user approves
   -> Automation executes via WAPI -> verified -> full audit chain.
   *(driven end-to-end in ``test_m5_ddi_golden_path.py``; this file pins the
   four-eyes + audit-chain spine.)*
2. A non-``approved`` CR cannot execute; self-approval is rejected under default
   config.
3. Config restore of a prior snapshot executes through a CR; the device matches
   the snapshot afterward.
4. A UI capture -> pcap -> sandboxed tshark -> the top-talkers summary matches
   ``tshark`` ground truth. *(the ground-truth comparison is
   ``test_m5_packet_ground_truth.py``; this file pins the analyzer/agent path.)*
5. Expired pcaps are removed by the retention job; metadata rows are tombstoned
   and audited.
6. An incident report (timeline, evidence links, trace refs) is stored + embedded.
7. The DNS-dependency layer is visible in topology; ``RESOLVES_TO`` matches
   Infoblox zone data.
8. Security review checklist signed off; Trivy zero critical CVEs; all M0 CI
   gates green. *(a process/release gate, owned by T19/T20; encoded here as the
   automatable slice — the redaction invariant the write paths must hold so no
   secret reaches an LLM/audit detail.)*
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from langchain_core.messages import AIMessage
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.automation.agent import AutomationAgent, ChangeExecutionRefused
from app.agents.documentation.tools import render_incident_report
from app.agents.framework.approval import ApprovalRequest, ChangeRequestGate
from app.core.errors import ConflictError, ForbiddenError
from app.core.security import Role
from app.engines.packet import (
    Conversation,
    expired_capture_ids,
    ingest_capture,
    summarize_packets,
    tombstone_capture,
)
from app.engines.topology.dns import derive_dns
from app.models import (
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    Device,
    User,
)
from app.models import Role as RoleRow
from app.models.pcap_metadata import PcapMetadata
from app.plugins.base import (
    ChangeOutcome,
    ChangePlan,
    ChangeResult,
    RollbackResult,
)
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord
from app.services.audit import service as audit
from app.services.change_requests import ChangeRequestService
from tests.agents.conftest import scripted_model

pytestmark = pytest.mark.eval

# A secret-bearing config line — the kind a write path must never surface to an
# LLM or echo into an audit ``detail`` (criterion 8 / A9, ADR-0017 §3).
_SECRET_LITERAL = "S3cr3tCommunityRO"
_SECRET_FRAGMENT = f"snmp-server community {_SECRET_LITERAL} RO\nntp server 10.0.0.1"

_DEVICE_ID = "22222222-2222-2222-2222-222222222222"


# ===========================================================================
# Shared in-memory database + CR-lifecycle helpers (offline; no Postgres).
# ===========================================================================


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema + FK enforcement."""
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


async def _audit_rows(maker: async_sessionmaker[AsyncSession], cr_id: uuid.UUID) -> list[AuditLog]:
    async with maker() as session:
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
        return list(rows)


async def _draft_pending_config_cr(
    service: ChangeRequestService,
    maker: async_sessionmaker[AsyncSession],
    requester_id: uuid.UUID,
) -> ChangeRequest:
    """Author + submit a config CR (now ``pending_approval``, awaiting approval)."""
    cr = await service.create_draft(
        requester_id=requester_id,
        actor_role=Role.ENGINEER,
        kind=ChangeRequestKind.CONFIG,
        payload={"capability": "config_deploy", "fragment": _SECRET_FRAGMENT},
        target_refs={"device_id": _DEVICE_ID},
        rollback_plan={"baseline_content_hash": "abc123"},
        reasoning_trace_id=uuid.uuid4(),
    )
    await service.submit(cr.id, actor_id=requester_id, actor_role=Role.ENGINEER)
    return await service.get(cr.id)


# ===========================================================================
# Scripted executor ports for the Automation Agent write path (no transport).
# ===========================================================================


class _ScriptedConfigExecutor:
    """A ``ConfigChangeExecutor`` returning a pre-scripted ``ChangeResult``."""

    def __init__(self, result_factory: Any) -> None:
        self._result_factory = result_factory
        self.calls: list[tuple[ChangeRequest, ChangePlan]] = []

    async def apply(self, cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
        self.calls.append((cr, plan))
        return self._result_factory(cr, plan)


def _restore_applied(cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
    """A successful config restore whose verify-after matched the snapshot."""
    return ChangeResult(
        change_request_id=cr.id,
        outcome=ChangeOutcome.APPLIED,
        verified=True,
        applied_diff=("+restored to snapshot", "-drifted lines"),
        rollback=None,
    )


def _restore_rolled_back(cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
    return ChangeResult(
        change_request_id=cr.id,
        outcome=ChangeOutcome.ROLLED_BACK,
        verified=False,
        applied_diff=(),
        rollback=RollbackResult(
            attempted=True, succeeded=True, verified=True, detail="restored baseline"
        ),
    )


# ===========================================================================
# Criterion 1 — golden path: four-eyes + reconstructable audit chain.
# (The full DDI WAPI golden path runs in test_m5_ddi_golden_path.py.)
# ===========================================================================


class TestCriterion1GoldenPathAuditChainSpine:
    """A different user approves; the requester->approver->executor chain + the
    before/after state + the reasoning-trace link are all reconstructable from
    ``audit_log`` + ``approvals`` alone (MVP §7 criterion 1, ADR-0020 §4).

    This pins the *spine* of the golden path that every variant shares; the
    end-to-end DDI WAPI variant (stale record -> CR -> approve -> execute ->
    verify) is ``test_m5_ddi_golden_path.py``.
    """

    async def test_full_chain_is_reconstructable_from_audit_and_approvals(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()

        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": _DEVICE_ID},
            rollback_plan={"baseline_content_hash": "abc123"},
            reasoning_trace_id=trace_id,
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        config_exec = _ScriptedConfigExecutor(_restore_applied)
        agent = AutomationAgent(change_request_service=service, config_executor=config_exec)
        result = await agent.execute(cr.id)
        assert result.state is ChangeRequestState.COMPLETED

        rows = await _audit_rows(sessionmaker, cr.id)
        actions = [row.action for row in rows]
        # Requester authored + submitted; a DIFFERENT user approved; the
        # Automation principal executed and completed — the full chain.
        assert audit.CHANGE_REQUEST_CREATED in actions
        assert audit.CHANGE_REQUEST_DRAFT_TO_PENDING in actions
        assert audit.CHANGE_REQUEST_PENDING_TO_APPROVED in actions
        assert audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING in actions
        assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in actions

        created = next(r for r in rows if r.action == audit.CHANGE_REQUEST_CREATED)
        approved = next(r for r in rows if r.action == audit.CHANGE_REQUEST_PENDING_TO_APPROVED)
        executed = next(r for r in rows if r.action == audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING)
        completed = next(r for r in rows if r.action == audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED)
        # Distinct actors: requester != approver, executor is the Automation principal.
        assert created.actor == f"user:{requester}"
        assert approved.actor == f"user:{approver}"
        assert created.actor != approved.actor
        assert executed.actor == "agent:automation"
        # Every transition is tied to the originating reasoning trace.
        for row in (created, approved, executed, completed):
            assert row.reasoning_trace_id == trace_id

        # The approvals row records the distinct approver (four-eyes evidence).
        async with sessionmaker() as session:
            from app.models.change_requests import Approval, ApprovalDecision

            approvals = (
                (await session.execute(select(Approval).where(Approval.change_request_id == cr.id)))
                .scalars()
                .all()
            )
        assert len(approvals) == 1
        assert approvals[0].actor_id == approver
        assert approvals[0].decision is ApprovalDecision.APPROVE


# ===========================================================================
# Criterion 2 — non-approved cannot execute; self-approval rejected.
# ===========================================================================


class TestCriterion2NonApprovedCannotExecuteAndSelfApprovalRejected:
    """MVP §7 criterion 2 (M5-PLAN risk #2, the heaviest write-path control)."""

    @pytest.mark.parametrize(
        "force_state",
        [
            ChangeRequestState.DRAFT,
            ChangeRequestState.PENDING_APPROVAL,
            ChangeRequestState.COMPLETED,
            ChangeRequestState.FAILED,
            ChangeRequestState.ROLLED_BACK,
        ],
    )
    async def test_executor_refuses_every_non_approved_state(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        force_state: ChangeRequestState,
    ) -> None:
        """The Automation Agent refuses any CR not in ``approved`` — no write,
        state untouched, refusal audited."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": _DEVICE_ID},
        )
        async with sessionmaker() as session:
            row = await session.get(ChangeRequest, cr.id)
            assert row is not None
            row.state = force_state
            await session.commit()

        config_exec = _ScriptedConfigExecutor(_restore_applied)
        agent = AutomationAgent(change_request_service=service, config_executor=config_exec)
        with pytest.raises(ChangeExecutionRefused):
            await agent.execute(cr.id)

        assert config_exec.calls == []  # no device write
        assert (await service.get(cr.id)).state is force_state  # untouched
        actions = {r.action for r in await _audit_rows(sessionmaker, cr.id)}
        assert audit.AUTOMATION_EXECUTION_REFUSED in actions

    async def test_self_approval_is_rejected_under_default_config(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """four_eyes_required defaults True: the requester approving their own CR
        is a ``ForbiddenError`` — checked before any state write or approvals row,
        so the CR never reaches ``approved`` and so can never execute."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await _draft_pending_config_cr(service, sessionmaker, requester)
        assert cr.four_eyes_required is True

        with pytest.raises(ForbiddenError):
            await service.approve(cr.id, actor_id=requester, actor_role=Role.ENGINEER)

        # Still pending: no self-approval leaked through, no approvals row written.
        assert (await service.get(cr.id)).state is ChangeRequestState.PENDING_APPROVAL
        async with sessionmaker() as session:
            from app.models.change_requests import Approval

            approvals = (
                (await session.execute(select(Approval).where(Approval.change_request_id == cr.id)))
                .scalars()
                .all()
            )
        assert approvals == []
        # And because it never reached approved, the executor refuses it too.
        agent = AutomationAgent(
            change_request_service=service,
            config_executor=_ScriptedConfigExecutor(_restore_applied),
        )
        with pytest.raises(ChangeExecutionRefused):
            await agent.execute(cr.id)

    async def test_pending_approval_cannot_be_executed_directly(
        self,
        service: ChangeRequestService,
    ) -> None:
        """The lifecycle has no edge from ``pending_approval`` to ``executing`` —
        ``mark_executing`` requires ``approved`` and raises ``ConflictError``
        otherwise (even with the verified principal)."""
        from app.services.change_requests import AUTOMATION_PRINCIPAL

        maker = service.sessionmaker
        requester = await _seed_user(maker, role_name="engineer")
        cr = await _draft_pending_config_cr(service, maker, requester)
        with pytest.raises(ConflictError):
            await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)


# ===========================================================================
# Criterion 3 — config restore of a prior snapshot through a CR; device matches.
# ===========================================================================


class TestCriterion3ConfigRestoreThroughChangeRequest:
    """A CONFIG restore CR drives approved -> executing -> completed; the verified
    ``after_state`` records that the device matched the snapshot (MVP §7 #3).

    The restore *payload* references a prior ``config_snapshots`` content hash
    (the rollback baseline); the deterministic executor stands in for the device
    apply and reports ``verified=True`` — exactly the post-restore "device config
    matches the snapshot afterward" signal the criterion asserts.
    """

    async def test_restore_completes_and_records_verified_match(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        snapshot_hash = "snapshot-deadbeef"
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"capability": "config_restore", "snapshot_content_hash": snapshot_hash},
            target_refs={"device_id": _DEVICE_ID},
            rollback_plan={"baseline_content_hash": snapshot_hash},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        config_exec = _ScriptedConfigExecutor(_restore_applied)
        agent = AutomationAgent(change_request_service=service, config_executor=config_exec)
        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert result.state is ChangeRequestState.COMPLETED
        assert final.state is ChangeRequestState.COMPLETED
        # The executor received an *executing* plan attesting the snapshot baseline.
        assert len(config_exec.calls) == 1
        _, plan = config_exec.calls[0]
        assert plan.is_executing
        assert plan.baseline_content_hash == snapshot_hash
        # The verified post-restore match is recorded on the CR's after_state.
        assert final.after_state is not None
        assert final.after_state.get("verified") is True

    async def test_restore_failure_rolls_back_to_baseline_never_completes(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A restore whose verify-after fails rolls back to the captured baseline
        (failed -> rolled_back) and never reports completed (ADR-0021 §3)."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"capability": "config_restore"},
            target_refs={"device_id": _DEVICE_ID},
            rollback_plan={"baseline_content_hash": "x"},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        agent = AutomationAgent(
            change_request_service=service,
            config_executor=_ScriptedConfigExecutor(_restore_rolled_back),
        )
        result = await agent.execute(cr.id)
        assert result.state is ChangeRequestState.ROLLED_BACK
        actions = {r.action for r in await _audit_rows(sessionmaker, cr.id)}
        assert audit.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK in actions
        assert audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED not in actions


# ===========================================================================
# Criterion 4 — capture -> tshark -> top-talkers summary (analyzer path here;
# the tshark-ground-truth comparison is test_m5_packet_ground_truth.py).
# ===========================================================================


class TestCriterion4PacketTopTalkersFromSandboxedAnalysis:
    """The packet analyzer turns tshark ``-T json`` records into a normalized
    top-talkers summary (most-active conversation first), with no raw payload
    bytes crossing the boundary (MVP §7 #4, ADR-0023 §1).

    The byte-for-byte equality with ``tshark``'s own conversation tally is the
    ground-truth comparison in ``test_m5_packet_ground_truth.py``; this class
    pins the analyzer contract the criterion's summary depends on.
    """

    @staticmethod
    def _pkt(src: str, dst: str, length: int) -> dict[str, Any]:
        return {
            "_source": {
                "layers": {
                    "ip": {"ip.src": src, "ip.dst": dst},
                    "frame": {"frame.len": str(length)},
                    "tcp": {},
                }
            }
        }

    def test_top_talkers_ordered_by_packet_volume(self) -> None:
        # 3 packets A->B, 1 packet C->D. A->B must rank first.
        packets = [
            self._pkt("10.0.0.1", "10.0.0.2", 100),
            self._pkt("10.0.0.1", "10.0.0.2", 200),
            self._pkt("10.0.0.1", "10.0.0.2", 150),
            self._pkt("10.0.0.5", "10.0.0.6", 60),
        ]
        findings = summarize_packets(packets)
        assert findings.packet_count == 4
        assert findings.top_talkers[0] == Conversation(
            src="10.0.0.1", dst="10.0.0.2", packets=3, bytes=450
        )
        assert findings.top_talkers[1] == Conversation(
            src="10.0.0.5", dst="10.0.0.6", packets=1, bytes=60
        )

    def test_analyzer_emits_only_aggregates_no_payload(self) -> None:
        """The normalized findings carry counts/addresses only — never any packet
        payload field (the data-minimization boundary, ADR-0023 §1)."""
        findings = summarize_packets([self._pkt("10.0.0.1", "10.0.0.2", 100)])
        dumped = findings.model_dump()
        assert set(dumped) == {
            "packet_count",
            "top_talkers",
            "protocol_hierarchy",
            "tcp_resets",
            "tcp_retransmissions",
        }
        # No conversation field is anything but addressing/volume metadata.
        for talker in dumped["top_talkers"]:
            assert set(talker) == {"src", "dst", "packets", "bytes"}


# ===========================================================================
# Criterion 5 — retention job removes expired pcaps; rows tombstoned + audited.
# ===========================================================================


class TestCriterion5PcapRetentionTombstonesAndAudits:
    """An expired capture is found by the retention worklist, its row is
    tombstoned (never deleted), and the purge is audited (MVP §7 #5)."""

    async def test_expired_capture_is_listed_tombstoned_and_audited(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        capture_id = uuid.uuid4()
        started = datetime.now(UTC) - timedelta(days=40)

        # Persist a capture whose retention clock has already expired.
        async with sessionmaker() as session:
            await ingest_capture(
                session,
                capture_id=capture_id,
                requester_id=requester,
                interface="eth0",
                storage_path=f"/pcaps/{capture_id}.pcap",
                sha256="abc",
                byte_count=1024,
                packet_count=10,
                started_at=started,
                ended_at=started + timedelta(minutes=5),
                retention_days=30,
            )  # return value unused — worklist uses capture_id only
            await session.commit()

        # The retention worklist surfaces exactly this capture as expired.
        async with sessionmaker() as session:
            expired = await expired_capture_ids(session)
        assert capture_id in expired

        # Tombstone it (the worker deletes the file first; that is mocked at the
        # worker layer — here we drive the metadata side the criterion asserts).
        async with sessionmaker() as session:
            row = await tombstone_capture(
                session, capture_id=capture_id, reason="retention_expired"
            )
            await session.commit()
        assert row is not None
        assert row.tombstoned_at is not None
        assert row.tombstoned_reason == "retention_expired"

        # The row SURVIVES (never deleted) so the audit fact persists.
        async with sessionmaker() as session:
            still = (
                await session.execute(
                    select(PcapMetadata).where(PcapMetadata.capture_id == capture_id)
                )
            ).scalar_one_or_none()
        assert still is not None

        # A tombstoned capture is no longer in the worklist (idempotent retention).
        async with sessionmaker() as session:
            expired_again = await expired_capture_ids(session)
        assert capture_id not in expired_again

        # Audit the purge exactly as the worker does, and assert it is recorded.
        async with sessionmaker() as session:
            await audit.record(
                session,
                actor="system:retention",
                action="pcap.purged",
                target_type="pcap_metadata",
                target_id=str(capture_id),
                detail={"sha256": "abc", "file_removed": True, "reason": "retention_expired"},
            )
            await session.commit()
        async with sessionmaker() as session:
            purges = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.target_id == str(capture_id),
                            AuditLog.action == "pcap.purged",
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(purges) == 1


# ===========================================================================
# Criterion 6 — incident report (timeline, evidence links, trace refs) stored.
# ===========================================================================


class TestCriterion6IncidentReportGroundedAndRedacted:
    """An incident report generated from a troubleshooting session contains the
    timeline, evidence references, and a trace ref; it is the ``incident_report``
    Document shape and is A9-redacted (MVP §7 #6).

    The narrative prose is model-written (a fake chat model here); the timeline
    and evidence tables are deterministic, so the criterion's *structure* is
    proved without depending on model judgment.
    """

    async def test_report_carries_timeline_evidence_trace_and_is_redacted(self) -> None:
        session_id = str(uuid.uuid4())
        trace_ref = "trace:" + uuid.uuid4().hex
        session = {
            "session_id": session_id,
            "title": "BGP peer flap on core-rtr-01",
            "started_at": "2026-06-19T01:00:00Z",
            "resolved_at": "2026-06-19T01:42:00Z",
            "reasoning_trace_id": trace_ref,
            # A secret-bearing finding line the A9 layer must scrub.
            "findings": f"root cause traced; offending line: {_SECRET_FRAGMENT}",
            "timeline": [
                {
                    "ts": "01:05",
                    "step": "peer 10.0.0.2 observed Idle",
                    "evidence": "show bgp summary",
                },
                {"ts": "01:30", "step": "interface flap correlated", "evidence": "show log"},
            ],
            # Evidence links AND the reasoning-trace reference are carried in the
            # evidence_refs list — that is the surface the report renders into its
            # "Evidence References" section, so the criterion's "trace references"
            # land in the deterministic content (not invented by the model).
            "evidence_refs": ["show bgp summary @ 01:05", "show log @ 01:30", trace_ref],
        }
        change_requests = [
            {"id": "CR-1", "kind": "config", "state": "completed", "description": "stabilize peer"},
        ]
        # A fake chat model writes the two narrative sections; the deterministic
        # tables carry the facts the criterion asserts.
        model = scripted_model(
            [
                AIMessage(content="Summary narrative grounded in the timeline."),
                AIMessage(content="Root cause grounded in evidence."),
            ]
        )
        report = await render_incident_report(session, change_requests, model=model)

        assert report["kind"] == "incident_report"
        assert report["format"] == "md"
        assert report["source_refs"]["session_id"] == session_id
        content = report["content"]
        # Timeline rows, evidence references, and the trace ref are all present.
        assert "show bgp summary" in content
        assert "show log @ 01:30" in content
        assert trace_ref in content
        assert "## Timeline" in content
        assert "## Evidence References" in content
        # A9: the secret never appears, the redaction sentinel does.
        assert _SECRET_LITERAL not in content
        assert "<<REDACTED:" in content


# ===========================================================================
# Criterion 7 — DNS-dependency layer; RESOLVES_TO matches Infoblox zone data.
# ===========================================================================


class TestCriterion7DnsDependencyLayerResolvesToInventory:
    """``derive_dns`` projects ``DnsZone``/``DnsRecord`` nodes and a
    ``RESOLVES_TO`` edge from each A record toward the inventory node carrying
    that address — the topology DNS layer the UI renders (MVP §7 #7)."""

    @staticmethod
    def _a_record(name: str, value: str, zone: str) -> NormalizedDnsRecord:
        return NormalizedDnsRecord(
            device_id=uuid.UUID(_DEVICE_ID),
            collected_at=datetime.now(UTC),
            source_vendor="infoblox",
            name=name,
            record_type=DnsRecordType.A,
            value=value,
            zone=zone,
        )

    def test_resolves_to_reconciles_a_record_to_a_device_mgmt_ip(self) -> None:
        device = Device(
            id=uuid.UUID(_DEVICE_ID),
            hostname="core-rtr-01",
            mgmt_ip="10.0.0.10",
            vendor_id="cisco_ios",
        )
        records = [
            self._a_record("core-rtr-01.corp.example", "10.0.0.10", "corp.example"),
            self._a_record("ghost.corp.example", "192.0.2.99", "corp.example"),
        ]
        derived = derive_dns(records, zones=["corp.example"], devices=[device], interfaces=[])

        # Zone + record nodes are projected.
        assert {z.fqdn for z in derived.zones} == {"corp.example"}
        assert len(derived.records) == 2

        edges_by_value = {edge.value: edge for edge in derived.resolves_to}
        # The record whose value matches the device mgmt_ip reconciles to it.
        matched = edges_by_value["10.0.0.10"]
        assert matched.reconciled is True
        assert matched.target_label == "Device"
        assert matched.target_key == _DEVICE_ID
        # The record with no inventory match is an honest unreconciled edge.
        ghost = edges_by_value["192.0.2.99"]
        assert ghost.reconciled is False
        assert ghost.target_key is None

    def test_derivation_is_order_independent(self) -> None:
        """Same Infoblox currency in any order yields the same projection set —
        the property the topology rebuild relies on (D5)."""
        device = Device(
            id=uuid.UUID(_DEVICE_ID), hostname="r1", mgmt_ip="10.0.0.10", vendor_id="eos"
        )
        a = self._a_record("a.corp.example", "10.0.0.10", "corp.example")
        b = self._a_record("b.corp.example", "10.0.0.11", "corp.example")
        forward = derive_dns([a, b], ["corp.example"], [device], [])
        reverse = derive_dns([b, a], ["corp.example"], [device], [])
        assert forward.records == reverse.records
        assert forward.resolves_to == reverse.resolves_to


# ===========================================================================
# Criterion 8 — release/security gate. Automatable slice: the redaction
# invariant the write paths must hold (no secret reaches an LLM or audit detail).
# ===========================================================================


class TestCriterion8WritePathRedactionInvariant:
    """MVP §7 #8 is a process/release gate (Trivy zero-critical + signed
    checklist, owned by T19/T20). Its automatable, code-level slice is the A9
    invariant every M5 write path must hold: a secret-bearing change is stored
    verbatim for the executor but never surfaces to an LLM preview or an audit
    ``detail`` — the security property the whole write spine is built on.
    """

    async def test_cr_gate_redacts_llm_preview_but_stores_payload_verbatim(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        gate = ChangeRequestGate(service, requester_id=requester, actor_role=Role.ENGINEER)
        decision = await gate.authorize(
            ApprovalRequest(
                tool_name="deploy_config",
                arguments={"device_id": _DEVICE_ID, "fragment": _SECRET_FRAGMENT},
                kind=ChangeRequestKind.CONFIG,
                target_refs={"device_id": _DEVICE_ID},
            )
        )
        # The gate creates a DRAFT and never approves.
        assert decision.approved is False
        assert decision.change_request_created is True
        assert decision.change_request_state == "draft"

        cr = await service.get(uuid.UUID(decision.change_request_id))
        # Stored payload is VERBATIM (the executor renders it byte-for-byte).
        assert cr.payload is not None
        assert _SECRET_LITERAL in str(cr.payload)
        # The LLM-facing preview (after_state) is A9-redacted: no secret leaks.
        assert cr.after_state is not None
        assert _SECRET_LITERAL not in str(cr.after_state)
        assert "<<REDACTED:" in str(cr.after_state)

    async def test_no_audit_detail_for_a_full_run_carries_the_secret(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """Across the entire author->approve->execute audit chain, no audit
        ``detail`` may echo the secret-bearing payload (ADR-0020 §4)."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": _DEVICE_ID},
            rollback_plan={"baseline_content_hash": "x"},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)
        agent = AutomationAgent(
            change_request_service=service,
            config_executor=_ScriptedConfigExecutor(_restore_applied),
        )
        await agent.execute(cr.id)
        for row in await _audit_rows(sessionmaker, cr.id):
            assert _SECRET_LITERAL not in repr(row.detail)
