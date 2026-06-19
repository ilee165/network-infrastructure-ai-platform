"""Tests for the DDI Agent (M5 task #10, ADR-0022).

Mandatory behaviours (task T10):

1. Read-only troubleshooting tools (DNS + DHCP) return normalized DDI data:
   zone/record lookup, delegation/resolution-path, mismatch-vs-inventory for
   DNS; scope utilization, lease lookup, conflict detection for DHCP.
2. Mutating tools (record add/modify/delete) do NOT execute inline — each is
   STATE_CHANGING and routes through the framework gate, which CREATES a
   ``ChangeRequest`` draft (kind ``ddi_record``). The tool body never runs; the
   tool returns a :class:`ChangeRequestCreated`.
3. Secret boundary (A9) — any DNS/DHCP content surfaced to the LLM passes
   ``llm/redaction.py`` first, so a secret-bearing TXT value never reaches the
   model prompt.
4. Routing — the description disambiguates DDI from troubleshooting/discovery.
5. Registration — the package singleton registers cleanly.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.ddi import DdiAgent, ddi_agent, registry
from app.agents.ddi.agent import DdiAgent as _AgentImpl
from app.agents.ddi.tools import (
    DDI_TOOLS,
    add_dhcp_range,
    add_dns_record,
    check_dhcp_conflicts,
    delete_dns_record,
    dns_mismatch_vs_inventory,
    lookup_dhcp_lease,
    lookup_dns_records,
    modify_dns_record,
    resolve_dns_path,
    scope_utilization,
)
from app.agents.framework.approval import ChangeRequestGate
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import (
    AgentRunIdentity,
    ChangeRequestCreated,
    NetOpsTool,
    ToolClassification,
    agent_run_context,
    change_request_gate_context,
)
from app.core.security import Role
from app.llm.redaction import REDACTION_TOKENS
from app.models import (
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.schemas.normalized import (
    DhcpLeaseState,
    DnsRecordType,
    NormalizedDhcpLease,
    NormalizedDhcpRange,
    NormalizedDnsRecord,
    NormalizedNetwork,
)
from app.services.change_requests import ChangeRequestService
from tests.agents.conftest import scripted_model

DEVICE = "11111111-1111-1111-1111-111111111111"
_DEVICE_UUID = uuid.UUID(DEVICE)

# A secret-bearing DNS TXT value that the A9 redaction layer recognizes and must
# scrub before any DDI content reaches the model. A misconfigured TXT record that
# leaks a vendor-encoded credential is exactly the secret the redaction layer
# strips (here a Cisco type-9 hash blob embedded in the TXT value).
_SECRET_TXT = "config=$9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F"
_SECRET_LITERALS = ("$9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F",)


def _prov() -> dict[str, Any]:
    return {
        "device_id": _DEVICE_UUID,
        "collected_at": datetime.now(tz=UTC),
        "source_vendor": "infoblox",
    }


def _a_record(name: str, value: str, **kw: Any) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        **_prov(),
        name=name,
        record_type=DnsRecordType.A,
        value=value,
        zone=kw.get("zone", "corp.example.com"),
        ttl=kw.get("ttl", 3600),
        object_ref=kw.get("object_ref", "record:a/abc:1"),
    )


def _txt_record(name: str, value: str) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        **_prov(),
        name=name,
        record_type=DnsRecordType.TXT,
        value=value,
        zone="corp.example.com",
        object_ref="record:txt/xyz:1",
    )


def _lease(ip: str, state: DhcpLeaseState, **kw: Any) -> NormalizedDhcpLease:
    return NormalizedDhcpLease(
        **_prov(),
        ip_address=ip,
        state=state,
        mac_address=kw.get("mac"),
        hostname=kw.get("hostname"),
        network=kw.get("network", "10.0.0.0/24"),
        object_ref=kw.get("object_ref", "lease/abc:10.0.0.5"),
    )


def _range(start: str, end: str, **kw: Any) -> NormalizedDhcpRange:
    return NormalizedDhcpRange(
        **_prov(),
        start_address=start,
        end_address=end,
        network=kw.get("network", "10.0.0.0/24"),
        name=kw.get("name", "pool-1"),
        object_ref=kw.get("object_ref", "range/abc:1"),
    )


def _net(cidr: str, util: float | None) -> NormalizedNetwork:
    return NormalizedNetwork(
        **_prov(),
        network=cidr,
        comment="corp subnet",
        utilization_percent=util,
        object_ref="network/abc:1",
    )


def _records_payload(records: list[NormalizedDnsRecord]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in records]


def _leases_payload(leases: list[NormalizedDhcpLease]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in leases]


def _ranges_payload(ranges: list[NormalizedDhcpRange]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in ranges]


def _networks_payload(nets: list[NormalizedNetwork]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in nets]


def _make_agent(**kwargs: Any) -> DdiAgent:
    return DdiAgent(**kwargs)


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestDdiIdentity:
    def test_name_is_ddi(self) -> None:
        assert _make_agent().name == "ddi"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _make_agent().description.lower()
        assert desc.strip()
        assert "dns" in desc
        assert "dhcp" in desc

    def test_description_disambiguates_from_siblings(self) -> None:
        desc = _make_agent().description.lower()
        # DDI is not generic troubleshooting or discovery.
        assert "troubleshoot" in desc or "diagnos" in desc
        assert "discover" in desc

    def test_system_prompt_non_empty(self) -> None:
        assert _make_agent().system_prompt.strip()

    def test_validate_definition_passes(self) -> None:
        _make_agent().validate_definition()


# ---------------------------------------------------------------------------
# Tool classification — read-only readers + state-changing mutators
# ---------------------------------------------------------------------------


class TestDdiToolClassification:
    _READ_ONLY = {
        "lookup_dns_records",
        "resolve_dns_path",
        "dns_mismatch_vs_inventory",
        "scope_utilization",
        "lookup_dhcp_lease",
        "check_dhcp_conflicts",
    }
    _STATE_CHANGING = {
        "add_dns_record",
        "modify_dns_record",
        "delete_dns_record",
        "add_dhcp_range",
        "delete_dhcp_range",
    }

    def test_read_only_tools_classified_read_only(self) -> None:
        by_name = {t.name: t for t in _make_agent().tools}
        for name in self._READ_ONLY:
            assert name in by_name, f"missing read-only tool {name}"
            assert by_name[name].classification is ToolClassification.READ_ONLY

    def test_mutating_tools_classified_state_changing(self) -> None:
        by_name = {t.name: t for t in _make_agent().tools}
        for name in self._STATE_CHANGING:
            assert name in by_name, f"missing mutating tool {name}"
            assert by_name[name].classification is ToolClassification.STATE_CHANGING

    def test_mutating_tools_declare_ddi_record_kind(self) -> None:
        by_name = {t.name: t for t in _make_agent().tools}
        for name in self._STATE_CHANGING:
            assert by_name[name].change_request_kind is ChangeRequestKind.DDI_RECORD

    def test_mutating_tools_require_engineer(self) -> None:
        by_name = {t.name: t for t in _make_agent().tools}
        for name in self._STATE_CHANGING:
            assert by_name[name].min_role is Role.ENGINEER

    def test_no_diagnostic_tool_declared(self) -> None:
        offenders = [
            t.name for t in _make_agent().tools if t.classification is ToolClassification.DIAGNOSTIC
        ]
        assert not offenders, f"DIAGNOSTIC tools found: {offenders}"

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _make_agent().tools:
            assert isinstance(tool, NetOpsTool)


# ---------------------------------------------------------------------------
# Read-only DNS tools return normalized DDI data
# ---------------------------------------------------------------------------


class TestDnsReadTools:
    async def test_lookup_dns_records_returns_normalized(self) -> None:
        records = _records_payload(
            [
                _a_record("host1.corp.example.com", "10.0.0.10"),
                _a_record("host2.corp.example.com", "10.0.0.11"),
            ]
        )
        raw = await lookup_dns_records.ainvoke(
            {"device_id": DEVICE, "name": "host1.corp.example.com", "records": records}
        )
        payload = json.loads(raw)
        assert payload["device_id"] == DEVICE
        names = {r["name"] for r in payload["records"]}
        assert names == {"host1.corp.example.com"}
        assert payload["records"][0]["value"] == "10.0.0.10"
        assert payload["records"][0]["record_type"] == "a"

    async def test_lookup_dns_records_filters_by_zone(self) -> None:
        records = _records_payload(
            [
                _a_record("a.corp.example.com", "10.0.0.10", zone="corp.example.com"),
                _a_record("b.lab.example.com", "10.0.1.10", zone="lab.example.com"),
            ]
        )
        raw = await lookup_dns_records.ainvoke(
            {"device_id": DEVICE, "zone": "lab.example.com", "records": records}
        )
        payload = json.loads(raw)
        zones = {r["zone"] for r in payload["records"]}
        assert zones == {"lab.example.com"}

    async def test_resolve_dns_path_follows_cname_chain(self) -> None:
        cname = NormalizedDnsRecord(
            **_prov(),
            name="www.corp.example.com",
            record_type=DnsRecordType.CNAME,
            value="host1.corp.example.com",
            zone="corp.example.com",
            object_ref="record:cname/c:1",
        )
        a = _a_record("host1.corp.example.com", "10.0.0.10")
        records = _records_payload([cname, a])
        raw = await resolve_dns_path.ainvoke(
            {"device_id": DEVICE, "name": "www.corp.example.com", "records": records}
        )
        payload = json.loads(raw)
        # The resolution path follows the CNAME to the terminal A record.
        assert payload["resolved"] is True
        assert payload["answer"] == "10.0.0.10"
        hops = [h["value"] for h in payload["path"]]
        assert "host1.corp.example.com" in hops
        assert "10.0.0.10" in hops

    async def test_resolve_dns_path_unresolved_when_no_record(self) -> None:
        raw = await resolve_dns_path.ainvoke(
            {"device_id": DEVICE, "name": "missing.corp.example.com", "records": []}
        )
        payload = json.loads(raw)
        assert payload["resolved"] is False
        assert payload["answer"] is None

    async def test_dns_mismatch_vs_inventory_flags_divergence(self) -> None:
        records = _records_payload([_a_record("host1.corp.example.com", "10.0.0.10")])
        # Inventory believes host1 lives at a different address — a mismatch.
        inventory = [{"name": "host1.corp.example.com", "ip_address": "10.0.0.99"}]
        raw = await dns_mismatch_vs_inventory.ainvoke(
            {"device_id": DEVICE, "records": records, "inventory": inventory}
        )
        payload = json.loads(raw)
        assert payload["has_mismatch"] is True
        mismatched = {m["name"] for m in payload["mismatches"]}
        assert "host1.corp.example.com" in mismatched

    async def test_dns_mismatch_vs_inventory_clean_when_aligned(self) -> None:
        records = _records_payload([_a_record("host1.corp.example.com", "10.0.0.10")])
        inventory = [{"name": "host1.corp.example.com", "ip_address": "10.0.0.10"}]
        raw = await dns_mismatch_vs_inventory.ainvoke(
            {"device_id": DEVICE, "records": records, "inventory": inventory}
        )
        payload = json.loads(raw)
        assert payload["has_mismatch"] is False
        assert payload["mismatches"] == []

    async def test_dns_content_is_redacted(self) -> None:
        records = _records_payload([_txt_record("_dkim.corp.example.com", _SECRET_TXT)])
        raw = await lookup_dns_records.ainvoke(
            {"device_id": DEVICE, "name": "_dkim.corp.example.com", "records": records}
        )
        for literal in _SECRET_LITERALS:
            assert literal not in raw, f"secret {literal!r} leaked into DNS tool output"
        # The redaction token is present, so the model still sees a secret existed.
        assert REDACTION_TOKENS["cisco_type89"] in raw


# ---------------------------------------------------------------------------
# Read-only DHCP tools return normalized DDI data
# ---------------------------------------------------------------------------


class TestDhcpReadTools:
    async def test_scope_utilization_computes_from_leases(self) -> None:
        leases = _leases_payload(
            [
                _lease("10.0.0.5", DhcpLeaseState.ACTIVE),
                _lease("10.0.0.6", DhcpLeaseState.ACTIVE),
                _lease("10.0.0.7", DhcpLeaseState.FREE),
            ]
        )
        # Pool of 10 addresses, 2 active -> 20% utilization.
        ranges = _ranges_payload([_range("10.0.0.5", "10.0.0.14")])
        raw = await scope_utilization.ainvoke(
            {"device_id": DEVICE, "ranges": ranges, "leases": leases}
        )
        payload = json.loads(raw)
        scope = payload["scopes"][0]
        assert scope["active_leases"] == 2
        assert scope["pool_size"] == 10
        assert scope["utilization_percent"] == pytest.approx(20.0)

    async def test_scope_utilization_uses_network_utilization_when_supplied(self) -> None:
        ranges = _ranges_payload([_range("10.0.0.5", "10.0.0.14")])
        networks = _networks_payload([_net("10.0.0.0/24", 73.5)])
        raw = await scope_utilization.ainvoke(
            {"device_id": DEVICE, "ranges": ranges, "leases": [], "networks": networks}
        )
        payload = json.loads(raw)
        assert payload["networks"][0]["utilization_percent"] == pytest.approx(73.5)

    async def test_lookup_dhcp_lease_by_ip(self) -> None:
        leases = _leases_payload(
            [
                _lease("10.0.0.5", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:ff", hostname="pc-1"),
                _lease("10.0.0.6", DhcpLeaseState.ACTIVE),
            ]
        )
        raw = await lookup_dhcp_lease.ainvoke(
            {"device_id": DEVICE, "ip_address": "10.0.0.5", "leases": leases}
        )
        payload = json.loads(raw)
        assert len(payload["leases"]) == 1
        assert payload["leases"][0]["ip_address"] == "10.0.0.5"
        assert payload["leases"][0]["hostname"] == "pc-1"

    async def test_lookup_dhcp_lease_by_mac(self) -> None:
        leases = _leases_payload(
            [_lease("10.0.0.5", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:ff")]
        )
        raw = await lookup_dhcp_lease.ainvoke(
            {"device_id": DEVICE, "mac_address": "aa:bb:cc:dd:ee:ff", "leases": leases}
        )
        payload = json.loads(raw)
        assert payload["leases"][0]["ip_address"] == "10.0.0.5"

    async def test_check_dhcp_conflicts_detects_duplicate_ip(self) -> None:
        leases = _leases_payload(
            [
                _lease("10.0.0.5", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:01"),
                _lease("10.0.0.5", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:02"),
            ]
        )
        raw = await check_dhcp_conflicts.ainvoke({"device_id": DEVICE, "leases": leases})
        payload = json.loads(raw)
        assert payload["has_conflict"] is True
        conflict_ips = {c["ip_address"] for c in payload["conflicts"]}
        assert "10.0.0.5" in conflict_ips

    async def test_check_dhcp_conflicts_clean_when_unique(self) -> None:
        leases = _leases_payload(
            [
                _lease("10.0.0.5", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:01"),
                _lease("10.0.0.6", DhcpLeaseState.ACTIVE, mac="aa:bb:cc:dd:ee:02"),
            ]
        )
        raw = await check_dhcp_conflicts.ainvoke({"device_id": DEVICE, "leases": leases})
        payload = json.loads(raw)
        assert payload["has_conflict"] is False
        assert payload["conflicts"] == []


# ---------------------------------------------------------------------------
# Mutating tools create a ChangeRequest and never execute inline
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full schema + FK enforcement."""
    eng = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(eng.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def service(sessionmaker: async_sessionmaker[AsyncSession]) -> ChangeRequestService:
    return ChangeRequestService(sessionmaker)


async def _seed_engineer(maker: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    async with maker() as session:
        role = RoleRow(name=f"engineer-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(
            username=f"user-{uuid.uuid4().hex[:8]}",
            password_hash="x",
            role_id=role.id,
        )
        session.add(user)
        await session.commit()
        return user.id


async def _all_crs(maker: async_sessionmaker[AsyncSession]) -> list[ChangeRequest]:
    async with maker() as session:
        return list((await session.execute(select(ChangeRequest))).scalars().all())


def _gate_factory(service: ChangeRequestService):
    def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
        assert identity.user_id is not None
        return ChangeRequestGate(
            service,
            requester_id=identity.user_id,
            actor_role=identity.role,
            generating_session_id=identity.session_id,
            reasoning_trace_id=identity.reasoning_trace_id,
        )

    return factory


class TestMutatingToolsCreateChangeRequest:
    async def test_add_dns_record_creates_ddi_cr_and_does_not_execute(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        engineer_id = await _seed_engineer(sessionmaker)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(_gate_factory(service)),
        ):
            result = await add_dns_record.ainvoke(
                {
                    "device_id": DEVICE,
                    "name": "new.corp.example.com",
                    "record_type": "a",
                    "value": "10.0.0.50",
                    "zone": "corp.example.com",
                }
            )
        assert isinstance(result, ChangeRequestCreated)
        assert result.change_request_state == ChangeRequestState.DRAFT.value
        assert uuid.UUID(result.change_request_id)

        crs = await _all_crs(sessionmaker)
        assert len(crs) == 1
        cr = crs[0]
        assert cr.state is ChangeRequestState.DRAFT
        assert cr.kind is ChangeRequestKind.DDI_RECORD
        assert cr.requester_id == engineer_id
        # The verbatim payload carries the proposed record fields.
        assert cr.payload["name"] == "new.corp.example.com"
        assert cr.payload["value"] == "10.0.0.50"
        # target_refs is id-only (the device + record name) — never secret-bearing.
        assert cr.target_refs is not None
        assert cr.target_refs.get("device_id") == DEVICE

    async def test_modify_dns_record_creates_ddi_cr(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        engineer_id = await _seed_engineer(sessionmaker)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(_gate_factory(service)),
        ):
            result = await modify_dns_record.ainvoke(
                {
                    "device_id": DEVICE,
                    "object_ref": "record:a/abc:1",
                    "record_type": "a",
                    "name": "host1.corp.example.com",
                    "value": "10.0.0.77",
                }
            )
        assert isinstance(result, ChangeRequestCreated)
        crs = await _all_crs(sessionmaker)
        assert len(crs) == 1
        assert crs[0].kind is ChangeRequestKind.DDI_RECORD
        assert crs[0].payload["object_ref"] == "record:a/abc:1"

    async def test_delete_dns_record_creates_ddi_cr(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        engineer_id = await _seed_engineer(sessionmaker)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(_gate_factory(service)),
        ):
            result = await delete_dns_record.ainvoke(
                {
                    "device_id": DEVICE,
                    "object_ref": "record:a/abc:1",
                    "name": "host1.corp.example.com",
                }
            )
        assert isinstance(result, ChangeRequestCreated)
        crs = await _all_crs(sessionmaker)
        assert len(crs) == 1
        assert crs[0].kind is ChangeRequestKind.DDI_RECORD

    async def test_add_dhcp_range_creates_ddi_cr(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        engineer_id = await _seed_engineer(sessionmaker)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(_gate_factory(service)),
        ):
            result = await add_dhcp_range.ainvoke(
                {
                    "device_id": DEVICE,
                    "start_address": "10.0.0.100",
                    "end_address": "10.0.0.150",
                    "network": "10.0.0.0/24",
                }
            )
        assert isinstance(result, ChangeRequestCreated)
        crs = await _all_crs(sessionmaker)
        assert len(crs) == 1
        assert crs[0].kind is ChangeRequestKind.DDI_RECORD
        assert crs[0].payload["start_address"] == "10.0.0.100"

    async def test_mutating_tool_below_engineer_creates_no_cr(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """RBAC: an operator-bound run cannot even reach the gate (min_role)."""
        from app.agents.framework.tools import RbacForbiddenError

        operator_id = await _seed_engineer(sessionmaker)  # any user; role bound below
        with (
            agent_run_context(role=Role.OPERATOR, user_id=operator_id),
            change_request_gate_context(_gate_factory(service)),
            pytest.raises(RbacForbiddenError),
        ):
            await add_dns_record.ainvoke(
                {
                    "device_id": DEVICE,
                    "name": "new.corp.example.com",
                    "record_type": "a",
                    "value": "10.0.0.50",
                }
            )
        assert await _all_crs(sessionmaker) == []


# ---------------------------------------------------------------------------
# Bespoke graph wiring — the agent compiles and routes through the gate
# ---------------------------------------------------------------------------


class _RecordingModel:
    """Scripted chat model that retains every message it is asked to generate over."""

    def __init__(self, replies: list[AIMessage]) -> None:
        self._inner = scripted_model(replies)
        self.seen: list[BaseMessage] = []

    def __getattr__(self, item: str):  # pragma: no cover - delegation glue
        return getattr(self._inner, item)

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self

    async def ainvoke(self, messages: Any, *a: Any, **k: Any) -> Any:
        self.seen.extend(messages)
        return await self._inner.ainvoke(messages, *a, **k)


class TestDdiGraph:
    async def test_graph_name_matches_agent(self) -> None:
        agent = _make_agent()
        graph = agent.build_graph(scripted_model([AIMessage(content="ok")]))
        assert graph.name == "ddi"

    async def test_graph_runs_a_read_only_turn(self) -> None:
        agent = _make_agent()
        model = _RecordingModel([AIMessage(content="I looked up the records.")])
        result = await agent.build_graph(model).ainvoke(
            {"messages": [HumanMessage(content=f"look up DNS for host1 on {DEVICE}")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        assert "records" in str(final.content).lower()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestDdiRegistration:
    def test_package_singleton_type(self) -> None:
        assert isinstance(ddi_agent, _AgentImpl)

    def test_package_registry_contains_agent(self) -> None:
        assert "ddi" in registry

    def test_register_fresh_instance(self) -> None:
        fresh = AgentRegistry()
        fresh.register(_make_agent())
        assert "ddi" in fresh

    def test_double_register_conflicts(self) -> None:
        from app.core.errors import ConflictError

        fresh = AgentRegistry()
        fresh.register(_make_agent())
        with pytest.raises(ConflictError):
            fresh.register(_make_agent())

    def test_tool_list_exported(self) -> None:
        names = {t.name for t in DDI_TOOLS}
        assert "lookup_dns_records" in names
        assert "add_dns_record" in names
        assert "scope_utilization" in names
