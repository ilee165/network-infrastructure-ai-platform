"""Relational write boundary for directly invoked READ_ONLY agent tools."""

from __future__ import annotations

import ast
import re
from collections.abc import AsyncIterator, Iterator
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from langchain_core.messages import AIMessage
from sqlalchemy import Delete, Insert, Table, Update, event, func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.sql.elements import TextClause

import app.db as db
from app.agents import build_default_registry
from app.agents.framework import read_facade
from app.agents.framework.credential_access import acquire_troubleshooting_ssh
from app.agents.framework.discovery_jobs import create_discovery_run, mark_discovery_run_failed
from app.agents.framework.tools import ToolClassification, agent_run_context, netops_tool
from app.core.crypto import FakeKmsKeyProvider, KeyProviderUnavailable, envelope_encrypt
from app.models import (
    AuditLog,
    CredentialKind,
    Device,
    DeviceCredential,
    DiscoveryRun,
    DiscoveryRunStatus,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    ReportArtifact,
    ReportRun,
)
from app.schemas.normalized import NeighborProtocol, RouteProtocol
from app.services import audit
from tests.agents.conftest import scripted_model

_ROOT = Path(__file__).parents[3]
_UNKNOWN_DEVICE_ID = "11111111-1111-1111-1111-111111111111"

# READ_ONLY direct invocation may create operational discovery jobs and append
# credential/tool audit evidence. Neither mutates relational domain state.
_ALLOWED_WRITES: dict[str, frozenset[str]] = {
    # Operational job row; READ_ONLY job-launch semantic (create + failure update).
    "discovery_runs": frozenset({"insert", "update"}),
    # Append-only credential-access/tool audit; fail-closed evidence.
    "audit_log": frozenset({"insert"}),
}

_TEXTUAL_DML = re.compile(
    r"\b(?P<operation>insert\s+into|update|delete\s+from)\s+"
    r"(?P<table>(?:[A-Za-z_][\w$]*\.)?"
    r'(?:[A-Za-z_][\w$]*|"[^"]+"|`[^`]+`|\[[^\]]+\]))',
    re.IGNORECASE,
)
_DML_KEYWORD = re.compile(r"\b(?:insert|update|delete)\b", re.IGNORECASE)


def _sql_code_only(statement: str) -> str:
    """Blank comments and string literals while retaining executable SQL."""
    output: list[str] = []
    index = 0
    length = len(statement)
    while index < length:
        if statement.startswith("--", index):
            end = statement.find("\n", index + 2)
            index = length if end == -1 else end
            output.append(" ")
            continue
        if statement.startswith("/*", index):
            end = statement.find("*/", index + 2)
            index = length if end == -1 else end + 2
            output.append(" ")
            continue
        if statement[index] == "'":
            index += 1
            while index < length:
                if statement[index] != "'":
                    index += 1
                    continue
                if index + 1 < length and statement[index + 1] == "'":
                    index += 2
                    continue
                index += 1
                break
            output.append(" ")
            continue
        if statement[index] == "$":
            delimiter = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", statement[index:])
            if delimiter is not None:
                marker = delimiter.group(0)
                end = statement.find(marker, index + len(marker))
                index = length if end == -1 else end + len(marker)
                output.append(" ")
                continue
        output.append(statement[index])
        index += 1
    return "".join(output)


def _textual_dml_targets(statement: str) -> list[tuple[str, str]]:
    """Return every textual ``(operation, table)`` pair, failing closed."""
    sql = _sql_code_only(statement)
    matches = list(_TEXTUAL_DML.finditer(sql))
    keyword_starts = [match.start() for match in _DML_KEYWORD.finditer(sql)]
    if keyword_starts != [match.start() for match in matches]:
        raise ReadOnlyWriteViolation(
            "READ_ONLY direct invocation attempted unparseable textual DML"
        )
    targets: list[tuple[str, str]] = []
    for match in matches:
        operation = match.group("operation").split()[0].lower()
        identifier = match.group("table").rsplit(".", 1)[-1]
        targets.append((operation, identifier.strip('"`[]')))
    return targets


def _write_is_allowed(operation: str, table_name: str) -> bool:
    return operation in _ALLOWED_WRITES.get(table_name, frozenset())


class ReadOnlyWriteViolation(AssertionError):
    """A READ_ONLY direct invocation attempted a forbidden relational write."""


@pytest.fixture()
def key_provider() -> FakeKmsKeyProvider:
    """In-memory stand-in for the only external KMS boundary."""
    return FakeKmsKeyProvider()


@pytest.fixture()
async def engine(key_provider: FakeKmsKeyProvider) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        tables = cast(
            list[Table],
            [
                DeviceCredential.__table__,
                Device.__table__,
                DiscoveryRun.__table__,
                NormalizedNeighborRow.__table__,
                NormalizedRouteRow.__table__,
                AuditLog.__table__,
                # P4 W3-T1 report surface (ADR-0053 §1): the documentation
                # report tools issue SELECTs over these two tables.
                ReportRun.__table__,
                ReportArtifact.__table__,
            ],
        )
        await conn.run_sync(lambda sync_conn: Device.metadata.create_all(sync_conn, tables=tables))
    seed_maker = async_sessionmaker(engine, expire_on_commit=False)
    credential_id = uuid4()
    envelope = envelope_encrypt(
        uuid4().hex.encode("ascii"), str(credential_id).encode("ascii"), key_provider
    )
    async with seed_maker() as session:
        session.add(
            DeviceCredential(
                id=credential_id,
                name="read-boundary-ssh",
                kind=CredentialKind.SSH,
                username="fixture",
                ciphertext=envelope.ciphertext,
                nonce=envelope.nonce,
                wrapped_dek=envelope.wrapped_dek,
                dek_nonce=envelope.dek_nonce,
                kek_version=envelope.kek_version,
                params={},
            )
        )
        session.add(
            Device(
                id=UUID(_UNKNOWN_DEVICE_ID),
                hostname="read-boundary-device",
                mgmt_ip="192.0.2.1",
                vendor_id="cisco_ios",
                credential_id=credential_id,
            )
        )
        await session.commit()
    yield engine
    await engine.dispose()


@pytest.fixture()
def maker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_read_facade_returns_frozen_plain_snapshots(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ORM state never escapes the facade's active database session."""
    device_id = UUID(_UNKNOWN_DEVICE_ID)
    collected_at = datetime.now(UTC)
    async with maker() as session:
        session.add(
            NormalizedNeighborRow(
                device_id=device_id,
                raw_artifact_id=uuid4(),
                collected_at=collected_at,
                source_vendor="cisco_ios",
                protocol=NeighborProtocol.LLDP,
                local_interface="GigabitEthernet1",
                neighbor_name="edge-2",
                neighbor_interface="GigabitEthernet2",
                neighbor_capabilities=["router"],
            )
        )
        session.add(
            NormalizedRouteRow(
                device_id=device_id,
                raw_artifact_id=uuid4(),
                collected_at=collected_at,
                source_vendor="cisco_ios",
                prefix="203.0.113.0/24",
                protocol=RouteProtocol.BGP,
                next_hop="192.0.2.2",
                interface="GigabitEthernet1",
                vrf="",
                distance=20,
                metric=0,
            )
        )
        await session.commit()

    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    total, devices = await read_facade.list_devices(
        status_filter=None,
        vendor_id=None,
        limit=50,
        offset=0,
    )
    device = await read_facade.get_device(device_id)
    neighbor_device, neighbors = await read_facade.list_neighbors(device_id)
    routes = await read_facade.list_routes(device_id, prefix=None)

    assert total == 1
    snapshots = [*devices, device, neighbor_device, *neighbors, *routes]
    for snapshot in snapshots:
        assert snapshot is not None
        assert is_dataclass(snapshot)
        assert not hasattr(snapshot, "_sa_instance_state")
        with pytest.raises(FrozenInstanceError):
            snapshot.id = uuid4()


@pytest.mark.asyncio
async def test_read_facade_raises_typed_invalid_status(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid filters use a typed error channel, not a union return shape."""
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)

    with pytest.raises(ValueError) as error:
        await read_facade.list_devices(
            status_filter="not-a-device-status",
            vendor_id=None,
            limit=50,
            offset=0,
        )

    assert error.value.args == (
        "unknown status 'not-a-device-status'; valid values: ['new', 'reachable', 'unreachable']",
    )


@pytest.fixture()
def guarded_engine(engine: AsyncEngine) -> Iterator[AsyncEngine]:
    """Deny every relational mutation outside the two justified tables."""

    def reject_forbidden_write(
        _conn: Any,
        clauseelement: Any,
        _multiparams: Any,
        _params: Any,
        _execution_options: Any,
    ) -> None:
        table_name: str | None = None
        operation: str | None = None
        if isinstance(clauseelement, Insert):
            operation = "insert"
            table_name = cast(Table, clauseelement.table).name
        elif isinstance(clauseelement, Update):
            operation = "update"
            table_name = cast(Table, clauseelement.table).name
        elif isinstance(clauseelement, Delete):
            operation = "delete"
            table_name = cast(Table, clauseelement.table).name
        elif isinstance(clauseelement, TextClause):
            targets = _textual_dml_targets(clauseelement.text)
            for textual_operation, textual_table_name in targets:
                if not _write_is_allowed(textual_operation, textual_table_name):
                    allowed_operations = _ALLOWED_WRITES.get(textual_table_name, frozenset())
                    raise ReadOnlyWriteViolation(
                        "READ_ONLY direct invocation attempted "
                        f"{textual_operation.upper()} on {textual_table_name!r}; "
                        f"allowed operations: {allowed_operations}"
                    )
            return
        else:
            return
        assert operation is not None
        if not _write_is_allowed(operation, table_name):
            raise ReadOnlyWriteViolation(
                f"READ_ONLY direct invocation attempted {operation.upper()} on {table_name!r}; "
                f"allowed operations: {_ALLOWED_WRITES.get(table_name, frozenset())}"
            )

    event.listen(engine.sync_engine, "before_execute", reject_forbidden_write)
    try:
        yield engine
    finally:
        event.remove(engine.sync_engine, "before_execute", reject_forbidden_write)


@pytest.mark.asyncio
async def test_guard_bites_on_synthetic_read_only_device_insert(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A permanent synthetic READ_ONLY domain write proves the guard fires."""

    @netops_tool(classification=ToolClassification.READ_ONLY)
    async def synthetic_device_write() -> str:
        """Attempt a forbidden inventory mutation from a READ_ONLY tool."""
        async with maker() as session:
            session.add(Device(hostname="forbidden", mgmt_ip="192.0.2.250"))
            await session.commit()
        return "unreachable"

    with pytest.raises(ReadOnlyWriteViolation, match="devices"):
        await synthetic_device_write.ainvoke({})


@pytest.mark.asyncio
async def test_guard_bites_on_textual_device_update(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Textual domain DML cannot bypass the READ_ONLY write boundary."""
    async with maker() as session:
        with pytest.raises(ReadOnlyWriteViolation, match="devices"):
            await session.execute(text("UPDATE devices SET hostname = 'forbidden'"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET action = 'tampered' WHERE id IS NULL",
        "DELETE FROM audit_log WHERE id IS NULL",
    ],
)
async def test_guard_bites_on_non_append_audit_write_from_read_only_tool(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    statement: str,
) -> None:
    """READ_ONLY tools may append audit evidence, never alter or erase it."""

    @netops_tool(classification=ToolClassification.READ_ONLY)
    async def synthetic_audit_tamper() -> str:
        """Attempt to alter append-only audit evidence."""
        async with maker() as session:
            await session.execute(text(statement))
        return "unreachable"

    with pytest.raises(ReadOnlyWriteViolation, match="audit_log"):
        await synthetic_audit_tamper.ainvoke({})


@pytest.mark.asyncio
async def test_guard_allows_textual_select(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Textual reads remain valid under the write boundary."""
    async with maker() as session:
        assert await session.scalar(text("SELECT 1")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "statement",
    [
        "/* maintenance */ UPDATE devices SET hostname = 'forbidden'",
        "-- maintenance\nDELETE FROM devices",
        (
            "WITH changed AS ("
            "UPDATE devices SET hostname = 'forbidden' RETURNING id"
            ") SELECT id FROM changed"
        ),
    ],
)
async def test_guard_bites_on_hidden_textual_device_dml(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    statement: str,
) -> None:
    """Comments and data-modifying CTEs cannot conceal textual DML."""
    async with maker() as session:
        with pytest.raises(ReadOnlyWriteViolation, match="devices"):
            await session.execute(text(statement))


@pytest.mark.asyncio
async def test_guard_allows_textual_select_cte(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A read-only CTE remains valid under conservative textual scanning."""
    async with maker() as session:
        assert await session.scalar(text("WITH value AS (SELECT 1 AS n) SELECT n FROM value")) == 1


@pytest.mark.asyncio
async def test_guard_checks_every_data_modifying_cte_target(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """An allowed first CTE mutation cannot conceal a forbidden later one."""
    statement = """
        WITH removed AS (
            INSERT INTO audit_log (id) VALUES (NULL) RETURNING id
        ), changed AS (
            UPDATE devices SET hostname = 'forbidden' RETURNING id
        )
        SELECT id FROM removed
    """
    async with maker() as session:
        with pytest.raises(ReadOnlyWriteViolation, match="devices"):
            await session.execute(text(statement))


def test_textual_parser_returns_every_operation_and_target() -> None:
    """Every mutation in a multi-DML statement is returned for validation."""
    statement = """
        WITH removed AS (
            DELETE FROM audit_log WHERE id IS NULL RETURNING id
        ), appended AS (
            INSERT INTO audit_log (id) SELECT id FROM removed RETURNING id
        )
        SELECT id FROM appended
    """
    assert _textual_dml_targets(statement) == [
        ("delete", "audit_log"),
        ("insert", "audit_log"),
    ]


def test_textual_parser_ignores_dml_words_in_comments_and_strings() -> None:
    """Non-executable DML-looking text does not turn a SELECT into a write."""
    statement = """
        /* DELETE FROM devices */
        WITH value AS (SELECT 'UPDATE devices' AS message)
        SELECT message FROM value -- INSERT INTO devices
    """
    assert _textual_dml_targets(statement) == []


@pytest.mark.asyncio
async def test_real_credential_access_chain_catches_planted_domain_write(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A domain mutation planted below the real credential seam is denied."""
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    from app.services import credentials

    async def mutating_decrypt(session: AsyncSession, *_args: Any, **_kwargs: Any) -> Any:
        await session.execute(
            text("UPDATE devices SET hostname = 'forbidden' WHERE id = :device_id"),
            {"device_id": _UNKNOWN_DEVICE_ID},
        )
        raise AssertionError("unreachable")

    monkeypatch.setattr(credentials, "decrypt", mutating_decrypt)
    async with maker() as session:
        device = await session.get(Device, UUID(_UNKNOWN_DEVICE_ID))
        assert device is not None and device.credential_id is not None
        credential_id = device.credential_id

    with pytest.raises(ReadOnlyWriteViolation, match="devices"):
        await acquire_troubleshooting_ssh(
            UUID(_UNKNOWN_DEVICE_ID),
            object(),
            expected_host="192.0.2.1",
            expected_vendor_id="cisco_ios",
            expected_credential_id=credential_id,
            actor="agent:troubleshooting",
            reason="troubleshooting_live_read",
        )


@pytest.mark.asyncio
async def test_real_credential_access_chain_fails_closed_with_durable_audit_only(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider refusal persists only its autonomous fail-closed audit row."""
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    async with maker() as session:
        device = await session.get(Device, UUID(_UNKNOWN_DEVICE_ID))
        assert device is not None and device.credential_id is not None
        credential_id = device.credential_id

    with pytest.raises(KeyProviderUnavailable):
        await acquire_troubleshooting_ssh(
            UUID(_UNKNOWN_DEVICE_ID),
            FakeKmsKeyProvider(available=False),
            expected_host="192.0.2.1",
            expected_vendor_id="cisco_ios",
            expected_credential_id=credential_id,
            actor="agent:troubleshooting",
            reason="troubleshooting_live_read",
        )

    async with maker() as session:
        rows = list((await session.scalars(select(AuditLog))).all())
        assert len(rows) == 1
        assert rows[0].action == audit.KEK_PROVIDER_UNAVAILABLE
        assert rows[0].target_id == str(credential_id)
        assert rows[0].detail == {"reason_class": "ConnectionError"}
        assert await session.scalar(select(func.count()).select_from(Device)) == 1
        assert await session.scalar(select(func.count()).select_from(DeviceCredential)) == 1
        assert await session.scalar(select(func.count()).select_from(DiscoveryRun)) == 0
        assert await session.scalar(select(func.count()).select_from(NormalizedNeighborRow)) == 0
        assert await session.scalar(select(func.count()).select_from(NormalizedRouteRow)) == 0


def _invocation_fixtures() -> dict[str, dict[str, Any]]:
    """Valid minimal direct-call arguments for the complete default census."""
    empty_findings = {
        "packet_count": 0,
        "top_talkers": [],
        "protocol_hierarchy": [],
        "tcp_resets": 0,
        "tcp_retransmissions": 0,
    }
    return {
        "summarize_change_request": {
            "change_request_id": "cr-test",
            "kind": "config",
            "summary": "test",
        },
        "explain_drift_diff": {"device_id": _UNKNOWN_DEVICE_ID, "has_drift": False},
        "assess_device_vs_policy": {
            "device_id": _UNKNOWN_DEVICE_ID,
            "policy_id": "baseline",
            "findings": [],
        },
        "summarize_compliance_posture": {
            "device_id": _UNKNOWN_DEVICE_ID,
            "findings": [],
        },
        "lookup_dns_records": {"device_id": _UNKNOWN_DEVICE_ID, "records": []},
        "resolve_dns_path": {
            "device_id": _UNKNOWN_DEVICE_ID,
            "name": "missing.example",
            "records": [],
        },
        "dns_mismatch_vs_inventory": {
            "device_id": _UNKNOWN_DEVICE_ID,
            "records": [],
            "inventory": [],
        },
        "scope_utilization": {
            "device_id": _UNKNOWN_DEVICE_ID,
            "ranges": [],
        },
        "lookup_dhcp_lease": {"device_id": _UNKNOWN_DEVICE_ID, "leases": []},
        "check_dhcp_conflicts": {"device_id": _UNKNOWN_DEVICE_ID, "leases": []},
        "trigger_discovery_run": {
            "seeds": ["192.0.2.1"],
            "hop_limit": 0,
            "allowlist": ["192.0.2.0/24"],
        },
        "list_devices": {},
        "get_device": {"device_id": _UNKNOWN_DEVICE_ID},
        "query_neighbors": {"device_id": _UNKNOWN_DEVICE_ID},
        "generate_inventory": {
            "devices": [],
            "interfaces": [],
            "neighbors": [],
            "routes": [],
        },
        "generate_diagram": {"projection": {"nodes": [], "edges": []}},
        "generate_runbook": {
            "device": {"id": _UNKNOWN_DEVICE_ID, "hostname": "test"},
            "interfaces": [],
            "neighbors": [],
            "routes": [],
        },
        "generate_incident_report": {"session": {"id": "session-test", "status": "completed"}},
        "summarize_capture": {"findings": empty_findings},
        "query_capture": {"findings": empty_findings},
        "analyze_firewall_policy": {"device_id": _UNKNOWN_DEVICE_ID, "rules": []},
        "assess_security_posture": {"device_id": _UNKNOWN_DEVICE_ID},
        "get_device_routes": {"device_id": _UNKNOWN_DEVICE_ID},
        "read_live_bgp_peers": {"device_id": _UNKNOWN_DEVICE_ID},
        "read_live_ospf_neighbors": {"device_id": _UNKNOWN_DEVICE_ID},
        "read_live_acls": {"device_id": _UNKNOWN_DEVICE_ID},
        "get_application_impact": {"target": "device:missing"},
        # P4 W3-T1 documentation report tools (ADR-0053 §1): pure reads over
        # the report tables (SELECT-only) + a Celery job launch (send_task is
        # stubbed); none may issue relational writes.
        "list_report_runs": {},
        "get_report_run": {"run_id": _UNKNOWN_DEVICE_ID},
        "request_report_generation": {
            "kind": "change",
            "period_start": "2026-07-01T00:00:00+00:00",
            "period_end": "2026-07-08T00:00:00+00:00",
        },
    }


@pytest.mark.asyncio
async def test_every_default_read_only_tool_obeys_relational_write_boundary(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    key_provider: FakeKmsKeyProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the registry census under the deny-by-default SQLAlchemy guard."""
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(db, "get_reader_sessionmaker", lambda: maker)

    from app.workers import celery_app as celery_module

    monkeypatch.setattr(celery_module.celery_app, "send_task", lambda *_a, **_kw: None)

    # Hermetic Neo4j boundary: the impact tool receives a deterministic empty graph.
    from app.agents.troubleshooting import tools as troubleshooting_tools

    async def empty_impact(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "projected_at": None,
            "depth_used": 0,
            "dependents": [],
            "dependencies": [],
        }

    monkeypatch.setattr(troubleshooting_tools, "application_impact", empty_impact)
    monkeypatch.setattr(troubleshooting_tools, "_knowledge_client", lambda: object())

    # Hermetic KMS and SSH boundaries. Device validation, envelope decryption,
    # credential audits, and transaction ownership remain production-real.
    class EmptyCapability:
        def __init__(self, *_args: Any) -> None:
            pass

        def get_bgp_peers(self) -> list[Any]:
            return []

        def get_ospf_neighbors(self) -> list[Any]:
            return []

        def get_acls(self) -> list[Any]:
            return []

    class EmptyPluginRegistry:
        def resolve(self, *_args: Any) -> type[EmptyCapability]:
            return EmptyCapability

    import app.plugins.registry as plugin_registry

    monkeypatch.setattr(troubleshooting_tools, "_key_provider", lambda: key_provider)
    monkeypatch.setattr(troubleshooting_tools, "_open_ssh", lambda _params: nullcontext(object()))
    monkeypatch.setattr(plugin_registry, "get_default_registry", lambda: EmptyPluginRegistry())

    # Hermetic LLM boundary for the two generative documentation tools.
    model = scripted_model([AIMessage(content="test document")] * 4)
    import app.llm.providers as providers

    monkeypatch.setattr(providers, "get_chat_model", lambda *_a, **_kw: model)

    registry = build_default_registry()
    read_only_tool_list = [
        tool
        for agent in registry.list()
        for tool in agent.tools
        if tool.classification is ToolClassification.READ_ONLY
    ]
    names = [tool.name for tool in read_only_tool_list]
    assert len(names) == len(set(names)) == 30, (
        "default registry must expose exactly 30 uniquely named READ_ONLY tools"
    )
    read_only_tools = {tool.name: tool for tool in read_only_tool_list}
    invocations = _invocation_fixtures()
    assert invocations.keys() == read_only_tools.keys()

    # The P4 W3-T1 report tools enforce the ADR-0053 §3 per-kind RBAC floor
    # against the role bound by agent_run_context (deny-by-default unbound), so
    # the census drives every tool under an admin invoking identity; the
    # relational write boundary under test is identity-independent.
    from app.core.security import Role as _Role

    with agent_run_context(role=_Role.ADMIN):
        for name, tool in read_only_tools.items():
            await tool.ainvoke(invocations[name])

    async with maker() as session:
        assert await session.scalar(select(func.count()).select_from(DiscoveryRun)) == 1
        actions = list((await session.scalars(select(AuditLog.action))).all())
        assert len(actions) == 6
        assert actions.count(audit.KEK_UNWRAP) == 3
        assert actions.count(audit.CREDENTIAL_DECRYPTED) == 3


@pytest.mark.asyncio
async def test_append_only_audit_write_remains_permitted(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The guard is not a zero-write rule: legitimate audit evidence persists."""
    async with maker() as session:
        await audit.record(
            session,
            actor="agent:troubleshooting",
            action=audit.CREDENTIAL_DECRYPTED,
            target_type="device_credential",
            target_id=str(uuid4()),
            detail={"reason": "troubleshooting_live_read"},
        )
        await session.commit()
    async with maker() as session:
        assert await session.scalar(select(func.count()).select_from(AuditLog)) == 1


@pytest.mark.asyncio
async def test_discovery_job_lifecycle_writes_only_discovery_runs(
    guarded_engine: AsyncEngine,
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both the launch INSERT and broker-failure UPDATE remain legitimate."""
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    run_id, status = await create_discovery_run(
        seeds=["192.0.2.1"],
        hop_limit=0,
        allowlist=["192.0.2.0/24"],
        credential_names=[],
    )
    assert status == DiscoveryRunStatus.PENDING.value

    await mark_discovery_run_failed(run_id, "fixture broker refusal")
    async with maker() as session:
        row = await session.get(DiscoveryRun, UUID(run_id))
        assert row is not None
        assert row.status is DiscoveryRunStatus.FAILED
        assert row.error == "fixture broker refusal"


_READ_FACADE_SQLALCHEMY_IMPORTS = frozenset({"Select", "func", "select"})


def _expression_root_name(node: ast.expr) -> str | None:
    """Return the left-most name in a call/attribute expression."""
    current = node
    while isinstance(current, (ast.Call, ast.Attribute, ast.Await)):
        if isinstance(current, ast.Call):
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _read_facade_ast_offenders(source: str) -> list[tuple[int, str]]:
    """Return imports/calls that can make the facade execute non-SELECT SQL."""
    tree = ast.parse(source)
    offenders: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("sqlalchemy"):
                    offenders.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("sqlalchemy"):
            if node.module != "sqlalchemy":
                offenders.append((node.lineno, f"from {node.module}"))
                continue
            for alias in node.names:
                if alias.name not in _READ_FACADE_SQLALCHEMY_IMPORTS or alias.asname is not None:
                    offenders.append((node.lineno, f"sqlalchemy import {alias.name}"))

    select_bindings: set[str] = set()
    assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
    changed = True
    while changed:
        changed = False
        for assignment in assignments:
            value = assignment.value
            if value is None:
                continue
            root = _expression_root_name(value)
            if root not in {"select", *select_bindings}:
                continue
            targets = (
                assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            )
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in select_bindings:
                    select_bindings.add(target.id)
                    changed = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "session":
            if node.func.attr in {"add", "commit", "delete", "flush", "rollback"}:
                offenders.append((node.lineno, f"session.{node.func.attr}"))
            elif node.func.attr == "execute":
                argument_root = _expression_root_name(node.args[0]) if node.args else None
                if argument_root not in {"select", *select_bindings}:
                    offenders.append((node.lineno, f"execute({argument_root})"))
    return sorted(offenders)


def test_read_facade_ast_contains_no_write_constructs() -> None:
    """Fast secondary pin: only known SELECT expressions reach execute()."""
    path = _ROOT / "app" / "agents" / "framework" / "read_facade.py"
    assert _read_facade_ast_offenders(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "source",
    [
        """
from sqlalchemy import text
async def bypass(session):
    await session.execute(text("UPDATE devices SET hostname = 'x'"))
""",
        """
from sqlalchemy import update as upd
async def bypass(session, Device):
    await session.execute(upd(Device).values(hostname="x"))
""",
    ],
)
def test_read_facade_ast_guard_bites_on_write_bypasses(source: str) -> None:
    """Textual DML and aliased Core writes both trip the static pin."""
    assert _read_facade_ast_offenders(source)


def test_read_facade_ast_guard_ignores_unrelated_container_updates() -> None:
    """The pin targets SQL/session writes, not ordinary dict mutation."""
    source = """
async def read_only():
    values = {}
    values.update({"status": "reachable"})
"""
    assert _read_facade_ast_offenders(source) == []


def test_discovery_jobs_ast_writes_only_discovery_runs() -> None:
    """The operational job seam is structurally pinned to its named table."""
    path = _ROOT / "app" / "agents" / "framework" / "discovery_jobs.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported_models = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "app.models"
        for alias in node.names
    }
    assert imported_models == {"DiscoveryRun", "DiscoveryRunStatus"}
