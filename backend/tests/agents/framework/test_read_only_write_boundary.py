"""Relational write boundary for directly invoked READ_ONLY agent tools."""

from __future__ import annotations

import ast
import re
from collections.abc import AsyncIterator, Iterator
from contextlib import nullcontext
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
from app.agents.framework.credential_access import acquire_troubleshooting_ssh
from app.agents.framework.discovery_jobs import create_discovery_run, mark_discovery_run_failed
from app.agents.framework.tools import ToolClassification, netops_tool
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
)
from app.services import audit
from tests.agents.conftest import scripted_model

_ROOT = Path(__file__).parents[3]
_UNKNOWN_DEVICE_ID = "11111111-1111-1111-1111-111111111111"

# READ_ONLY direct invocation may create operational discovery jobs and append
# credential/tool audit evidence. Neither mutates relational domain state.
_ALLOWED_WRITES = {
    "discovery_runs": "operational job row; READ_ONLY job-launch semantic",
    "audit_log": "append-only credential-access/tool audit; fail-closed evidence",
}

_TEXTUAL_DML = re.compile(
    r"\b(?:insert\s+into|update|delete\s+from)\s+"
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


def _textual_dml_targets(statement: str) -> list[str]:
    """Return every textual DML target, failing closed on unparsed DML."""
    sql = _sql_code_only(statement)
    matches = list(_TEXTUAL_DML.finditer(sql))
    keyword_starts = [match.start() for match in _DML_KEYWORD.finditer(sql)]
    if keyword_starts != [match.start() for match in matches]:
        raise ReadOnlyWriteViolation(
            "READ_ONLY direct invocation attempted unparseable textual DML"
        )
    targets: list[str] = []
    for match in matches:
        identifier = match.group("table").rsplit(".", 1)[-1]
        targets.append(identifier.strip('"`[]'))
    return targets


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
        if isinstance(clauseelement, (Insert, Update, Delete)):
            table_name = cast(Table, clauseelement.table).name
        elif isinstance(clauseelement, TextClause):
            table_names = _textual_dml_targets(clauseelement.text)
            for textual_table_name in table_names:
                if textual_table_name not in _ALLOWED_WRITES:
                    raise ReadOnlyWriteViolation(
                        "READ_ONLY direct invocation attempted a write to "
                        f"{textual_table_name!r}; allowed tables: {sorted(_ALLOWED_WRITES)}"
                    )
            return
        else:
            return
        if table_name not in _ALLOWED_WRITES:
            raise ReadOnlyWriteViolation(
                f"READ_ONLY direct invocation attempted a write to {table_name!r}; "
                f"allowed tables: {sorted(_ALLOWED_WRITES)}"
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
            DELETE FROM audit_log WHERE id IS NULL RETURNING id
        ), changed AS (
            UPDATE devices SET hostname = 'forbidden' RETURNING id
        )
        SELECT id FROM removed
    """
    async with maker() as session:
        with pytest.raises(ReadOnlyWriteViolation, match="devices"):
            await session.execute(text(statement))


def test_textual_parser_accepts_multiple_allowed_dml_targets() -> None:
    """Every mutation in a multi-DML statement is returned for validation."""
    statement = """
        WITH removed AS (
            DELETE FROM audit_log WHERE id IS NULL RETURNING id
        ), appended AS (
            INSERT INTO audit_log (id) SELECT id FROM removed RETURNING id
        )
        SELECT id FROM appended
    """
    assert _textual_dml_targets(statement) == ["audit_log", "audit_log"]


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
    assert len(names) == len(set(names)) == 27, (
        "default registry must expose exactly 27 uniquely named READ_ONLY tools"
    )
    read_only_tools = {tool.name: tool for tool in read_only_tool_list}
    invocations = _invocation_fixtures()
    assert invocations.keys() == read_only_tools.keys()

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


def _call_name(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def test_read_facade_ast_contains_no_write_constructs() -> None:
    """Fast secondary pin: the read facade has no ORM/Core mutation syntax."""
    path = _ROOT / "app" / "agents" / "framework" / "read_facade.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {"add", "delete", "commit", "flush", "insert", "update"}
    offenders = [
        (node.lineno, name)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (name := _call_name(node)) is not None
        and name in forbidden
    ]
    assert offenders == []


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
