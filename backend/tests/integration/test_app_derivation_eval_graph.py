"""Live PostgreSQL -> Neo4j -> impact proof for the W4-T2 exact corpus."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import pytest
from sqlalchemy import delete, or_, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.agents.eval import app_derivation_eval as app_eval

from app import db
from app.core.config import Settings, get_settings
from app.engines.topology.app_derivation import derive_application_dependencies
from app.engines.topology.app_derivation_store import apply_derivation_plan
from app.engines.topology.projector import PROJECTED_NODE_LABELS, full_rebuild
from app.engines.topology.sync import derive_topology
from app.knowledge.neo4j_client import Neo4jClient
from app.knowledge.schema import (
    LABEL_APPLICATION,
    LABEL_DEVICE,
    LABEL_IPADDRESS,
    REL_DEPENDS_ON,
)
from app.knowledge.topology_read import fetch_impact
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
)
from app.models.identity import Role, User
from app.models.inventory import Device, NormalizedInterfaceRow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow

pytestmark = [pytest.mark.integration, pytest.mark.neo4j]


def _application_key(row: Application) -> str:
    if row.origin is ApplicationOrigin.MANUAL:
        return f"id:{row.id}"
    return f"origin:{row.origin_ref}"


def _instant(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    isoformat = getattr(value, "isoformat", None)
    rendered = isoformat() if callable(isoformat) else str(value)
    return datetime.fromisoformat(rendered.replace("Z", "+00:00"))


def _database_identity(url: URL) -> tuple[Any, ...]:
    """Driver-neutral identity used to bind destructive writes to the test DB."""
    return (
        url.get_backend_name(),
        url.username,
        url.password,
        url.host,
        url.port or 5432,
        url.database,
        tuple(sorted(url.query.items())),
    )


def _require_safe_test_endpoints() -> Settings:
    """Reject ambient/non-test stores before constructing a write-capable client."""
    if os.environ.get("PYTEST_XDIST_WORKER"):
        pytest.skip("destructive live graph corpus is serialized outside pytest-xdist")
    explicit_database_url = os.environ.get("NETOPS_TEST_DATABASE_URL")
    if explicit_database_url is None:
        pytest.skip("NETOPS_TEST_DATABASE_URL is required for live graph corpus writes")

    settings = get_settings()
    active_database = make_url(settings.database_url)
    explicit_database = make_url(explicit_database_url)
    if active_database.get_backend_name() != "postgresql":
        pytest.skip("live graph corpus writes require a PostgreSQL test database")
    if active_database.database != "netops_test":
        pytest.skip("live graph corpus writes require the dedicated netops_test database")
    if _database_identity(active_database) != _database_identity(explicit_database):
        pytest.skip("active database does not match explicit NETOPS_TEST_DATABASE_URL")

    neo4j_host = urlparse(str(settings.neo4j_uri)).hostname
    if neo4j_host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.skip("live graph corpus writes require a loopback Neo4j test endpoint")
    return settings


async def _purge_postgres(
    sessionmaker: async_sessionmaker[AsyncSession], estate: dict[str, Any]
) -> None:
    device_ids = [UUID(row["id"]) for row in estate["devices"]]
    manual_app_ids = [UUID(row["id"]) for row in estate["applications"]]
    origin_refs = [f"f5:{row['device_id']}:{row['name']}" for row in estate["virtual_servers"]]
    owned_app_ids = select(Application.id).where(
        or_(Application.id.in_(manual_app_ids), Application.origin_ref.in_(origin_refs))
    )
    async with sessionmaker() as session:
        await session.execute(
            delete(ApplicationDependency).where(
                ApplicationDependency.application_id.in_(owned_app_ids)
            )
        )
        await session.execute(
            delete(Application).where(
                or_(Application.id.in_(manual_app_ids), Application.origin_ref.in_(origin_refs))
            )
        )
        for model in (
            NormalizedHypervisorHostRow,
            NormalizedVirtualMachineRow,
            NormalizedPoolRow,
            NormalizedVirtualServerRow,
            NormalizedInterfaceRow,
        ):
            await session.execute(delete(model).where(model.device_id.in_(device_ids)))
        await session.execute(delete(User).where(User.id == UUID(estate["manual_actor"]["id"])))
        await session.execute(delete(Device).where(Device.id.in_(device_ids)))
        await session.commit()


async def _wipe_graph(client: Neo4jClient) -> None:
    async with client.session() as session:
        for label in PROJECTED_NODE_LABELS:
            await session.run(f"MATCH (n:{label}) DETACH DELETE n")


async def _projected_node_count(client: Neo4jClient) -> int:
    """Read-only safety census before this test takes ownership of the graph."""
    async with client.session() as session:
        result = await session.run(
            "MATCH (n) WHERE any(label IN labels(n) WHERE label IN $labels) "
            "RETURN count(n) AS count",
            labels=list(PROJECTED_NODE_LABELS),
        )
        record = await result.single()
    return int(record["count"] if record is not None else 0)


def _normalize_properties(properties: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(properties)
    if normalized.get("last_projected_at") is not None:
        normalized["last_projected_at"] = _instant(normalized["last_projected_at"])
    return normalized


async def _read_live_application_graph(
    client: Neo4jClient,
    application_key_by_id: dict[str, str],
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    """Read every projected Application node and DEPENDS_ON edge canonically."""
    applications: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    target_properties: dict[tuple[str, str], dict[str, Any]] = {}
    async with client.session() as session:
        result = await session.run("MATCH (a:Application) RETURN properties(a) AS props")
        async for record in result:
            properties = _normalize_properties(dict(record["props"]))
            pg_id = str(properties.pop("pg_id"))
            applications.append({"key": application_key_by_id[pg_id], **properties})

        result = await session.run(
            f"MATCH (a:Application)-[r:{REL_DEPENDS_ON}]->(t) "
            "RETURN a.pg_id AS application_id, labels(t) AS target_labels, "
            "t.pg_id AS target_key, properties(t) AS target_props, properties(r) AS rel_props"
        )
        async for record in result:
            target_label = next(
                label
                for label in record["target_labels"]
                if label in {LABEL_DEVICE, LABEL_IPADDRESS}
            )
            target_key = str(record["target_key"])
            normalized_target = _normalize_properties(dict(record["target_props"]))
            prior = target_properties.setdefault((target_label, target_key), normalized_target)
            assert prior == normalized_target

            rel_props = _normalize_properties(dict(record["rel_props"]))
            rel_props["derived_at"] = _instant(rel_props["derived_at"])
            edges.append(
                {
                    "app_key": application_key_by_id[str(record["application_id"])],
                    "target_label": target_label,
                    "target_key": target_key,
                    **rel_props,
                }
            )
    applications.sort(key=lambda row: row["key"])
    edges.sort(key=lambda row: (row["app_key"], row["target_label"], row["target_key"]))
    return {"applications": applications, "edges": edges}, target_properties


def _expected_live_application_graph(
    expected: dict[str, Any], projected_at: datetime
) -> dict[str, Any]:
    applications = [
        {
            key: value
            for key, value in {
                "key": row["key"],
                "name": row["name"],
                "description": row["description"],
                "origin": row["origin"],
                "owner": row["owner"],
                "fqdns": row["fqdns"],
                "last_projected_at": projected_at,
            }.items()
            if value is not None
        }
        for row in expected["applications"]
    ]
    edges = [
        {
            "app_key": row["app_key"],
            "target_label": row["target_label"],
            "target_key": row["target_key"],
            "sources": row["sources"],
            "derived_at": _instant(row["derived_at"]),
            "provenance": row["compact_provenance"],
            "last_projected_at": projected_at,
        }
        for row in expected["edges"]
    ]
    return {"applications": applications, "edges": edges}


def _normalize_impact(result: dict[str, Any]) -> dict[str, Any]:
    """Normalize temporals/order while rejecting any malformed or extra payload field."""
    assert set(result) == {
        "target",
        "dependents",
        "dependencies",
        "projected_at",
        "depth_used",
    }
    assert set(result["target"]) == {"label", "key"}

    dependents: list[dict[str, Any]] = []
    for row in result["dependents"]:
        assert set(row) == {"application", "target", "sources", "provenance", "derived_at"}
        assert set(row["application"]) == {"label", "key", "properties"}
        assert set(row["target"]) == {"label", "key"}
        dependents.append(
            {
                "application": {
                    **row["application"],
                    "properties": _normalize_properties(row["application"]["properties"]),
                },
                "target": row["target"],
                "sources": row["sources"],
                "provenance": row["provenance"],
                "derived_at": _instant(row["derived_at"]),
            }
        )
    dependents.sort(
        key=lambda row: (
            str(row["application"]["key"]),
            row["target"]["label"],
            str(row["target"]["key"]),
        )
    )

    dependencies: list[dict[str, Any]] = []
    for row in result["dependencies"]:
        assert set(row) == {"target", "sources", "provenance", "derived_at"}
        assert set(row["target"]) == {"label", "key", "properties"}
        dependencies.append(
            {
                "target": {
                    **row["target"],
                    "properties": _normalize_properties(row["target"]["properties"]),
                },
                "sources": row["sources"],
                "provenance": row["provenance"],
                "derived_at": _instant(row["derived_at"]),
            }
        )
    dependencies.sort(key=lambda row: (row["target"]["label"], str(row["target"]["key"])))
    return {
        "target": result["target"],
        "dependents": dependents,
        "dependencies": dependencies,
        "projected_at": (
            _instant(result["projected_at"]) if result["projected_at"] is not None else None
        ),
        "depth_used": result["depth_used"],
    }


async def _assert_application_store_isolated(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """Fail before the production global desired-state applier can touch foreign rows."""
    async with sessionmaker() as session:
        applications = list((await session.execute(select(Application.id))).scalars())
        dependencies = list((await session.execute(select(ApplicationDependency.id))).scalars())
    assert applications == [], (
        "live corpus requires an isolated application store before global derivation apply"
    )
    assert dependencies == [], (
        "live corpus requires an isolated dependency store before global derivation apply"
    )


async def _seed_apply_and_reload(
    sessionmaker: async_sessionmaker[AsyncSession], estate: dict[str, Any]
) -> tuple[
    app_eval.EstateRows,
    list[Device],
    list[NormalizedInterfaceRow],
    list[Application],
    list[ApplicationDependency],
]:
    rows = app_eval.build_estate_rows(estate)
    actor = estate["manual_actor"]
    device_ids = [row.id for row in rows.devices]
    manual_app_ids = [row.id for row in rows.applications]
    origin_refs = [f"f5:{row.device_id}:{row.name}" for row in rows.virtual_servers]
    application_scope = or_(
        Application.id.in_(manual_app_ids), Application.origin_ref.in_(origin_refs)
    )
    async with sessionmaker() as session:
        role = (await session.execute(select(Role).where(Role.name == "engineer"))).scalar_one()
        session.add(
            User(
                id=UUID(actor["id"]),
                username=actor["username"],
                email=actor["email"],
                password_hash="not-a-real-hash",
                role_id=role.id,
            )
        )
        # No ORM relationship links these rows; make the created_by target
        # durable in this transaction before applications can be flushed.
        await session.flush()
        session.add_all([*rows.devices, *rows.applications])
        await session.flush()
        session.add_all(
            [
                *rows.interfaces,
                *rows.virtual_servers,
                *rows.pools,
                *rows.virtual_machines,
                *rows.hypervisor_hosts,
                *rows.manual_dependencies,
            ]
        )
        await session.commit()

    async with sessionmaker() as session:
        applications = list(
            (await session.execute(select(Application).where(application_scope))).scalars()
        )
        application_ids = [row.id for row in applications]
        dependencies = list(
            (
                await session.execute(
                    select(ApplicationDependency).where(
                        ApplicationDependency.application_id.in_(application_ids)
                    )
                )
            ).scalars()
        )
        virtual_servers = list(
            (
                await session.execute(
                    select(NormalizedVirtualServerRow).where(
                        NormalizedVirtualServerRow.device_id.in_(device_ids)
                    )
                )
            ).scalars()
        )
        pools = list(
            (
                await session.execute(
                    select(NormalizedPoolRow).where(NormalizedPoolRow.device_id.in_(device_ids))
                )
            ).scalars()
        )
        virtual_machines = list(
            (
                await session.execute(
                    select(NormalizedVirtualMachineRow).where(
                        NormalizedVirtualMachineRow.device_id.in_(device_ids)
                    )
                )
            ).scalars()
        )
        hypervisor_hosts = list(
            (
                await session.execute(
                    select(NormalizedHypervisorHostRow).where(
                        NormalizedHypervisorHostRow.device_id.in_(device_ids)
                    )
                )
            ).scalars()
        )
        devices = list(
            (await session.execute(select(Device).where(Device.id.in_(device_ids)))).scalars()
        )
        interfaces = list(
            (
                await session.execute(
                    select(NormalizedInterfaceRow).where(
                        NormalizedInterfaceRow.device_id.in_(device_ids)
                    )
                )
            ).scalars()
        )
        plan = derive_application_dependencies(
            virtual_servers=virtual_servers,
            pools=pools,
            virtual_machines=virtual_machines,
            hypervisor_hosts=hypervisor_hosts,
            devices=devices,
            interfaces=interfaces,
            applications=applications,
            dependencies=dependencies,
            dns_records=rows.dns_records,
        )
        await apply_derivation_plan(session, plan, now=rows.t0)
        await session.commit()

    async with sessionmaker() as session:
        devices = list(
            (await session.execute(select(Device).where(Device.id.in_(device_ids)))).scalars()
        )
        interfaces = list(
            (
                await session.execute(
                    select(NormalizedInterfaceRow).where(
                        NormalizedInterfaceRow.device_id.in_(device_ids)
                    )
                )
            ).scalars()
        )
        applications = list(
            (await session.execute(select(Application).where(application_scope))).scalars()
        )
        application_ids = [row.id for row in applications]
        dependencies = list(
            (
                await session.execute(
                    select(ApplicationDependency).where(
                        ApplicationDependency.application_id.in_(application_ids)
                    )
                )
            ).scalars()
        )
    return rows, devices, interfaces, applications, dependencies


def _expected_dependencies(
    expected: dict[str, Any],
    application_key: str,
    target_properties: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        {
            "target": {
                "label": edge["target_label"],
                "key": edge["target_key"],
                "properties": target_properties[(edge["target_label"], edge["target_key"])],
            },
            "sources": edge["sources"],
            "provenance": edge["compact_provenance"],
            "derived_at": _instant(edge["derived_at"]),
        }
        for edge in expected["edges"]
        if edge["app_key"] == application_key
    ]
    return sorted(rows, key=lambda row: (row["target"]["label"], row["target"]["key"]))


async def test_exact_corpus_persists_projects_and_drives_impact_both_directions() -> None:
    settings = _require_safe_test_endpoints()

    engine = db.create_engine(settings)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"PostgreSQL unreachable for live graph integration: {type(exc).__name__}")

    client = Neo4jClient(settings)
    try:
        neo4j_healthy = await client.health_check()
    except BaseException:
        try:
            await client.close()
        finally:
            await engine.dispose()
        raise
    if not neo4j_healthy:
        try:
            await client.close()
        finally:
            await engine.dispose()
        pytest.skip("Neo4j unreachable for live graph integration")

    try:
        projected_nodes_before = await _projected_node_count(client)
    except BaseException:
        try:
            await client.close()
        finally:
            await engine.dispose()
        raise
    if projected_nodes_before != 0:
        try:
            await client.close()
        finally:
            await engine.dispose()
        pytest.fail("refusing destructive live corpus run: projected Neo4j test graph is not empty")

    sessionmaker = db.create_sessionmaker(engine)
    estate = app_eval.load_estate()
    contract = app_eval.load_expected_contract()
    expected = app_eval.load_expected_graph()
    test_error: BaseException | None = None
    try:
        await _purge_postgres(sessionmaker, estate)
        await _assert_application_store_isolated(sessionmaker)
        rows, devices, interfaces, applications, dependencies = await _seed_apply_and_reload(
            sessionmaker, estate
        )

        persisted_graph = app_eval.canonicalize_persisted_graph(applications, dependencies)
        assert persisted_graph == expected

        topology = derive_topology(devices, interfaces, [], [], applications, dependencies)
        assert len(topology.applications.applications) == len(expected["applications"])
        assert len(topology.applications.depends_on) == len(expected["edges"])
        await full_rebuild(
            client,
            topology.nodes,
            topology.edges,
            rows.projection_at,
            applications=topology.applications,
        )

        application_ids = {_application_key(row): str(row.id) for row in applications}
        application_key_by_id = {value: key for key, value in application_ids.items()}
        live_graph, target_properties = await _read_live_application_graph(
            client, application_key_by_id
        )
        assert live_graph == _expected_live_application_graph(expected, rows.projection_at)

        for expected_application in expected["applications"]:
            application_key = expected_application["key"]
            expected_dependencies = _expected_dependencies(
                expected, application_key, target_properties
            )
            if not expected_dependencies:
                continue
            result = await fetch_impact(
                client,
                target_label=LABEL_APPLICATION,
                target_key=application_ids[application_key],
                depth=1,
            )
            assert _normalize_impact(result) == {
                "target": {
                    "label": LABEL_APPLICATION,
                    "key": application_ids[application_key],
                },
                "dependents": [],
                "dependencies": expected_dependencies,
                "projected_at": rows.projection_at,
                "depth_used": 1,
            }

        retail_key = contract["retail_app_key"]
        shared = next(
            edge
            for edge in expected["edges"]
            if tuple(edge[key] for key in ("app_key", "target_label", "target_key"))
            == tuple(contract["shared_edge_key"])
        )
        indirect = await fetch_impact(
            client,
            target_label=LABEL_DEVICE,
            target_key="20000000-0000-0000-0000-000000000002",
            depth=2,
        )
        assert _normalize_impact(indirect) == {
            "target": {
                "label": LABEL_DEVICE,
                "key": "20000000-0000-0000-0000-000000000002",
            },
            "dependents": [
                {
                    "application": {
                        "label": LABEL_APPLICATION,
                        "key": application_ids[retail_key],
                        "properties": {
                            "pg_id": application_ids[retail_key],
                            "name": "Retail.CORP.example.com",
                            "description": "Operator-owned retail service",
                            "origin": "manual",
                            "owner": "payments-platform",
                            "fqdns": [
                                "loop.example.com",
                                "retail-manual.example.com",
                                "unresolved.example.com",
                            ],
                            "last_projected_at": rows.projection_at,
                        },
                    },
                    "target": {
                        "label": LABEL_IPADDRESS,
                        "key": "30000000-0000-0000-0000-000000000002",
                    },
                    "sources": shared["sources"],
                    "provenance": shared["compact_provenance"],
                    "derived_at": rows.t0,
                }
            ],
            "dependencies": [],
            "projected_at": rows.projection_at,
            "depth_used": 2,
        }
    except BaseException as exc:
        test_error = exc
        raise
    finally:
        cleanup_errors: list[Exception] = []
        for cleanup in (
            lambda: _wipe_graph(client),
            lambda: _purge_postgres(sessionmaker, estate),
            client.close,
            engine.dispose,
        ):
            try:
                await cleanup()
            except Exception as exc:  # cleanup must continue through every resource
                cleanup_errors.append(exc)
        if cleanup_errors:
            if test_error is not None:
                for cleanup_error in cleanup_errors:
                    test_error.add_note(
                        f"cleanup failure: {type(cleanup_error).__name__}: {cleanup_error}"
                    )
            else:
                raise ExceptionGroup("live corpus cleanup failures", cleanup_errors)
