"""Real-PostgreSQL exact-corpus persistence gate (P4 W4-T2, ADR-0052)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.engines.topology.app_derivation import DerivationPlan, derive_application_dependencies
from app.engines.topology.app_derivation_store import (
    DerivationApplyStats,
    apply_derivation_plan,
)
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
)
from app.models.identity import Role, User
from app.models.inventory import Device, NormalizedInterfaceRow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow
from tests.agents.eval import app_derivation_eval as app_eval

pytestmark = pytest.mark.integration


async def _stored_rows(
    session: AsyncSession,
) -> tuple[list[Application], list[ApplicationDependency]]:
    applications = list(
        (
            await session.execute(
                select(Application).order_by(Application.origin, Application.name, Application.id)
            )
        ).scalars()
    )
    dependencies = list(
        (
            await session.execute(
                select(ApplicationDependency).order_by(
                    ApplicationDependency.application_id,
                    ApplicationDependency.target_kind,
                    ApplicationDependency.target_ref,
                    ApplicationDependency.source,
                )
            )
        ).scalars()
    )
    return applications, dependencies


async def _reload_rows(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> tuple[list[Application], list[ApplicationDependency]]:
    """Reload through a new identity map so assertions see server state only."""
    async with sessionmaker() as session:
        return await _stored_rows(session)


def _storage_snapshot(
    applications: list[Application], dependencies: list[ApplicationDependency]
) -> dict[str, Any]:
    """Every value that an unchanged re-run is forbidden to churn."""
    return {
        "applications": [
            {
                "id": str(row.id),
                "origin_ref": row.origin_ref,
                "name_key": row.name.casefold(),
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "derived_watermark": row.derived_watermark,
                "created_by": str(row.created_by) if row.created_by else None,
            }
            for row in applications
        ],
        "dependencies": [
            {
                "id": str(row.id),
                "natural_key": (
                    str(row.application_id),
                    str(row.target_kind),
                    row.target_ref,
                    str(row.source),
                ),
                "provenance": row.provenance,
                "derived_at": row.derived_at,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "created_by": str(row.created_by) if row.created_by else None,
            }
            for row in dependencies
        ],
    }


async def _derive_and_apply(
    sessionmaker: async_sessionmaker[AsyncSession],
    rows: app_eval.EstateRows,
    *,
    now: datetime,
) -> tuple[DerivationPlan, DerivationApplyStats, dict[str, int]]:
    """Load every persisted source row, derive, apply, commit, and close."""
    async with sessionmaker() as session:
        current_applications, current_dependencies = await _stored_rows(session)
        virtual_servers = list(
            (await session.execute(select(NormalizedVirtualServerRow))).scalars()
        )
        pools = list((await session.execute(select(NormalizedPoolRow))).scalars())
        virtual_machines = list(
            (await session.execute(select(NormalizedVirtualMachineRow))).scalars()
        )
        hypervisor_hosts = list(
            (await session.execute(select(NormalizedHypervisorHostRow))).scalars()
        )
        devices = list((await session.execute(select(Device))).scalars())
        interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
        plan = derive_application_dependencies(
            virtual_servers=virtual_servers,
            pools=pools,
            virtual_machines=virtual_machines,
            hypervisor_hosts=hypervisor_hosts,
            devices=devices,
            interfaces=interfaces,
            applications=current_applications,
            dependencies=current_dependencies,
            # DNS is the ADR-0052 input-side exception: no persisted record table.
            dns_records=rows.dns_records,
        )
        stats = await apply_derivation_plan(session, plan, now=now)
        await session.commit()
    return (
        plan,
        stats,
        {
            "devices": len(devices),
            "interfaces": len(interfaces),
            "virtual_servers": len(virtual_servers),
            "pools": len(pools),
            "virtual_machines": len(virtual_machines),
            "hypervisor_hosts": len(hypervisor_hosts),
        },
    )


async def test_exact_corpus_round_trip_and_unchanged_rerun_are_storage_idempotent(
    pg_engine: AsyncEngine,
) -> None:
    estate = app_eval.load_estate()
    contract = app_eval.load_expected_contract()
    expected = app_eval.load_expected_graph()
    rows = app_eval.build_estate_rows(estate)
    actor = estate["manual_actor"]
    sessionmaker = async_sessionmaker(pg_engine, expire_on_commit=False)

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
        # No ORM relationship links these rows; flush the actor first so the
        # application/dependency created_by FKs cannot be ordered ahead of it.
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

    first_plan, first_stats, loaded_counts = await _derive_and_apply(
        sessionmaker, rows, now=rows.t0
    )
    assert loaded_counts == {
        "devices": len(estate["devices"]),
        "interfaces": len(estate["interfaces"]),
        "virtual_servers": len(estate["virtual_servers"]),
        "pools": len(estate["pools"]),
        "virtual_machines": len(estate["virtual_machines"]),
        "hypervisor_hosts": len(estate["hypervisor_hosts"]),
    }
    assert first_plan.stats.model_dump(mode="json") == contract["expected_stats"]
    assert (
        first_stats.applications_created,
        first_stats.applications_updated,
        first_stats.applications_deleted,
    ) == (4, 0, 0)
    assert (
        first_stats.f5.model_dump(),
        first_stats.vmware.model_dump(),
        first_stats.dns.model_dump() if first_stats.dns else None,
    ) == (
        {"inserted": 2, "updated": 0, "deleted": 0},
        {"inserted": 1, "updated": 0, "deleted": 0},
        {"inserted": 2, "updated": 0, "deleted": 0},
    )

    applications_t0, dependencies_t0 = await _reload_rows(sessionmaker)
    assert {
        str(row.created_by) for row in applications_t0 if row.origin is ApplicationOrigin.MANUAL
    } == {actor["id"]}
    assert {
        str(row.created_by) for row in dependencies_t0 if row.source is DependencySource.MANUAL
    } == {actor["id"]}
    graph_t0 = app_eval.canonicalize_persisted_graph(applications_t0, dependencies_t0)
    assert app_eval.evaluate_graph(graph_t0, expected).accepted
    storage_t0 = _storage_snapshot(applications_t0, dependencies_t0)

    _, second_stats, second_loaded_counts = await _derive_and_apply(sessionmaker, rows, now=rows.t1)
    assert second_loaded_counts == loaded_counts
    assert (
        second_stats.applications_created,
        second_stats.applications_updated,
        second_stats.applications_deleted,
    ) == (0, 0, 0)
    assert second_stats.f5.model_dump() == {"inserted": 0, "updated": 0, "deleted": 0}
    assert second_stats.vmware.model_dump() == {
        "inserted": 0,
        "updated": 0,
        "deleted": 0,
    }
    assert second_stats.dns is not None
    assert second_stats.dns.model_dump() == {"inserted": 0, "updated": 0, "deleted": 0}

    applications_t1, dependencies_t1 = await _reload_rows(sessionmaker)
    graph_t1 = app_eval.canonicalize_persisted_graph(applications_t1, dependencies_t1)
    assert graph_t1 == graph_t0 == expected
    storage_t1 = _storage_snapshot(applications_t1, dependencies_t1)
    assert storage_t1 == storage_t0
    dependency_rows = storage_t1["dependencies"]
    assert len({row["natural_key"] for row in dependency_rows}) == len(dependency_rows)
