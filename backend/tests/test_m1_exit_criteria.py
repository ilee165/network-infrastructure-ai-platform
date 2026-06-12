"""M1 roadmap exit-criteria tests (docs/roadmap/MVP.md §3, M1-18).

Verifiable-without-the-lab criteria covered here:

- "No API response, log line, or trace contains credential plaintext
  (automated leak test greps API responses and structured logs)"
  → :class:`TestCredentialLeakScan`.
- "Every normalized row links back to a ``raw_artifacts`` record containing
  the verbatim command output (D6 auditability — automated test)"
  → :class:`TestArtifactLinkage`.
- "Re-running discovery is idempotent: device/interface counts stable,
  changes recorded as updates not duplicates"
  → :class:`TestIdempotency`.

Lab-only criteria (deliberately NOT covered here — they require real
devices and are exercised by ``@pytest.mark.lab`` runs against the lab):

- From one seed device, a live discovery run walks LLDP/CDP neighbors
  within the hop limit and discovers every reachable lab device.
- SNMPv3 (authPriv) and SNMPv2c collection succeed against real devices.

Fixture reuse (per M1-18 instructions): the API stack (in-memory aiosqlite
engine, seeded users, ASGI app/client) is reused from ``tests/api/conftest.py``
and the static KEK provider from the M1-15 credentials tests; the realistic
collection-result builders are reused from the M1-13 persistence tests.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

import httpx
import pytest
import structlog.testing
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.discovery.persistence import (
    persist_device_result,
    store_artifact,
    upsert_device,
    upsert_interfaces,
)
from app.models import (
    AuditLog,
    Device,
    DiscoveryRun,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)
from app.schemas.normalized import InterfaceOperStatus
from tests.api import conftest as _api_conftest
from tests.api import test_credentials as _credentials_tests
from tests.engines.discovery.test_persistence import (
    MGMT_IP,
    RAW_OUTPUTS,
    _facts,
    _interface,
    _result,
)

TEST_PASSWORD = _api_conftest.TEST_PASSWORD

# Reused fixtures (M1-18: reuse, don't duplicate): binding them as module
# attributes registers them with pytest for the tests below, exactly as a
# ``from ... import`` would, without tripping F811 on shadowing parameters.
password_hash = _api_conftest.password_hash
engine = _api_conftest.engine
session = _api_conftest.session
users = _api_conftest.users
app = _api_conftest.app
client = _api_conftest.client
key_provider = _credentials_tests.key_provider
_StaticProvider = _credentials_tests._StaticProvider

# ---------------------------------------------------------------------------
# 1. Credential leak scan
# ---------------------------------------------------------------------------

#: Unmistakable sentinels: any appearance outside the vault is a leak.
SSH_SENTINEL = "LEAK-SENTINEL-SSH-c4a1f0d2e9b7"
ROTATED_SENTINEL = "LEAK-SENTINEL-ROTATED-5b8d3e0f12"
SNMPV3_AUTH_SENTINEL = "LEAK-SENTINEL-SNMPV3-AUTH-7fe2a90c"
SNMPV3_PRIV_SENTINEL = "LEAK-SENTINEL-SNMPV3-PRIV-91ab64d7"
SENTINELS = (SSH_SENTINEL, ROTATED_SENTINEL, SNMPV3_AUTH_SENTINEL, SNMPV3_PRIV_SENTINEL)


def _assert_clean(text: str, where: str) -> None:
    for sentinel in SENTINELS:
        assert sentinel not in text, f"credential sentinel {sentinel!r} leaked into {where}"


class TestCredentialLeakScan:
    """Exit criterion: no API response, header, or log line carries plaintext."""

    async def test_no_sentinel_in_any_response_header_or_log(
        self,
        client: httpx.AsyncClient,
        users: dict[str, Any],
        key_provider: _StaticProvider,
        session: AsyncSession,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        responses: list[httpx.Response] = []

        async def _do(coro: Any, expected_status: int) -> dict[str, Any]:
            response: httpx.Response = await coro
            responses.append(response)
            assert response.status_code == expected_status, response.text
            if response.status_code == 204 or not response.content:
                return {}
            body: dict[str, Any] = response.json()
            return body

        with structlog.testing.capture_logs() as captured_logs:
            # Real login (not a minted token) so the refresh cookie round-trips.
            login = await _do(
                client.post(
                    "/api/v1/auth/login",
                    json={"username": "engineer_user", "password": TEST_PASSWORD},
                ),
                200,
            )
            headers = {"Authorization": f"Bearer {login['access_token']}"}

            ssh_cred = await _do(
                client.post(
                    "/api/v1/credentials",
                    json={
                        "name": "lab-ssh",
                        "kind": "ssh",
                        "username": "netops",
                        "secret": SSH_SENTINEL,
                        "params": {"port": 22},
                    },
                    headers=headers,
                ),
                201,
            )
            await _do(
                client.post(
                    "/api/v1/credentials",
                    json={
                        "name": "lab-snmpv3",
                        "kind": "snmp_v3",
                        "username": "netops-snmp",
                        "secret": json.dumps(
                            {"auth_key": SNMPV3_AUTH_SENTINEL, "priv_key": SNMPV3_PRIV_SENTINEL}
                        ),
                        "params": {"auth_protocol": "SHA", "priv_protocol": "AES"},
                    },
                    headers=headers,
                ),
                201,
            )
            device = await _do(
                client.post(
                    "/api/v1/devices",
                    json={
                        "hostname": "lab-sw-01",
                        "mgmt_ip": MGMT_IP,
                        "vendor_id": "cisco_ios",
                        "credential_id": ssh_cred["id"],
                    },
                    headers=headers,
                ),
                201,
            )
            run = DiscoveryRun(seeds=[MGMT_IP], hop_limit=1, credential_names=["lab-ssh"])
            session.add(run)
            await session.commit()

            # Every read surface of M1: devices, credentials, discovery, auth.
            for path in (
                "/api/v1/devices",
                f"/api/v1/devices/{device['id']}",
                f"/api/v1/devices/{device['id']}/interfaces",
                f"/api/v1/devices/{device['id']}/neighbors",
                "/api/v1/credentials",
                "/api/v1/discovery/runs",
                f"/api/v1/discovery/runs/{run.id}",
                f"/api/v1/discovery/runs/{run.id}/results",
            ):
                await _do(client.get(path, headers=headers), 200)

            await _do(
                client.post(
                    f"/api/v1/credentials/{ssh_cred['id']}/rotate",
                    json={"secret": ROTATED_SENTINEL},
                    headers=headers,
                ),
                200,
            )
            # Refresh rotates the cookie set at login (cookie jar replays it).
            await _do(client.post("/api/v1/auth/refresh"), 200)

        for response in responses:
            where = f"{response.request.method} {response.request.url.path}"
            _assert_clean(response.text, f"response body of {where}")
            header_blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            _assert_clean(header_blob, f"response headers of {where}")

        _assert_clean(repr(captured_logs), "structlog output")
        _assert_clean(caplog.text, "stdlib logging output")

        # Defense in depth: the persisted audit trail must be clean too.
        audit_rows = (await session.execute(select(AuditLog))).scalars().all()
        assert audit_rows, "expected audit entries for the exercised endpoints"
        for row in audit_rows:
            _assert_clean(
                f"{row.actor} {row.action} {row.target_type} {row.target_id} {row.detail!r}",
                f"audit_log row {row.action}",
            )


# ---------------------------------------------------------------------------
# 2. Artifact linkage
# ---------------------------------------------------------------------------


@pytest.fixture()
async def run(session: AsyncSession) -> DiscoveryRun:
    discovery_run = DiscoveryRun(seeds=[MGMT_IP], hop_limit=1)
    session.add(discovery_run)
    await session.flush()
    return discovery_run


async def _count(session: AsyncSession, model: type[Any]) -> int:
    return (await session.execute(select(func.count()).select_from(model))).scalar_one()


NORMALIZED_MODELS: tuple[type[Any], ...] = (
    NormalizedInterfaceRow,
    NormalizedRouteRow,
    NormalizedNeighborRow,
)


class TestArtifactLinkage:
    """Exit criterion: every normalized row joins to its verbatim raw artifact."""

    async def test_every_normalized_row_joins_to_verbatim_artifact(
        self, session: AsyncSession, run: DiscoveryRun
    ) -> None:
        await persist_device_result(
            session, run=run, device_result=_result(), mgmt_ip=MGMT_IP, credential_id=None
        )
        await session.commit()

        artifacts: dict[uuid.UUID, RawArtifact] = {
            artifact.id: artifact
            for artifact in (await session.execute(select(RawArtifact))).scalars()
        }
        assert artifacts, "discovery persisted no raw artifacts"

        for model in NORMALIZED_MODELS:
            rows = list((await session.execute(select(model))).scalars())
            assert rows, f"no {model.__name__} rows persisted"
            for row in rows:
                assert row.raw_artifact_id is not None, f"{model.__name__} row lost provenance"
                artifact = artifacts.get(row.raw_artifact_id)
                assert artifact is not None, (
                    f"{model.__name__}.raw_artifact_id does not join to raw_artifacts"
                )
                # The artifact is the verbatim output of the originating command,
                # captured during this run.
                assert artifact.raw_text == RAW_OUTPUTS[artifact.command]
                assert artifact.raw_text.strip(), "raw artifact holds no command output"
                assert artifact.run_id == run.id


# ---------------------------------------------------------------------------
# 3. Idempotency
# ---------------------------------------------------------------------------


def _interface_pair(**gi2_overrides: Any) -> list[Any]:
    """Two interfaces so 'exactly that row' assertions are non-trivial."""
    return [
        _interface(),
        _interface(name="GigabitEthernet0/2", ip_address=None, **gi2_overrides),
    ]


def _iface_data(row: NormalizedInterfaceRow) -> tuple[Any, ...]:
    return (
        row.name,
        row.description,
        row.admin_status,
        row.oper_status,
        row.mac_address,
        row.ip_address,
        row.mtu,
        row.speed_mbps,
    )


def _route_data(row: NormalizedRouteRow) -> tuple[Any, ...]:
    return (
        row.vrf,
        row.prefix,
        row.protocol,
        row.next_hop,
        row.interface,
        row.distance,
        row.metric,
    )


def _neighbor_data(row: NormalizedNeighborRow) -> tuple[Any, ...]:
    return (
        row.protocol,
        row.local_interface,
        row.neighbor_name,
        row.neighbor_interface,
        row.neighbor_address,
        list(row.neighbor_capabilities),
    )


async def _snapshot(session: AsyncSession) -> dict[uuid.UUID, tuple[Any, ...]]:
    """``row id -> normalized data`` (provenance/timestamps excluded) across tables."""
    extractors = {
        NormalizedInterfaceRow: _iface_data,
        NormalizedRouteRow: _route_data,
        NormalizedNeighborRow: _neighbor_data,
    }
    snapshot: dict[uuid.UUID, tuple[Any, ...]] = {}
    for model, extract in extractors.items():
        rows = (
            (await session.execute(select(model).execution_options(populate_existing=True)))
            .scalars()
            .all()
        )
        for row in rows:
            snapshot[row.id] = (model.__name__, *extract(row))
    return snapshot


class TestIdempotency:
    """Exit criterion: re-running discovery updates in place, never duplicates."""

    async def test_two_identical_persists_keep_counts_stable(
        self, session: AsyncSession, run: DiscoveryRun
    ) -> None:
        result = _result(interfaces=_interface_pair())
        first = await persist_device_result(
            session, run=run, device_result=result, mgmt_ip=MGMT_IP, credential_id=None
        )
        await session.commit()
        counts_after_first = {m: await _count(session, m) for m in (Device, *NORMALIZED_MODELS)}

        second = await persist_device_result(
            session, run=run, device_result=result, mgmt_ip=MGMT_IP, credential_id=None
        )
        await session.commit()
        counts_after_second = {m: await _count(session, m) for m in (Device, *NORMALIZED_MODELS)}

        # Identical row counts, no duplicates: the second pass is pure updates.
        assert counts_after_second == counts_after_first
        assert counts_after_first[Device] == 1
        total_inserted_first = sum(c["inserted"] for c in first.values())
        assert total_inserted_first == sum(counts_after_first[m] for m in NORMALIZED_MODELS)
        assert all(c["inserted"] == 0 for c in second.values())
        assert {kind: c["updated"] for kind, c in second.items()} == {
            kind: c["inserted"] for kind, c in first.items()
        }

    async def test_updated_at_changes_only_where_data_changed(self, session: AsyncSession) -> None:
        device = await upsert_device(session, facts=_facts(), mgmt_ip=MGMT_IP, credential_id=None)
        artifact = await store_artifact(
            session,
            device_id=device.id,
            run_id=None,
            command="show interfaces",
            raw_text=RAW_OUTPUTS["show interfaces"],
            parsed=None,
        )
        await upsert_interfaces(session, device, _interface_pair(), artifact.id)
        await session.commit()

        async def _updated_at_by_name() -> dict[str, datetime]:
            rows = (
                (
                    await session.execute(
                        select(NormalizedInterfaceRow).execution_options(populate_existing=True)
                    )
                )
                .scalars()
                .all()
            )
            return {row.name: row.updated_at for row in rows}

        baseline = await _updated_at_by_name()

        # Identical re-upsert: nothing changed, so no row's updated_at moves.
        await upsert_interfaces(session, device, _interface_pair(), artifact.id)
        await session.commit()
        assert await _updated_at_by_name() == baseline

        # One interface flaps: only that row's updated_at moves.
        await upsert_interfaces(
            session,
            device,
            _interface_pair(oper_status=InterfaceOperStatus.DOWN),
            artifact.id,
        )
        await session.commit()
        after_change = await _updated_at_by_name()
        assert after_change["GigabitEthernet0/1"] == baseline["GigabitEthernet0/1"]
        assert after_change["GigabitEthernet0/2"] > baseline["GigabitEthernet0/2"]

    async def test_third_persist_with_changed_oper_status_updates_exactly_that_row(
        self, session: AsyncSession, run: DiscoveryRun
    ) -> None:
        result = _result(interfaces=_interface_pair())
        for _ in range(2):
            await persist_device_result(
                session, run=run, device_result=result, mgmt_ip=MGMT_IP, credential_id=None
            )
            await session.commit()
        before = await _snapshot(session)

        changed = _result(interfaces=_interface_pair(oper_status=InterfaceOperStatus.DOWN))
        counts = await persist_device_result(
            session, run=run, device_result=changed, mgmt_ip=MGMT_IP, credential_id=None
        )
        await session.commit()
        after = await _snapshot(session)

        # Same rows (identity preserved), no inserts on the third pass.
        assert set(after) == set(before)
        assert all(c["inserted"] == 0 for c in counts.values())

        differing = {row_id for row_id in before if before[row_id] != after[row_id]}
        assert len(differing) == 1, f"expected exactly one changed row, got {len(differing)}"
        (changed_id,) = differing
        changed_row = (
            await session.execute(
                select(NormalizedInterfaceRow).where(NormalizedInterfaceRow.id == changed_id)
            )
        ).scalar_one()
        assert changed_row.name == "GigabitEthernet0/2"
        assert changed_row.oper_status is InterfaceOperStatus.DOWN
