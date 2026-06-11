"""Celery discovery tasks (M1-14): run fan-out with retries + run lifecycle.

Two tasks on the ``discovery`` queue (routed by name prefix, ADR-0008 D8):

- ``discovery.run`` — orchestrates one :class:`~app.models.DiscoveryRun`:
  marks it ``running``, builds the validated :class:`DiscoveryPlan`, then
  dispatches per-device ``discovery.collect_device`` tasks as a Celery group
  per wave, feeding collected LLDP/CDP neighbor addresses through
  :func:`~app.engines.discovery.expansion.next_wave` until ``hop_limit`` is
  reached or no new targets remain. ``run.stats`` is persisted after every
  wave; the final status is ``succeeded`` / ``partial`` / ``failed`` with
  ``finished_at`` stamped.

- ``discovery.collect_device`` — contacts one target. Vendor detection
  DECISION (fixed): try SSH facts with each configured credential of kind
  ``ssh`` against each registered plugin declaring ``DISCOVERY_SSH``; the
  ``vendor_id`` of the first successfully parsed :class:`DeviceFacts`
  selects the plugin via the registry, and full CLI collection runs over
  the same session. When SSH never connects and an SNMP credential is
  configured, SNMP discovery (facts only) is the fallback. Transient
  transport failures (``SshTransportError`` / ``SnmpTransportError`` with
  no successful connection) are raised so Celery's ``autoretry_for``
  retries with backoff (``max_retries=2``); permanent failures (reachable
  but unrecognizable device, no usable credentials) return ``ok=False``
  without retry so the run can finish ``partial``.

Credential material conventions (D11): for ``snmp_v2c`` the decrypted secret
is the community string; for ``snmp_v3`` it is a JSON object
``{"auth_key": ..., "priv_key": ...}`` with non-secret protocol names in
``DeviceCredential.params`` (``auth_protocol``/``priv_protocol``). Secrets
exist in memory only inside :class:`_MaterializedCredential` (redacted
``repr``) and are never logged or embedded in results/exceptions.

Async DB from sync Celery: every task phase wraps its DB work in
``asyncio.run`` with a fresh engine per invocation (event loops do not
outlive a task, so connections must not either). Module-level seams
(``_make_engine``, ``_registry``, ``_key_provider``, ``_open_ssh``,
``_make_snmp_client``) exist so unit tests can run everything eagerly with
fakes.
"""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, cast
from uuid import UUID

import structlog
from celery import group
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core.config import get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.core.errors import PluginError
from app.engines.discovery import engine as discovery_engine
from app.engines.discovery.engine import DeviceCollectionResult
from app.engines.discovery.expansion import next_wave
from app.engines.discovery.persistence import persist_device_result
from app.engines.discovery.planner import DiscoveryPlan
from app.models import Device, DiscoveryRun, DiscoveryRunStatus
from app.models.inventory import CredentialKind, DeviceCredential
from app.models.mixins import utcnow
from app.plugins.base import (
    Capability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    PluginCapability,
    TransportKind,
    VendorPlugin,
)
from app.plugins.registry import PluginRegistry, get_default_registry
from app.plugins.transport import (
    SnmpAuthProtocol,
    SnmpClient,
    SnmpPrivProtocol,
    SnmpTransportError,
    SnmpV2cParams,
    SnmpV3Params,
    SshParams,
    SshTransport,
    SshTransportError,
)
from app.schemas.normalized import NormalizedNeighbor
from app.services import credentials
from app.workers.celery_app import celery_app

__all__ = ["collect_device", "run_discovery"]

logger = structlog.get_logger(__name__)

#: Audit actor recorded for every credential decryption by these tasks.
_ACTOR = "worker:discovery"

#: CLI capabilities collected once a vendor is detected, in order
#: (facts first: the engine keeps the first successful facts).
_CLI_CAPABILITIES: tuple[Capability, ...] = (
    Capability.DISCOVERY_SSH,
    Capability.INTERFACES,
    Capability.ROUTES,
    Capability.NEIGHBORS_LLDP,
    Capability.NEIGHBORS_CDP,
)

#: vendor_id -> netmiko ``device_type`` used for the detection connection.
_NETMIKO_DEVICE_TYPES: dict[str, str] = {
    "cisco_ios": "cisco_ios",
    "cisco_iosxe": "cisco_xe",
    "eos": "arista_eos",
}


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one task phase (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


def _registry() -> PluginRegistry:
    """The plugin registry consulted for vendor detection and collection."""
    return get_default_registry()


def _key_provider() -> KeyProvider:
    """The KEK provider used to decrypt vault credentials."""
    return get_key_provider(get_settings())


def _open_ssh(params: SshParams) -> SshTransport:
    """Context-managed SSH transport for *params* (netmiko-backed)."""
    return SshTransport(params)


def _make_snmp_client(params: SnmpV2cParams | SnmpV3Params) -> SnmpClient:
    """SNMP read client for *params* (pysnmp-backed)."""
    return SnmpClient(params)


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    """One AsyncSession on a fresh engine, disposed when the phase ends."""
    engine = _make_engine()
    try:
        async with db.create_sessionmaker(engine)() as session:
            yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Credential materialization
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class _MaterializedCredential:
    """A decrypted vault credential held in memory for one collection only."""

    id: UUID
    name: str
    kind: CredentialKind
    username: str | None
    secret: str
    params: dict[str, Any]

    def __repr__(self) -> str:  # secret never rendered
        return f"<_MaterializedCredential name={self.name!r} kind={self.kind!s}>"


async def _prepare(
    run_id: UUID, target_ip: str, credential_name: str | None
) -> tuple[list[_MaterializedCredential], UUID]:
    """Load + decrypt the run's credentials and resolve the engine device id.

    Decryptions are audited with ``reason="discovery"`` (committed here so the
    audit trail survives even if collection subsequently fails). The returned
    device id is the existing inventory id for ``mgmt_ip`` when known, else a
    fresh placeholder (persistence keys rows on the upserted device anyway).
    """
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            raise ValueError(f"discovery run {run_id} does not exist")
        names = [credential_name] if credential_name is not None else list(run.credential_names)
        provider = _key_provider()
        materialized: list[_MaterializedCredential] = []
        for name in names:
            row = (
                await session.execute(select(DeviceCredential).where(DeviceCredential.name == name))
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "discovery.credential_missing", run_id=str(run_id), credential_name=name
                )
                continue
            secret = await credentials.decrypt(
                session, provider, row, actor=_ACTOR, reason="discovery"
            )
            materialized.append(
                _MaterializedCredential(
                    id=row.id,
                    name=row.name,
                    kind=row.kind,
                    username=row.username,
                    secret=secret.plaintext.decode("utf-8"),
                    params=dict(row.params or {}),
                )
            )
        device_id = (
            await session.execute(select(Device.id).where(Device.mgmt_ip == target_ip))
        ).scalar_one_or_none()
        await session.commit()  # decrypt audit rows
        return materialized, device_id or uuid.uuid4()


async def _persist(
    run_id: UUID, target_ip: str, result: DeviceCollectionResult, credential_id: UUID | None
) -> dict[str, Any]:
    """Persist one device's collection through the M1-13 pipeline."""
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            raise ValueError(f"discovery run {run_id} does not exist")
        counts = await persist_device_result(
            session,
            run=run,
            device_result=result,
            mgmt_ip=target_ip,
            credential_id=credential_id,
        )
        await session.commit()
        return cast("dict[str, Any]", counts)


# ---------------------------------------------------------------------------
# Vendor detection + collection (sync, no DB)
# ---------------------------------------------------------------------------


@dataclass
class _CollectionOutcome:
    """What one protocol family's detection/collection pass produced."""

    result: DeviceCollectionResult | None = None
    credential_id: UUID | None = None
    connected: bool = False
    transport_error: PluginError | None = None
    failures: list[str] = field(default_factory=list)


def _instantiate(
    plugin: VendorPlugin, capability: Capability, transport: object, device_id: UUID
) -> PluginCapability:
    """Instantiate *plugin*'s implementation of *capability* over *transport*."""
    impl_cls = plugin.get_capability(capability)
    ctor = cast("Callable[[object, UUID], PluginCapability]", impl_cls)
    return ctor(transport, device_id)


def _collect_over_ssh(
    registry: PluginRegistry,
    target_ip: str,
    creds: list[_MaterializedCredential],
    device_id: UUID,
) -> _CollectionOutcome:
    """Detect the vendor over SSH and collect every CLI capability it declares."""
    outcome = _CollectionOutcome()
    for cred in creds:
        for vendor_id in registry.vendor_ids():
            plugin = registry.get_plugin(vendor_id)
            if not plugin.supports(Capability.DISCOVERY_SSH):
                continue
            params = SshParams(
                host=target_ip,
                device_type=str(
                    cred.params.get("device_type")
                    or _NETMIKO_DEVICE_TYPES.get(vendor_id, vendor_id)
                ),
                username=cred.username or "",
                password=cred.secret,
                port=int(cred.params.get("port", 22)),
            )
            try:
                with _open_ssh(params) as transport:
                    outcome.connected = True
                    probe = _instantiate(plugin, Capability.DISCOVERY_SSH, transport, device_id)
                    if not isinstance(probe, DiscoverySshCapability):
                        raise PluginError(f"{type(probe).__name__} is not a DiscoverySshCapability")
                    facts = probe.get_device_facts()
                    detected = registry.get_plugin(facts.vendor_id)
                    capabilities = [c for c in _CLI_CAPABILITIES if detected.supports(c)]
                    result = discovery_engine.collect_device(
                        detected,
                        {TransportKind.SSH: transport},
                        capabilities,
                        device_id=device_id,
                    )
                    if result.facts is None:
                        outcome.failures.append(
                            f"ssh {cred.name}/{facts.vendor_id}: collection lost device facts"
                        )
                        continue
                    outcome.result = result
                    outcome.credential_id = cred.id
                    return outcome
            except SshTransportError as exc:
                outcome.transport_error = exc
                outcome.failures.append(f"ssh {cred.name}/{vendor_id}: {type(exc).__name__}")
                continue
            except PluginError as exc:
                outcome.failures.append(f"ssh {cred.name}/{vendor_id}: {type(exc).__name__}: {exc}")
                continue
    return outcome


def _snmp_params(target_ip: str, cred: _MaterializedCredential) -> SnmpV2cParams | SnmpV3Params:
    """Build SNMP transport params from a materialized vault credential."""
    port = int(cred.params.get("port", 161))
    if cred.kind is CredentialKind.SNMP_V2C:
        return SnmpV2cParams(host=target_ip, community=cred.secret, port=port)
    payload = json.loads(cred.secret)
    if not isinstance(payload, dict) or "auth_key" not in payload or "priv_key" not in payload:
        raise ValueError("SNMPv3 secret must be a JSON object with auth_key and priv_key")
    return SnmpV3Params(
        host=target_ip,
        user=cred.username or "",
        auth_key=str(payload["auth_key"]),
        priv_key=str(payload["priv_key"]),
        auth_protocol=SnmpAuthProtocol(
            str(cred.params.get("auth_protocol", SnmpAuthProtocol.SHA.value))
        ),
        priv_protocol=SnmpPrivProtocol(
            str(cred.params.get("priv_protocol", SnmpPrivProtocol.AES128.value))
        ),
        port=port,
    )


def _collect_over_snmp(
    registry: PluginRegistry,
    target_ip: str,
    creds: list[_MaterializedCredential],
    device_id: UUID,
) -> _CollectionOutcome:
    """SNMP fallback: detect the vendor from system-MIB facts (facts only)."""
    outcome = _CollectionOutcome()
    for cred in creds:
        try:
            params = _snmp_params(target_ip, cred)
        except ValueError as exc:
            outcome.failures.append(
                f"snmp {cred.name}: unusable credential material ({type(exc).__name__})"
            )
            continue
        client = _make_snmp_client(params)
        for vendor_id in registry.vendor_ids():
            plugin = registry.get_plugin(vendor_id)
            if not plugin.supports(Capability.DISCOVERY_SNMP):
                continue
            try:
                probe = _instantiate(plugin, Capability.DISCOVERY_SNMP, client, device_id)
                if not isinstance(probe, DiscoverySnmpCapability):
                    raise PluginError(f"{type(probe).__name__} is not a DiscoverySnmpCapability")
                facts = probe.get_device_facts()
                detected = registry.get_plugin(facts.vendor_id)
                result = discovery_engine.collect_device(
                    detected,
                    {TransportKind.SNMP: client},
                    [Capability.DISCOVERY_SNMP],
                    device_id=device_id,
                )
                if result.facts is None:
                    outcome.failures.append(
                        f"snmp {cred.name}/{facts.vendor_id}: collection lost device facts"
                    )
                    continue
                outcome.connected = True
                outcome.result = result
                outcome.credential_id = cred.id
                return outcome
            except SnmpTransportError as exc:
                outcome.transport_error = exc
                outcome.failures.append(f"snmp {cred.name}/{vendor_id}: {type(exc).__name__}")
                break  # the same client will fail identically for every vendor
            except PluginError as exc:
                outcome.failures.append(
                    f"snmp {cred.name}/{vendor_id}: {type(exc).__name__}: {exc}"
                )
                continue
    return outcome


# ---------------------------------------------------------------------------
# Task: discovery.collect_device
# ---------------------------------------------------------------------------


@celery_app.task(
    name="discovery.collect_device",
    autoretry_for=(SshTransportError, SnmpTransportError),
    max_retries=2,
    retry_backoff=True,
)
def collect_device(
    run_id: str, target_ip: str, credential_name: str | None = None
) -> dict[str, Any]:
    """Contact *target_ip*, detect its vendor, collect, and persist.

    Returns a JSON-safe summary: ``ok``, ``target_ip``, ``vendor_id``,
    ``neighbors`` (serialized :class:`NormalizedNeighbor` records the run
    orchestrator expands from), ``capability_errors``, and per-type upsert
    ``counts``. Raises the last transport error when the device was never
    reached over any protocol so Celery retries it (transient failure).
    """
    run_uuid = uuid.UUID(run_id)
    creds, device_id = asyncio.run(_prepare(run_uuid, target_ip, credential_name))
    registry = _registry()
    ssh_creds = [c for c in creds if c.kind is CredentialKind.SSH]
    snmp_creds = [c for c in creds if c.kind in (CredentialKind.SNMP_V2C, CredentialKind.SNMP_V3)]

    outcome = _CollectionOutcome()
    transient: PluginError | None = None
    failures: list[str] = []
    if ssh_creds:
        outcome = _collect_over_ssh(registry, target_ip, ssh_creds, device_id)
        failures.extend(outcome.failures)
        if outcome.result is None and not outcome.connected:
            transient = outcome.transport_error
    if outcome.result is None and not outcome.connected and snmp_creds:
        outcome = _collect_over_snmp(registry, target_ip, snmp_creds, device_id)
        failures.extend(outcome.failures)
        if outcome.result is None:
            transient = outcome.transport_error or transient

    result = outcome.result
    if result is None or result.facts is None:
        if transient is not None:
            logger.warning(
                "discovery.device_unreachable",
                run_id=run_id,
                target_ip=target_ip,
                error_type=type(transient).__name__,
            )
            raise transient
        error = "; ".join(failures) or "no usable credentials configured for this run"
        logger.warning("discovery.device_failed", run_id=run_id, target_ip=target_ip, error=error)
        return {"ok": False, "target_ip": target_ip, "error": error, "neighbors": []}

    counts = asyncio.run(_persist(run_uuid, target_ip, result, outcome.credential_id))
    logger.info(
        "discovery.device_collected",
        run_id=run_id,
        target_ip=target_ip,
        vendor_id=result.facts.vendor_id,
        neighbors=len(result.neighbors),
        capability_errors=len(result.errors),
    )
    return {
        "ok": True,
        "target_ip": target_ip,
        "vendor_id": result.facts.vendor_id,
        "hostname": result.facts.hostname,
        "neighbors": [n.model_dump(mode="json") for n in result.neighbors],
        "capability_errors": {cap.value: msg for cap, msg in result.errors.items()},
        "counts": counts,
    }


# ---------------------------------------------------------------------------
# Task: discovery.run (wave orchestration)
# ---------------------------------------------------------------------------


async def _start_run(run_id: UUID) -> DiscoveryPlan | None:
    """Transition the run to ``running`` and build its validated plan.

    Returns ``None`` (after persisting ``failed`` + ``finished_at``) when the
    stored parameters do not form a valid :class:`DiscoveryPlan`.
    """
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            raise ValueError(f"discovery run {run_id} does not exist")
        run.status = DiscoveryRunStatus.RUNNING
        run.started_at = utcnow()
        plan: DiscoveryPlan | None
        try:
            plan = DiscoveryPlan(
                seeds=list(run.seeds),
                hop_limit=run.hop_limit,
                allowlist=list(run.allowlist),
                credential_names=list(run.credential_names),
            )
        except ValidationError as exc:
            run.status = DiscoveryRunStatus.FAILED
            run.error = f"invalid run parameters: {exc.error_count()} validation error(s)"
            run.finished_at = utcnow()
            plan = None
            logger.warning("discovery.run_invalid", run_id=str(run_id), errors=run.error)
        await session.commit()
        return plan


async def _record_stats(run_id: UUID, stats: dict[str, Any]) -> None:
    """Persist a snapshot of *stats* onto the run (after every wave)."""
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            raise ValueError(f"discovery run {run_id} does not exist")
        run.stats = copy.deepcopy(stats)
        await session.commit()


async def _finish_run(
    run_id: UUID, status: DiscoveryRunStatus, stats: dict[str, Any], error: str | None
) -> None:
    """Finalize the run: terminal status, stats, error, ``finished_at``."""
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            raise ValueError(f"discovery run {run_id} does not exist")
        run.status = status
        run.stats = copy.deepcopy(stats)
        run.error = error
        run.finished_at = utcnow()
        await session.commit()


def _dispatch_wave(run_id: str, wave: list[str]) -> list[dict[str, Any]]:
    """Fan one wave out as a Celery group and gather per-device summaries.

    A child task that exhausted its retries surfaces here as an exception;
    it is folded into an ``ok=False`` summary so one dead device degrades
    the run to ``partial`` instead of aborting it.
    """
    job = group(collect_device.s(run_id, target) for target in wave)
    group_result = job.apply_async()
    results: list[dict[str, Any]] = []
    for target, child in zip(wave, group_result.results, strict=True):
        try:
            results.append(child.get(disable_sync_subtasks=False))
        except Exception as exc:
            # Transport errors carry coordinates + exception class only (D11).
            results.append(
                {
                    "ok": False,
                    "target_ip": target,
                    "error": f"{type(exc).__name__}: {exc}",
                    "neighbors": [],
                }
            )
    return results


@celery_app.task(name="discovery.run")
def run_discovery(run_id: str) -> dict[str, Any]:
    """Execute one discovery run: seed waves, bounded expansion, lifecycle.

    Wave ``hop`` 0 is the seeds; expansion to wave ``hop+1`` happens while
    ``hop < hop_limit`` using the LLDP/CDP neighbor addresses returned by the
    wave's ``collect_device`` tasks, deduplicated against visited targets and
    bounded by the subnet allowlist (:func:`next_wave`).
    """
    run_uuid = uuid.UUID(run_id)
    plan = asyncio.run(_start_run(run_uuid))
    if plan is None:
        return {"run_id": run_id, "status": DiscoveryRunStatus.FAILED.value}
    logger.info("discovery.run_started", run_id=run_id, seeds=plan.seeds, hop_limit=plan.hop_limit)

    visited: set[str] = set()
    wave = list(plan.seeds)
    hop = 0
    stats: dict[str, Any] = {"waves": [], "devices_succeeded": 0, "devices_failed": 0}
    while wave:
        results = _dispatch_wave(run_id, wave)
        visited.update(wave)
        succeeded = [r for r in results if r.get("ok")]
        failed = [r for r in results if not r.get("ok")]
        stats["devices_succeeded"] += len(succeeded)
        stats["devices_failed"] += len(failed)
        stats["waves"].append(
            {
                "hop": hop,
                "targets": list(wave),
                "succeeded": len(succeeded),
                "failed": len(failed),
            }
        )
        asyncio.run(_record_stats(run_uuid, stats))
        logger.info(
            "discovery.wave_completed",
            run_id=run_id,
            hop=hop,
            targets=len(wave),
            succeeded=len(succeeded),
            failed=len(failed),
        )
        if hop >= plan.hop_limit:
            break
        neighbors = [
            NormalizedNeighbor.model_validate(item)
            for summary in succeeded
            for item in summary.get("neighbors", [])
        ]
        wave = next_wave(neighbors, visited, plan.allowlist)
        hop += 1

    if stats["devices_succeeded"] == 0:
        status = DiscoveryRunStatus.FAILED
        error: str | None = "no device could be discovered"
    elif stats["devices_failed"] > 0:
        status = DiscoveryRunStatus.PARTIAL
        error = None
    else:
        status = DiscoveryRunStatus.SUCCEEDED
        error = None
    asyncio.run(_finish_run(run_uuid, status, stats, error))
    logger.info("discovery.run_finished", run_id=run_id, status=status.value)
    return {"run_id": run_id, "status": status.value, "stats": stats}
