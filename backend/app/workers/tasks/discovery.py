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
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final, cast
from uuid import UUID

import structlog
from celery import chord, group
from celery.exceptions import Ignore, Reject, Retry
from pydantic import ValidationError
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core import metrics
from app.core.config import Settings, get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.core.errors import PluginError
from app.engines.discovery import engine as discovery_engine
from app.engines.discovery.engine import DeviceCollectionResult
from app.engines.discovery.expansion import next_wave
from app.engines.discovery.persistence import persist_device_result
from app.engines.discovery.planner import DiscoveryPlan
from app.models import Device, DiscoveryRun, DiscoveryRunStatus
from app.models.inventory import CredentialKind, DeviceCredential, RawArtifact
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
    netmiko_device_type,
)
from app.schemas.normalized import NormalizedNeighbor
from app.services import audit, credentials
from app.workers.celery_app import QUEUE_TOPOLOGY, celery_app
from app.workers.dispatch import durable_dispatch

__all__ = [
    "collect_device",
    "continue_discovery_wave",
    "purge_expired_artifacts",
    "run_discovery",
]

logger = structlog.get_logger(__name__)

#: Audit actor recorded for every credential decryption by these tasks.
_ACTOR = "worker:discovery"

#: Audit actor for the raw-artifact retention beat (parity with pcap retention).
_RETENTION_ACTOR = "system:retention"

#: Audit action for a raw-artifact retention sweep (one entry per run).
_RAW_ARTIFACT_PURGED = "raw_artifact.purged"

#: CLI capabilities collected once a vendor is detected, in order
#: (facts first: the engine keeps the first successful facts).
_CLI_CAPABILITIES: tuple[Capability, ...] = (
    Capability.DISCOVERY_SSH,
    Capability.INTERFACES,
    Capability.ROUTES,
    Capability.NEIGHBORS_LLDP,
    Capability.NEIGHBORS_CDP,
)


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one task phase (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


def _settings() -> Settings:
    """Process settings (seam: tests monkeypatch the returned instance)."""
    return get_settings()


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
) -> tuple[list[_MaterializedCredential], UUID, str | None]:
    """Load + decrypt the run's credentials and resolve the engine device id.

    Decryptions are audited with ``reason="discovery"`` (committed here so the
    audit trail survives even if collection subsequently fails). The returned
    device id is the existing inventory id for ``mgmt_ip`` when known, else a
    fresh placeholder (persistence keys rows on the upserted device anyway).

    When the inventory already has a device at *target_ip*, its ``vendor_id``
    is returned as a detection hint so SSH vendor try-order prefers the known
    driver (Wave 5 / perf #1).
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
                session,
                provider,
                row,
                actor=_ACTOR,
                reason="discovery",
                # ADR-0040 §2: no `target=` here — discovery is the path that
                # CREATES inventory, so a fully-resolved Device (with scope
                # attributes) does not yet exist at decrypt time. The run targets a
                # bare mgmt_ip; the device id is resolved AFTER this loop and may be a
                # fresh placeholder for a not-yet-inventoried device. Scope is
                # enforced on the SESSION-OPEN paths that act on a known device
                # (config backup, packet capture); discovery credentials are
                # operator-provisioned for a discovery run, not bound to a device.
                sessionmaker=credentials.autonomous_sessionmaker(session),
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
        device_row = (
            await session.execute(select(Device).where(Device.mgmt_ip == target_ip))
        ).scalar_one_or_none()
        await session.commit()  # decrypt audit rows
        preferred_vendor = device_row.vendor_id if device_row is not None else None
        device_id = device_row.id if device_row is not None else uuid.uuid4()
        return materialized, device_id, preferred_vendor


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


def _ssh_vendor_candidates(
    registry: PluginRegistry, preferred_vendor: str | None = None
) -> list[str]:
    """Order SSH discovery vendor ids: known vendor first, then registry order.

    Wave 5 / perf #1: a re-discovery of a known device should open ~1 SSH
    session with the correct driver instead of thrashing every registered
    vendor driver (each wrong ConnectHandler costs seconds).
    """
    candidates = [
        vid
        for vid in registry.vendor_ids()
        if registry.get_plugin(vid).supports(Capability.DISCOVERY_SSH)
    ]
    if preferred_vendor and preferred_vendor in candidates:
        rest = [v for v in candidates if v != preferred_vendor]
        return [preferred_vendor, *rest]
    return candidates


def _collect_over_ssh(
    registry: PluginRegistry,
    target_ip: str,
    creds: list[_MaterializedCredential],
    device_id: UUID,
    *,
    preferred_vendor: str | None = None,
) -> _CollectionOutcome:
    """Detect the vendor over SSH and collect every CLI capability it declares.

    Vendor try-order prefers *preferred_vendor* (prior inventory vendor_id)
    when set so rediscovery amortizes to one successful handshake.
    """
    outcome = _CollectionOutcome()
    vendor_order = _ssh_vendor_candidates(registry, preferred_vendor)
    for cred in creds:
        for vendor_id in vendor_order:
            plugin = registry.get_plugin(vendor_id)
            from app.plugins.transport import ssh_params_from

            params = ssh_params_from(
                host=target_ip,
                device_type=netmiko_device_type(vendor_id, cred.params),
                username=cred.username or "",
                password=cred.secret,
                cred_params=cred.params,
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
                    # Reuse this session for full collection (no second handshake).
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
    bind=True,
    name="discovery.collect_device",
    autoretry_for=(SshTransportError, SnmpTransportError),
    max_retries=2,
    retry_backoff=True,
)
def collect_device(
    self: Any,
    run_id: str,
    target_ip: str,
    credential_name: str | None = None,
) -> dict[str, Any]:
    """Contact *target_ip*, detect its vendor, collect, and persist.

    Returns a JSON-safe summary: ``ok``, ``target_ip``, ``vendor_id``,
    ``neighbors`` (serialized :class:`NormalizedNeighbor` records the run
    orchestrator expands from), ``capability_errors``, and per-type upsert
    ``counts``. Raises the last transport error when the device was never
    reached so Celery retries it (transient failure). After retries are
    exhausted, returns ``ok=False`` instead of raising so a wave **chord**
    still completes with partial results (Wave 5 / perf #2).

    Any *other* exception is folded into ``ok=False`` as well: a raised
    header task fails the whole chord and the ``continue_discovery_wave``
    body never runs, stranding the run in ``running`` forever.
    """
    try:
        return _collect_device_inner(self, run_id, target_ip, credential_name)
    except (SshTransportError, SnmpTransportError, Retry, Ignore, Reject):
        # Transport: autoretry_for retries these (retries-exhausted folds
        # inside). Retry/Ignore/Reject: Celery control flow, never folded
        # (PR 161 Task C).
        raise
    except Exception as exc:  # noqa: BLE001 — the chord body must always run
        logger.exception("discovery.collect_device_unexpected", run_id=run_id, target_ip=target_ip)
        return {
            "ok": False,
            "target_ip": target_ip,
            "error": f"{type(exc).__name__}: {exc}",
            "neighbors": [],
        }


def _collect_device_inner(
    self: Any,
    run_id: str,
    target_ip: str,
    credential_name: str | None,
) -> dict[str, Any]:
    """Body of :func:`collect_device` (wrapped by its chord-safety fold)."""
    run_uuid = uuid.UUID(run_id)
    creds, device_id, preferred_vendor = asyncio.run(_prepare(run_uuid, target_ip, credential_name))
    registry = _registry()
    ssh_creds = [c for c in creds if c.kind is CredentialKind.SSH]
    snmp_creds = [c for c in creds if c.kind in (CredentialKind.SNMP_V2C, CredentialKind.SNMP_V3)]

    outcome = _CollectionOutcome()
    transient: PluginError | None = None
    failures: list[str] = []
    if ssh_creds:
        outcome = _collect_over_ssh(
            registry,
            target_ip,
            ssh_creds,
            device_id,
            preferred_vendor=preferred_vendor,
        )
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
            # Chord-safe: after the last retry, fold into ok=False so the wave
            # callback still runs (Wave 5).
            max_retries = int(getattr(self, "max_retries", 0) or 0)
            retries = int(getattr(getattr(self, "request", None), "retries", 0) or 0)
            if retries >= max_retries:
                return {
                    "ok": False,
                    "target_ip": target_ip,
                    "error": f"{type(transient).__name__}: {transient}",
                    "neighbors": [],
                }
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


#: Terminal run statuses the body-failure safety net must never overwrite.
_TERMINAL_RUN_STATUSES: Final[frozenset[DiscoveryRunStatus]] = frozenset(
    {DiscoveryRunStatus.SUCCEEDED, DiscoveryRunStatus.PARTIAL, DiscoveryRunStatus.FAILED}
)


async def _fail_run_if_not_terminal(run_id: UUID, error: str) -> None:
    """Mark the run ``failed`` unless it already reached a terminal status.

    PR 161 Task C: the chord-body safety net finalizes a run whose body task
    raised. A run that already finished keeps its terminal status — the body
    failure then happened *after* finalize (e.g. dispatching the next wave or
    building the return payload) and must not regress the recorded outcome.
    """
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None or run.status in _TERMINAL_RUN_STATUSES:
            return
        run.status = DiscoveryRunStatus.FAILED
        run.error = error
        run.finished_at = utcnow()
        await session.commit()


def _fail_run_best_effort(run_id: str, error: str) -> None:
    """Best-effort ``failed`` finalize on a fresh loop + engine (guard support).

    Runs on its own ``asyncio.run`` and engine so the attempt does not depend
    on whatever broke the body task; a secondary failure is logged and
    swallowed — the caller re-raises the original exception regardless.
    """
    try:
        asyncio.run(_fail_run_if_not_terminal(uuid.UUID(run_id), error))
    except Exception:  # noqa: BLE001 — never mask the original body failure
        logger.exception("discovery.finalize_failed_error", run_id=run_id)


def _normalize_wave_results(raw_results: list[Any], wave: list[str]) -> list[dict[str, Any]]:
    """Fold chord/group header results into per-device summaries.

    Children that still raise (or return ExceptionInfo) become ``ok=False`` so
    one dead device degrades the run to ``partial`` instead of aborting it.
    """
    results: list[dict[str, Any]] = []
    # Chord may pass fewer/more if a member was revoked; zip to wave length.
    padded: list[Any] = list(raw_results) if raw_results is not None else []
    while len(padded) < len(wave):
        padded.append(None)
    for target, item in zip(wave, padded, strict=False):
        if isinstance(item, dict) and "ok" in item:
            results.append(item)
            continue
        if isinstance(item, BaseException):
            results.append(
                {
                    "ok": False,
                    "target_ip": target,
                    "error": f"{type(item).__name__}: {item}",
                    "neighbors": [],
                }
            )
            continue
        # Celery ExceptionInfo / unexpected shapes
        results.append(
            {
                "ok": False,
                "target_ip": target,
                "error": f"wave_member_failed: {type(item).__name__}: {item!r}",
                "neighbors": [],
            }
        )
    return results


def _finalize_discovery_run(
    run_id: str,
    stats: dict[str, Any],
    *,
    started_monotonic: float,
) -> dict[str, Any]:
    """Terminal status, metrics, topology trigger — shared by chord body."""
    run_uuid = uuid.UUID(run_id)
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
    metrics.observe_discovery_run(
        status=status.value, duration_seconds=time.monotonic() - started_monotonic
    )
    logger.info("discovery.run_finished", run_id=run_id, status=status.value)
    if status is not DiscoveryRunStatus.FAILED:
        _trigger_topology_sync(run_id)
    return {"run_id": run_id, "status": status.value, "stats": stats}


def _enqueue_discovery_wave(
    run_id: str,
    wave: list[str],
    *,
    hop: int,
    visited: list[str],
    stats: dict[str, Any],
    plan: dict[str, Any],
    started_monotonic: float,
) -> dict[str, Any]:
    """Dispatch one wave as a Celery chord (Wave 5 / perf #2).

    Header = per-device ``collect_device`` group; body =
    :func:`continue_discovery_wave` which either expands the next hop or
    finalizes the run. The orchestrator task **does not** ``.get()`` on
    children — it only schedules the chord, freeing the worker slot while
    collection runs. Under ``task_always_eager`` the chord runs inline and
    this function returns the body's final result for unit tests.
    """
    if not wave:
        return _finalize_discovery_run(run_id, stats, started_monotonic=started_monotonic)

    header = group(collect_device.s(run_id, target) for target in wave)
    body = continue_discovery_wave.s(
        run_id,
        hop,
        list(visited),
        stats,
        plan,
        list(wave),
        started_monotonic,
    )
    async_result = chord(header)(body)
    if celery_app.conf.task_always_eager:
        # Eager tests: resolve the full cascade synchronously for assertable
        # return values; production never blocks the orchestrator on children.
        return cast("dict[str, Any]", async_result.get(disable_sync_subtasks=True))
    return {
        "run_id": run_id,
        "status": DiscoveryRunStatus.RUNNING.value,
        "dispatched_wave": hop,
        "targets": list(wave),
    }


@celery_app.task(name="discovery.continue_wave")
def continue_discovery_wave(
    results: list[Any],
    run_id: str,
    hop: int,
    visited: list[str],
    stats: dict[str, Any],
    plan: dict[str, Any],
    wave: list[str],
    started_monotonic: float,
) -> dict[str, Any]:
    """Chord body: fold one wave's results, expand or finalize (Wave 5).

    Signature is Celery-chord style: the header results list is the first
    positional argument, then the bound continuation state.

    Safety net (PR 161 Task C): with global ``acks_late`` and no ``link_error``
    a chord body that raises is acked and never redelivered, so the run row
    would strand in ``running`` forever. Any unexpected exception best-effort
    finalizes the run as ``failed`` (never clobbering an already-terminal
    status) and then re-raises so Celery still records the task failure.
    """
    try:
        return _continue_discovery_wave_inner(
            results, run_id, hop, visited, stats, plan, wave, started_monotonic
        )
    except (Retry, Ignore, Reject):
        raise  # celery control flow, not a body failure
    except Exception as exc:
        logger.exception("discovery.continue_wave_unexpected", run_id=run_id, hop=hop)
        _fail_run_best_effort(run_id, f"continue_discovery_wave: {type(exc).__name__}: {exc}")
        raise


def _continue_discovery_wave_inner(
    results: list[Any],
    run_id: str,
    hop: int,
    visited: list[str],
    stats: dict[str, Any],
    plan: dict[str, Any],
    wave: list[str],
    started_monotonic: float,
) -> dict[str, Any]:
    """Body of :func:`continue_discovery_wave` (wrapped by its safety net)."""
    run_uuid = uuid.UUID(run_id)
    hop_limit = int(plan["hop_limit"])
    allowlist = list(plan["allowlist"])
    normalized = _normalize_wave_results(results, wave)
    visited_set = set(visited)
    visited_set.update(wave)

    succeeded = [r for r in normalized if r.get("ok")]
    failed = [r for r in normalized if not r.get("ok")]
    stats = copy.deepcopy(stats)
    stats["devices_succeeded"] = int(stats.get("devices_succeeded", 0)) + len(succeeded)
    stats["devices_failed"] = int(stats.get("devices_failed", 0)) + len(failed)
    waves = list(stats.get("waves") or [])
    waves.append(
        {
            "hop": hop,
            "targets": list(wave),
            "succeeded": len(succeeded),
            "failed": len(failed),
        }
    )
    stats["waves"] = waves
    asyncio.run(_record_stats(run_uuid, stats))
    logger.info(
        "discovery.wave_completed",
        run_id=run_id,
        hop=hop,
        targets=len(wave),
        succeeded=len(succeeded),
        failed=len(failed),
    )

    if hop >= hop_limit:
        return _finalize_discovery_run(run_id, stats, started_monotonic=started_monotonic)

    neighbors = [
        NormalizedNeighbor.model_validate(item)
        for summary in succeeded
        for item in summary.get("neighbors", [])
    ]
    next_targets = next_wave(neighbors, visited_set, allowlist)
    if not next_targets:
        return _finalize_discovery_run(run_id, stats, started_monotonic=started_monotonic)

    return _enqueue_discovery_wave(
        run_id,
        next_targets,
        hop=hop + 1,
        visited=sorted(visited_set),
        stats=stats,
        plan=plan,
        started_monotonic=started_monotonic,
    )


@celery_app.task(name="discovery.run")
def run_discovery(run_id: str) -> dict[str, Any]:
    """Execute one discovery run: seed waves, bounded expansion, lifecycle.

    Wave ``hop`` 0 is the seeds; expansion to wave ``hop+1`` happens while
    ``hop < hop_limit`` using the LLDP/CDP neighbor addresses returned by the
    wave's ``collect_device`` tasks, deduplicated against visited targets and
    bounded by the subnet allowlist (:func:`next_wave`).

    Wave 5 / perf #2: fan-out uses Celery **chords** so this orchestrator does
    not hold a worker pool slot while children run (no blocking
    ``.get(disable_sync_subtasks=False)``). Continuation lives in
    :func:`continue_discovery_wave`.
    """
    run_uuid = uuid.UUID(run_id)
    started_monotonic = time.monotonic()
    plan = asyncio.run(_start_run(run_uuid))
    if plan is None:
        # The run never left planning (e.g. it was already terminal / unknown): a
        # failed terminal state with no measurable run duration (ADR-0046 §1).
        metrics.observe_discovery_run(status=DiscoveryRunStatus.FAILED.value)
        return {"run_id": run_id, "status": DiscoveryRunStatus.FAILED.value}
    logger.info("discovery.run_started", run_id=run_id, seeds=plan.seeds, hop_limit=plan.hop_limit)

    plan_dict = plan.model_dump(mode="json")
    stats: dict[str, Any] = {"waves": [], "devices_succeeded": 0, "devices_failed": 0}
    return _enqueue_discovery_wave(
        run_id,
        list(plan.seeds),
        hop=0,
        visited=[],
        stats=stats,
        plan=plan_dict,
        started_monotonic=started_monotonic,
    )


def _trigger_topology_sync(run_id: str) -> None:
    """Enqueue ``topology.sync_after_run`` for *run_id* (best-effort dispatch).

    Dispatched by task name (``send_task``) so the discovery module never
    imports the topology task module. A dispatch error (broker hiccup) is
    logged and swallowed — the run is already finished and must not regress.
    """
    try:
        durable_dispatch(
            task_name="topology.sync_after_run",
            args=[run_id],
            queue=QUEUE_TOPOLOGY,
        )
        logger.info("discovery.topology_sync_enqueued", run_id=run_id)
    except Exception:  # dispatch failures must not fail an already-finished run
        logger.warning("discovery.topology_sync_dispatch_failed", run_id=run_id)


# ---------------------------------------------------------------------------
# Task: discovery.purge_expired_artifacts (raw-artifact retention beat)
# ---------------------------------------------------------------------------


async def _purge_artifacts(cutoff: datetime) -> int:
    """Hard-delete raw_artifacts created before *cutoff*, audited; return count.

    ``raw_artifacts`` hold verbatim device CLI output — potentially
    credential-bearing text (D11) — and, unlike a pcap (whose metadata row is the
    surviving audit fact), the artifact row *is* the sensitive payload, so it is
    removed outright. The retention sweep is summarized in one audit row: the
    deleted count and the cutoff, never any captured device text.
    """
    async with _session() as session:
        count = (
            await session.execute(
                select(func.count()).select_from(RawArtifact).where(RawArtifact.created_at < cutoff)
            )
        ).scalar_one()
        if count:
            await session.execute(delete(RawArtifact).where(RawArtifact.created_at < cutoff))
        await audit.record(
            session,
            actor=_RETENTION_ACTOR,
            action=_RAW_ARTIFACT_PURGED,
            target_type="raw_artifacts",
            target_id=None,
            detail={"purged": int(count), "cutoff": cutoff.isoformat()},
        )
        await session.commit()
    return int(count)


@celery_app.task(name="discovery.purge_expired_artifacts")
def purge_expired_artifacts() -> dict[str, Any]:
    """Retention beat: hard-delete raw_artifacts past the retention window.

    Computes ``cutoff = now - raw_artifact_retention_days``, deletes every
    ``raw_artifacts`` row older than the cutoff, and records one audit entry for
    the sweep (actor=system/retention, action=``raw_artifact.purged``, count +
    cutoff). A retention of ``0`` days disables the purge (keep-forever policy):
    the task no-ops and returns ``disabled=True`` without deleting or auditing.
    """
    settings = _settings()
    days = settings.raw_artifact_retention_days
    if days <= 0:
        logger.info("discovery.artifact_retention_disabled")
        return {"purged": 0, "disabled": True}

    cutoff = utcnow() - timedelta(days=days)
    purged = asyncio.run(_purge_artifacts(cutoff))
    logger.info("discovery.artifact_retention_run", purged=purged, cutoff=cutoff.isoformat())
    return {"purged": purged, "cutoff": cutoff.isoformat()}
