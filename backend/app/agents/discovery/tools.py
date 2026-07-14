"""Discovery Agent typed tool wrappers (M3-12).

All tools are classified READ_ONLY — launching a discovery run is a
read-only job-launch that queues asynchronous work but changes no device
state (DECISIONS-BRIEF §5, MVP.md §5 M3 in-scope note).

Module boundary: these wrappers use the framework read/job seams for
persistence. The discovery planner and established Celery dispatch signature
remain explicit direct operational edges with named burn-down owners.

Each tool accepts a plain-data payload (primitives or simple dicts
suitable for JSON serialisation over the LangGraph tool protocol) and
returns a JSON-serialisable string so the model can consume it directly.
Operational imports are deferred inside the job-launch coroutine so tools can
be unit-tested without those layers being loaded.
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated
from uuid import UUID

from pydantic import Field

from app.agents.framework.discovery_jobs import (
    create_discovery_run,
    mark_discovery_run_failed,
)
from app.agents.framework.read_facade import (
    UnknownDeviceStatus,
)
from app.agents.framework.read_facade import (
    get_device as read_device,
)
from app.agents.framework.read_facade import (
    list_devices as read_devices,
)
from app.agents.framework.read_facade import (
    list_neighbors as read_neighbors,
)
from app.agents.framework.tools import ToolClassification, netops_tool

# ---------------------------------------------------------------------------
# trigger_discovery_run
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def trigger_discovery_run(
    seeds: Annotated[
        list[str],
        Field(description="IP addresses of the seed devices to start discovery from."),
    ],
    hop_limit: Annotated[
        int,
        Field(
            ge=0,
            description="Maximum LLDP/CDP expansion hops from the seeds (0 = seeds only).",
        ),
    ],
    allowlist: Annotated[
        list[str],
        Field(description="CIDR networks the discovery engine is allowed to touch."),
    ],
    credential_names: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Vault credential names to attempt against discovered devices.",
        ),
    ] = None,
) -> str:
    """Enqueue a discovery run starting from the given seed IP addresses.

    The run executes asynchronously on the ``discovery`` Celery queue; this
    tool returns immediately with the new run's UUID and ``pending`` status.
    Use ``get_device`` or ``list_devices`` to inspect the results after the
    run completes.  Classified READ_ONLY because this is a read-only
    job-launch: no device configuration is modified.
    """
    # Deferred imports keep the module boundary visible and allow lightweight
    # unit tests that do not need a running DB or Celery.
    from app.engines.discovery.planner import DiscoveryPlan
    from app.workers.celery_app import QUEUE_DISCOVERY, celery_app

    plan = DiscoveryPlan(
        seeds=seeds,
        hop_limit=hop_limit,
        allowlist=allowlist,
        credential_names=credential_names or [],
    )
    run_id, status = await create_discovery_run(
        seeds=plan.seeds,
        hop_limit=plan.hop_limit,
        allowlist=plan.allowlist,
        credential_names=plan.credential_names,
    )

    # Celery's send_task performs synchronous broker I/O (TCP round-trip).
    # Wrapping it in run_in_executor keeps the asyncio event loop unblocked
    # (D2: async-first platform contract).
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: celery_app.send_task("discovery.run", args=[run_id], queue=QUEUE_DISCOVERY),
        )
    except Exception as exc:
        # Broker unreachable / serialization error: mark the already-committed
        # run row as FAILED so the UI never shows a permanently-pending orphan.
        await mark_discovery_run_failed(run_id, str(exc))
        raise

    return json.dumps({"run_id": run_id, "status": status})


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def list_devices(
    status_filter: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional device status to filter by "
                "(e.g. 'reachable', 'unreachable', 'new'). "
                "Omit to return all devices."
            ),
        ),
    ] = None,
    vendor_id: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional vendor_id to filter by (e.g. 'cisco_ios', 'eos'). "
                "Omit to return all vendors."
            ),
        ),
    ] = None,
    limit: Annotated[
        int,
        Field(ge=1, le=500, description="Maximum number of devices to return."),
    ] = 50,
    offset: Annotated[
        int,
        Field(ge=0, description="Pagination offset."),
    ] = 0,
) -> str:
    """List inventory devices, optionally filtered by status or vendor.

    Returns a JSON object with ``total``, ``limit``, ``offset`` and an
    ``items`` list where each entry contains id, hostname, mgmt_ip,
    vendor_id, status, and last_discovered_at.
    """
    try:
        total, rows = await read_devices(
            status_filter=status_filter,
            vendor_id=vendor_id,
            limit=limit,
            offset=offset,
        )
    except UnknownDeviceStatus as exc:
        return json.dumps({"error": str(exc)})

    items = [
        {
            "id": str(d.id),
            "hostname": d.hostname,
            "mgmt_ip": d.mgmt_ip,
            "vendor_id": d.vendor_id,
            "status": d.status,
            "last_discovered_at": (
                d.last_discovered_at.isoformat() if d.last_discovered_at else None
            ),
        }
        for d in rows
    ]
    return json.dumps({"total": total, "limit": limit, "offset": offset, "items": items})


# ---------------------------------------------------------------------------
# get_device
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def get_device(
    device_id: Annotated[
        str,
        Field(description="UUID of the device to retrieve."),
    ],
) -> str:
    """Retrieve full details for one inventory device by its UUID.

    Returns a JSON object with all scalar device fields, or a JSON error
    object when the device does not exist.
    """
    try:
        uid = UUID(device_id)
    except ValueError:
        return json.dumps({"error": f"invalid UUID: {device_id!r}"})

    device = await read_device(uid)
    if device is None:
        return json.dumps({"error": f"device {device_id} not found"})
    return json.dumps(
        {
            "id": str(device.id),
            "hostname": device.hostname,
            "mgmt_ip": device.mgmt_ip,
            "vendor_id": device.vendor_id,
            "model": device.model,
            "os_version": device.os_version,
            "serial": device.serial,
            "status": device.status,
            "site": device.site,
            "last_discovered_at": (
                device.last_discovered_at.isoformat() if device.last_discovered_at else None
            ),
            "created_at": device.created_at.isoformat(),
            "updated_at": device.updated_at.isoformat(),
        }
    )


# ---------------------------------------------------------------------------
# query_neighbors
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def query_neighbors(
    device_id: Annotated[
        str,
        Field(description="UUID of the device whose neighbors to query."),
    ],
) -> str:
    """List the normalized LLDP/CDP neighbors discovered for a device.

    Returns a JSON object with ``device_id`` and a ``neighbors`` list where
    each entry contains protocol, local_interface, neighbor_name,
    neighbor_interface, neighbor_platform, neighbor_address, and
    neighbor_capabilities.
    """
    try:
        uid = UUID(device_id)
    except ValueError:
        return json.dumps({"error": f"invalid UUID: {device_id!r}"})

    device, rows = await read_neighbors(uid)
    if device is None:
        return json.dumps({"error": f"device {device_id} not found"})

    neighbors = [
        {
            "protocol": row.protocol,
            "local_interface": row.local_interface,
            "neighbor_name": row.neighbor_name,
            "neighbor_interface": row.neighbor_interface or None,
            "neighbor_platform": row.neighbor_platform,
            "neighbor_address": row.neighbor_address,
            "neighbor_capabilities": row.neighbor_capabilities,
        }
        for row in rows
    ]
    return json.dumps({"device_id": device_id, "neighbors": neighbors})


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

DISCOVERY_TOOLS = [
    trigger_discovery_run,
    list_devices,
    get_device,
    query_neighbors,
]

__all__ = [
    "DISCOVERY_TOOLS",
    "get_device",
    "list_devices",
    "query_neighbors",
    "trigger_discovery_run",
]
