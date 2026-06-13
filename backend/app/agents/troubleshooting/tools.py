"""Troubleshooting Agent typed tool wrappers (M3-13).

All tools are classified READ_ONLY: the Troubleshooting Agent is the first
real analytic agent and it *never* mutates device state (MVP.md §5,
DECISIONS-BRIEF §5 — "Troubleshooting Agent (read-only)"). A STATE_CHANGING
tool may never appear on this agent; the contract is asserted by the tests.

Two evidence sources, both surfaced through ``NetOpsTool`` wrappers:

- **Normalized store** — ``get_device_routes`` reads the persisted
  ``NormalizedRouteRow`` projection of
  :class:`~app.schemas.normalized.NormalizedRoute` (collected by the M1
  discovery runner).
- **On-demand live reads** — ``read_live_bgp_peers`` / ``read_live_ospf_neighbors``
  / ``read_live_acls`` resolve the device's vendor plugin BGP/OSPF/ACL
  capability (M3-07..10) through the plugin registry and execute it over a
  freshly opened transport. The capability methods are synchronous blocking
  calls (netmiko/pysnmp, ADR-0007 §3), so each is run via
  :func:`asyncio.to_thread` to keep the FastAPI event loop unblocked
  (D2: async-first backend).

Module boundary: these wrappers are the *only* point where the troubleshooting
agent touches model / plugin / engine functions. No code in the
``agents.troubleshooting`` package may import ``app.models``, ``app.plugins``,
or ``app.engines`` outside this module — the NetOpsTool wrappers are the typed
bridge the import-linter contract enforces (REPO-STRUCTURE §3.2 row 11). Engine
and model imports are therefore deferred inside each coroutine body so the
tools can be unit-tested without those layers loaded (or faked where needed).

Each tool returns a JSON-serialisable string the model (and the agent's
diagnosis flow) can consume directly. Live-read failures (unknown device,
vendor without the capability, transport error) are returned as a JSON
``{"error": ...}`` object rather than raised, so a single missing data source
never aborts a multi-evidence diagnosis.
"""

from __future__ import annotations

import json
from typing import Annotated, Any
from uuid import UUID

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool

# ---------------------------------------------------------------------------
# get_device_routes — normalized store (persisted routing table)
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def get_device_routes(
    device_id: Annotated[
        str,
        Field(description="UUID of the device whose collected routing table to read."),
    ],
    prefix: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional exact CIDR prefix to filter on (e.g. '10.0.0.0/24'). "
                "Omit to return the whole table."
            ),
        ),
    ] = None,
) -> str:
    """Read the device's normalized routing table from the collected inventory.

    Returns a JSON object with ``device_id`` and a ``routes`` list where each
    entry contains prefix, protocol, next_hop, interface, vrf, distance, and
    metric. Use this to answer "is prefix X present / which protocol installed
    it" without touching the device. Reads the persisted ``NormalizedRouteRow``
    projection only — no live device access.
    """
    from sqlalchemy import select

    import app.db as _db
    from app.models import NormalizedRouteRow

    try:
        uid = UUID(device_id)
    except ValueError:
        return json.dumps({"error": f"invalid UUID: {device_id!r}"})

    async with _db.get_sessionmaker()() as session:
        query = select(NormalizedRouteRow).where(NormalizedRouteRow.device_id == uid)
        if prefix is not None:
            query = query.where(NormalizedRouteRow.prefix == prefix)
        rows = (await session.execute(query.order_by(NormalizedRouteRow.prefix))).scalars().all()

    routes = [
        {
            "prefix": row.prefix,
            "protocol": row.protocol.value,
            "next_hop": row.next_hop or None,
            "interface": row.interface or None,
            "vrf": row.vrf or None,
            "distance": row.distance,
            "metric": row.metric,
        }
        for row in rows
    ]
    return json.dumps({"device_id": device_id, "routes": routes})


# ---------------------------------------------------------------------------
# Live-read helpers
# ---------------------------------------------------------------------------


async def _read_live(device_id: str, capability_name: str, method_name: str) -> dict[str, Any]:
    """Resolve and run one synchronous live-read capability for a device.

    Looks the device up in inventory and resolves its vendor plugin's
    *capability* through the process-wide plugin registry — the real, testable
    half of an on-demand read. Executing the resolved capability requires a
    connected transport built from materialized vault credentials (D11); that
    credential/transport wiring lands with M5, so until then the resolved path
    surfaces a typed "not yet wired" error rather than opening a session with
    placeholder secrets. Capability methods are synchronous blocking calls
    (netmiko/pysnmp, ADR-0007 §3) and will run via :func:`asyncio.to_thread`
    once the transport seam is injected.

    Returns ``{"records": [<normalized model dump>, ...]}`` on success or
    ``{"error": ...}`` on any failure, so a missing data source degrades the
    diagnosis instead of aborting it. No secret material is ever returned or
    logged: only a vault *reference* is ever used to open a session (D11).
    """
    from app.core.errors import NetOpsError
    from app.plugins.base import Capability

    try:
        uid = UUID(device_id)
    except ValueError:
        return {"error": f"invalid UUID: {device_id!r}"}

    import app.db as _db
    from app.models import Device
    from app.plugins.registry import get_default_registry

    async with _db.get_sessionmaker()() as session:
        device = await session.get(Device, uid)
        if device is None:
            return {"error": f"device {device_id} not found"}
        vendor_id = device.vendor_id

    if vendor_id is None:
        return {"error": f"device {device_id} has no identified vendor; cannot resolve a plugin"}

    capability = Capability(capability_name)
    try:
        # Fail fast (and explainably) when the vendor lacks the capability —
        # "FortiOS plugin does not implement OSPF analysis" (ADR-0006).
        get_default_registry().resolve(vendor_id, capability)
    except NetOpsError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    # The (vendor, capability) pair resolves; executing it needs a credentialed
    # transport (M5). Tests substitute fixture-backed fake tools for this body.
    _ = (uid, method_name)
    return {
        "error": (
            f"live {capability.value!r} read for vendor {vendor_id!r} is not yet wired: "
            "the credential/transport session lands in M5"
        )
    }


# ---------------------------------------------------------------------------
# read_live_bgp_peers — live BGP capability
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def read_live_bgp_peers(
    device_id: Annotated[
        str,
        Field(description="UUID of the device to read live BGP peer state from."),
    ],
) -> str:
    """Read live BGP peer/session state from a device, on demand.

    Resolves the device's vendor plugin ``BGP`` capability and returns a JSON
    object with ``device_id`` and a ``peers`` list of normalized BGP peers
    (peer_address, remote_as, local_as, state, vrf, address_family,
    prefixes_received, uptime_seconds). Use this to ground a "why is BGP peer X
    down" diagnosis in the *current* FSM state rather than a stale collection.
    Read-only: it issues only ``show``-class commands. Returns ``{"error": ...}``
    if the device is unknown or its vendor does not implement BGP.
    """
    result = await _read_live(device_id, "bgp", "get_bgp_peers")
    if "error" in result:
        return json.dumps({"device_id": device_id, "error": result["error"]})
    return json.dumps({"device_id": device_id, "peers": result["records"]})


# ---------------------------------------------------------------------------
# read_live_ospf_neighbors — live OSPF capability
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def read_live_ospf_neighbors(
    device_id: Annotated[
        str,
        Field(description="UUID of the device to read live OSPF neighbor state from."),
    ],
) -> str:
    """Read live OSPF neighbor/adjacency state from a device, on demand.

    Resolves the device's vendor plugin ``OSPF`` capability and returns a JSON
    object with ``device_id`` and a ``neighbors`` list of normalized OSPF
    neighbors (neighbor_id, interface, state, neighbor_address, area, priority,
    dead_time_seconds). Use this to ground an adjacency-stuck diagnosis
    (e.g. EXSTART/INIT) in the current state. Read-only. Returns
    ``{"error": ...}`` if the device is unknown or its vendor does not
    implement OSPF.
    """
    result = await _read_live(device_id, "ospf", "get_ospf_neighbors")
    if "error" in result:
        return json.dumps({"device_id": device_id, "error": result["error"]})
    return json.dumps({"device_id": device_id, "neighbors": result["records"]})


# ---------------------------------------------------------------------------
# read_live_acls — live ACL capability
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def read_live_acls(
    device_id: Annotated[
        str,
        Field(description="UUID of the device to read live ACL entries from."),
    ],
) -> str:
    """Read live ACL entries from a device, on demand.

    Resolves the device's vendor plugin ``ACL`` capability and returns a JSON
    object with ``device_id`` and an ``acls`` list of normalized ACL entries
    (acl_name, action, protocol, sequence, source, source_port, destination,
    destination_port, hits). Use this to ground a "traffic is being dropped"
    diagnosis in an actual deny rule. Read-only. Returns ``{"error": ...}`` if
    the device is unknown or its vendor does not implement ACL collection.
    """
    result = await _read_live(device_id, "acl", "get_acls")
    if "error" in result:
        return json.dumps({"device_id": device_id, "error": result["error"]})
    return json.dumps({"device_id": device_id, "acls": result["records"]})


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

TROUBLESHOOTING_TOOLS = [
    get_device_routes,
    read_live_bgp_peers,
    read_live_ospf_neighbors,
    read_live_acls,
]

__all__ = [
    "TROUBLESHOOTING_TOOLS",
    "get_device_routes",
    "read_live_acls",
    "read_live_bgp_peers",
    "read_live_ospf_neighbors",
]
