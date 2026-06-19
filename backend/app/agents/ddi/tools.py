"""DDI Agent typed tool wrappers (M5 task #10, ADR-0022).

Two tiers, both crossing the agents -> services/plugins boundary only through
``NetOpsTool`` wrappers (REPO-STRUCTURE §3.2 row 11):

- **Read-only troubleshooting** (``READ_ONLY``). DNS — ``lookup_dns_records``,
  ``resolve_dns_path`` (delegation / CNAME resolution path), and
  ``dns_mismatch_vs_inventory`` (DDI record vs collected inventory). DHCP —
  ``scope_utilization``, ``lookup_dhcp_lease``, and ``check_dhcp_conflicts``.
  Each takes already-collected normalized DDI data (the
  :class:`~app.schemas.normalized.NormalizedDnsRecord` /
  ``NormalizedDhcpLease`` / ``NormalizedDhcpRange`` / ``NormalizedNetwork``
  projections the discovery runner persisted via the Infoblox WAPI read
  capabilities, T7) as plain JSON-able input and returns a JSON object the model
  consumes directly. These tools hold no DB session and do no transport I/O — the
  audited read happened upstream; the tool only shapes and **redacts** the result
  for explanation.

- **State-changing mutators** (``STATE_CHANGING``, ``change_request_kind =
  ddi_record``). ``add_dns_record`` / ``modify_dns_record`` /
  ``delete_dns_record`` / ``add_dhcp_range`` / ``delete_dhcp_range`` do **not**
  write. They carry no body of their own: the framework's
  :class:`~app.agents.framework.approval.ChangeRequestGate` (T4) intercepts the
  call, CREATES a ``ChangeRequest`` draft (kind ``ddi_record``) from the verbatim
  arguments, and the tool returns a
  :class:`~app.agents.framework.tools.ChangeRequestCreated` — the change is never
  applied inline. Only the Automation Agent (T9) executes an *approved* DDI CR via
  the Infoblox ``WapiClient`` write path (ADR-0022 §3), so there is exactly one
  write spine and the LLM can never trigger a direct DDI write.

Secret boundary (A9 — ADR-0017 §3 / ADR-0020 §4). DNS/DHCP content is
secret-bearing (a TXT record may embed an API key; a record/lease value may carry
operator-sensitive data). Every fragment a *read-only* tool surfaces to the model
passes :func:`~app.llm.redaction.redact_prompt` first, so secret values become
stable ``<<REDACTED:...>>`` tokens before the text reaches a prompt. The mutator
arguments are stored **verbatim** on the CR (the executor renders them
byte-for-byte, ADR-0020 §2); redaction there lives at the gate's LLM-preview and
the audit-emit boundaries, not in the tool.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.llm.redaction import redact_prompt
from app.models.change_requests import ChangeRequestKind

# ---------------------------------------------------------------------------
# Shared helpers (no transport I/O; redaction at the LLM boundary)
# ---------------------------------------------------------------------------


def _redact_record(record: dict[str, Any], *fields: str) -> dict[str, Any]:
    """Return *record* with each named (secret-bearing) field A9-redacted.

    Only free-text value fields can carry a secret (a TXT value, a hostname).
    Structural fields (record_type, zone, object_ref) are operator/appliance
    metadata and pass through so the narration stays useful.
    """
    redacted = dict(record)
    for field in fields:
        value = redacted.get(field)
        if isinstance(value, str):
            redacted[field] = redact_prompt(value)
    return redacted


# ---------------------------------------------------------------------------
# Read-only DNS troubleshooting
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def lookup_dns_records(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose collected DNS records to read."),
    ],
    records: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Already-collected normalized DNS records (NormalizedDnsRecord dumps) to "
                "search — the persisted projection of the Infoblox WAPI read (ADR-0022 §2)."
            )
        ),
    ],
    name: Annotated[
        str | None,
        Field(default=None, description="Optional exact record name (FQDN) to filter on."),
    ] = None,
    zone: Annotated[
        str | None,
        Field(default=None, description="Optional exact zone to filter on."),
    ] = None,
) -> str:
    """Look up DNS records by name and/or zone over collected DDI data (read-only).

    Returns a JSON object with ``device_id`` and a ``records`` list of matching
    normalized records (name, record_type, value, ttl, zone, object_ref). Every
    record's secret-bearing ``value`` is A9-redacted before it reaches the model.
    Read-only: no appliance or DB write.
    """
    matched = [
        _redact_record(r, "value")
        for r in records
        if (name is None or r.get("name") == name) and (zone is None or r.get("zone") == zone)
    ]
    return json.dumps({"device_id": device_id, "records": matched})


@netops_tool(classification=ToolClassification.READ_ONLY)
async def resolve_dns_path(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose collected DNS records to traverse."),
    ],
    name: Annotated[
        str,
        Field(description="The FQDN to resolve through the collected records."),
    ],
    records: Annotated[
        list[dict[str, Any]],
        Field(description="Already-collected normalized DNS records to resolve against."),
    ],
    max_hops: Annotated[
        int,
        Field(default=10, ge=1, le=64, description="CNAME-chain hop cap (loop guard)."),
    ] = 10,
) -> str:
    """Trace the resolution path for a name, following CNAME delegation (read-only).

    Walks the collected records from ``name``, following each CNAME to its target
    until a terminal address (A/AAAA/PTR/MX/TXT) is reached or the chain ends.
    Returns a JSON object with ``resolved`` (bool), the terminal ``answer`` (or
    ``None``), and the ordered ``path`` of hops (each name -> redacted value). A
    loop or a chain longer than ``max_hops`` ends resolution honestly with
    ``resolved=False``. Read-only.
    """
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_name.setdefault(str(record.get("name")), []).append(record)

    path: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = name
    answer: str | None = None
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        hits = by_name.get(current)
        if not hits:
            break
        record = hits[0]
        record_type = str(record.get("record_type", ""))
        value = str(record.get("value", ""))
        path.append(
            {
                "name": current,
                "record_type": record_type,
                "value": redact_prompt(value),
            }
        )
        if record_type == "cname":
            current = value
            continue
        answer = redact_prompt(value)
        break

    return json.dumps(
        {
            "device_id": device_id,
            "name": name,
            "resolved": answer is not None,
            "answer": answer,
            "path": path,
        }
    )


@netops_tool(classification=ToolClassification.READ_ONLY)
async def dns_mismatch_vs_inventory(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose DNS records to reconcile."),
    ],
    records: Annotated[
        list[dict[str, Any]],
        Field(description="Already-collected normalized DNS records (the DDI view)."),
    ],
    inventory: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Collected inventory the DNS should agree with: each item has a 'name' "
                "(FQDN) and an 'ip_address' the platform discovered for that host."
            )
        ),
    ],
) -> str:
    """Flag where DNS A/AAAA records diverge from collected inventory (read-only).

    For each inventory host (name -> ip_address), compares against the DDI's A/AAAA
    records for that name. Returns a JSON object with ``has_mismatch`` and a
    ``mismatches`` list (name, dns_values, inventory_ip) where the DNS does not
    contain the inventory address. Addresses are not secrets and pass through;
    this grounds a "DNS says X but the host is at Y" diagnosis. Read-only.
    """
    dns_by_name: dict[str, set[str]] = {}
    for record in records:
        if str(record.get("record_type")) in ("a", "aaaa"):
            dns_by_name.setdefault(str(record.get("name")), set()).add(str(record.get("value")))

    mismatches: list[dict[str, Any]] = []
    for item in inventory:
        host = str(item.get("name"))
        inv_ip = str(item.get("ip_address"))
        dns_values = dns_by_name.get(host, set())
        if inv_ip not in dns_values:
            mismatches.append(
                {
                    "name": host,
                    "dns_values": sorted(dns_values),
                    "inventory_ip": inv_ip,
                }
            )
    return json.dumps(
        {
            "device_id": device_id,
            "has_mismatch": bool(mismatches),
            "mismatches": mismatches,
        }
    )


# ---------------------------------------------------------------------------
# Read-only DHCP troubleshooting
# ---------------------------------------------------------------------------


def _pool_size(start: str, end: str) -> int | None:
    """Inclusive address count between two IPs, or ``None`` if unparsable."""
    from ipaddress import ip_address

    try:
        first = int(ip_address(start))
        last = int(ip_address(end))
    except ValueError:
        return None
    return last - first + 1 if last >= first else None


@netops_tool(classification=ToolClassification.READ_ONLY)
async def scope_utilization(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose DHCP scopes to assess."),
    ],
    ranges: Annotated[
        list[dict[str, Any]],
        Field(description="Already-collected normalized DHCP ranges (the address pools)."),
    ],
    leases: Annotated[
        list[dict[str, Any]],
        Field(default=[], description="Already-collected normalized DHCP leases."),
    ] = [],  # noqa: B006 - read-only default, never mutated
    networks: Annotated[
        list[dict[str, Any]],
        Field(
            default=[],
            description=(
                "Optional collected IPAM networks carrying an appliance-reported "
                "utilization_percent, surfaced alongside the lease-derived counts."
            ),
        ),
    ] = [],  # noqa: B006 - read-only default, never mutated
) -> str:
    """Compute DHCP scope utilization from collected ranges and leases (read-only).

    For each range, counts active leases falling within (or, lacking IP math,
    attributed to) the pool and derives ``utilization_percent`` against the pool
    size. Returns a JSON object with per-scope counts plus, when supplied, the
    appliance-reported per-network ``utilization_percent`` from IPAM. Addresses
    are not secrets. Read-only — no appliance or DB write.
    """
    from ipaddress import ip_address

    active_ips = [
        str(lease.get("ip_address"))
        for lease in leases
        if str(lease.get("state")) == "active"
    ]

    scopes: list[dict[str, Any]] = []
    for dhcp_range in ranges:
        start = str(dhcp_range.get("start_address"))
        end = str(dhcp_range.get("end_address"))
        pool_size = _pool_size(start, end)
        in_pool = 0
        if pool_size is not None:
            try:
                lo, hi = int(ip_address(start)), int(ip_address(end))
                in_pool = sum(1 for ip in active_ips if lo <= int(ip_address(ip)) <= hi)
            except ValueError:
                in_pool = len(active_ips)
        else:
            in_pool = len(active_ips)
        utilization = (
            round(100.0 * in_pool / pool_size, 2) if pool_size else None
        )
        scopes.append(
            {
                "start_address": start,
                "end_address": end,
                "network": dhcp_range.get("network"),
                "pool_size": pool_size,
                "active_leases": in_pool,
                "utilization_percent": utilization,
            }
        )

    network_views = [
        {
            "network": str(net.get("network")),
            "utilization_percent": net.get("utilization_percent"),
        }
        for net in networks
    ]
    return json.dumps(
        {"device_id": device_id, "scopes": scopes, "networks": network_views}
    )


@netops_tool(classification=ToolClassification.READ_ONLY)
async def lookup_dhcp_lease(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose collected DHCP leases to read."),
    ],
    leases: Annotated[
        list[dict[str, Any]],
        Field(description="Already-collected normalized DHCP leases to search."),
    ],
    ip_address: Annotated[
        str | None,
        Field(default=None, description="Optional exact lease IP to look up."),
    ] = None,
    mac_address: Annotated[
        str | None,
        Field(default=None, description="Optional exact lease MAC (lowercase colon form)."),
    ] = None,
    hostname: Annotated[
        str | None,
        Field(default=None, description="Optional exact client hostname to look up."),
    ] = None,
) -> str:
    """Look up DHCP leases by IP, MAC, or hostname over collected data (read-only).

    Returns a JSON object with ``device_id`` and a ``leases`` list of matching
    normalized leases (ip_address, state, mac_address, hostname, network, times).
    The hostname (which can carry operator-sensitive labels) is A9-redacted before
    it reaches the model. Read-only — no appliance or DB write.
    """
    matched: list[dict[str, Any]] = []
    for lease in leases:
        if ip_address is not None and str(lease.get("ip_address")) != ip_address:
            continue
        if mac_address is not None and str(lease.get("mac_address")) != mac_address:
            continue
        if hostname is not None and str(lease.get("hostname")) != hostname:
            continue
        matched.append(_redact_record(lease, "hostname"))
    return json.dumps({"device_id": device_id, "leases": matched})


@netops_tool(classification=ToolClassification.READ_ONLY)
async def check_dhcp_conflicts(
    device_id: Annotated[
        str,
        Field(description="UUID of the DDI appliance whose DHCP leases to check."),
    ],
    leases: Annotated[
        list[dict[str, Any]],
        Field(description="Already-collected normalized DHCP leases to scan for conflicts."),
    ],
) -> str:
    """Detect DHCP address conflicts over collected leases (read-only).

    A conflict is one IP bound to more than one distinct MAC among active leases
    (a duplicate-allocation / rogue-server symptom). Returns a JSON object with
    ``has_conflict`` and a ``conflicts`` list (ip_address, macs). Addresses and
    MACs are not secrets. Read-only — no appliance or DB write.
    """
    macs_by_ip: dict[str, set[str]] = {}
    for lease in leases:
        if str(lease.get("state")) != "active":
            continue
        ip = str(lease.get("ip_address"))
        mac = lease.get("mac_address")
        if mac:
            macs_by_ip.setdefault(ip, set()).add(str(mac))

    conflicts = [
        {"ip_address": ip, "macs": sorted(macs)}
        for ip, macs in macs_by_ip.items()
        if len(macs) > 1
    ]
    return json.dumps(
        {
            "device_id": device_id,
            "has_conflict": bool(conflicts),
            "conflicts": conflicts,
            "lease_count": len(leases),
        }
    )


# ---------------------------------------------------------------------------
# State-changing mutators — each CREATES a ChangeRequest, never executes inline
# ---------------------------------------------------------------------------
#
# These tools carry no write body: the framework ChangeRequestGate (T4)
# intercepts the STATE_CHANGING call, authors a ``ddi_record`` ChangeRequest from
# the verbatim arguments, and the tool returns a ChangeRequestCreated. The body
# below is unreachable under any non-approved gate (the M5 default), so it exists
# only to carry the schema + docstring the LLM routes on. ``target_refs`` projects
# the call arguments to the id-only refs recorded on the CR (never secret-bearing).


def _dns_target_refs(args: dict[str, Any]) -> dict[str, Any] | None:
    refs: dict[str, Any] = {"device_id": args.get("device_id")}
    if args.get("object_ref"):
        refs["object_ref"] = args["object_ref"]
    if args.get("name"):
        refs["name"] = args["name"]
    return refs


def _dhcp_target_refs(args: dict[str, Any]) -> dict[str, Any] | None:
    refs: dict[str, Any] = {"device_id": args.get("device_id")}
    if args.get("object_ref"):
        refs["object_ref"] = args["object_ref"]
    if args.get("start_address"):
        refs["range"] = f"{args.get('start_address')}-{args.get('end_address')}"
    return refs


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.DDI_RECORD,
    target_refs=_dns_target_refs,
)
async def add_dns_record(
    device_id: Annotated[str, Field(description="UUID of the target DDI appliance.")],
    name: Annotated[str, Field(description="FQDN of the record to add.")],
    record_type: Annotated[
        str, Field(description="DNS record type (a, aaaa, cname, ptr, mx, txt).")
    ],
    value: Annotated[str, Field(description="The record value (address / target / text).")],
    zone: Annotated[str | None, Field(default=None, description="Owning zone, if known.")] = None,
    ttl: Annotated[int | None, Field(default=None, ge=0, description="TTL seconds.")] = None,
) -> str:
    """Propose adding a DNS record — creates a change request, does not apply it.

    State-changing: this never writes to the appliance. The framework gate creates
    a ``ddi_record`` ChangeRequest draft from these arguments and returns it for
    human approval; the Automation Agent applies the WAPI write only after the CR
    is approved (ADR-0022 §3). Use this when the user asks to *add* a DNS record.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "add_dns_record must not execute inline; the ChangeRequest gate handles it"
    )


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.DDI_RECORD,
    target_refs=_dns_target_refs,
)
async def modify_dns_record(
    device_id: Annotated[str, Field(description="UUID of the target DDI appliance.")],
    object_ref: Annotated[
        str, Field(description="Opaque DDI handle (WAPI _ref) of the record to modify.")
    ],
    record_type: Annotated[str, Field(description="DNS record type of the record.")],
    name: Annotated[str, Field(description="FQDN of the record being modified.")],
    value: Annotated[str, Field(description="The new record value.")],
) -> str:
    """Propose modifying a DNS record — creates a change request, does not apply it.

    State-changing: this never writes to the appliance. The framework gate creates
    a ``ddi_record`` ChangeRequest draft and returns it for approval; the
    Automation Agent applies the change only after approval (ADR-0022 §3). Use
    this when the user asks to *change* an existing DNS record's value.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "modify_dns_record must not execute inline; the ChangeRequest gate handles it"
    )


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.DDI_RECORD,
    target_refs=_dns_target_refs,
)
async def delete_dns_record(
    device_id: Annotated[str, Field(description="UUID of the target DDI appliance.")],
    object_ref: Annotated[
        str, Field(description="Opaque DDI handle (WAPI _ref) of the record to delete.")
    ],
    name: Annotated[
        str | None, Field(default=None, description="FQDN of the record, for the CR summary.")
    ] = None,
) -> str:
    """Propose deleting a DNS record — creates a change request, does not apply it.

    State-changing: this never writes to the appliance. The framework gate creates
    a ``ddi_record`` ChangeRequest draft and returns it for approval; the
    Automation Agent applies the delete only after approval (ADR-0022 §3). Use
    this when the user asks to *remove* a DNS record.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "delete_dns_record must not execute inline; the ChangeRequest gate handles it"
    )


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.DDI_RECORD,
    target_refs=_dhcp_target_refs,
)
async def add_dhcp_range(
    device_id: Annotated[str, Field(description="UUID of the target DDI appliance.")],
    start_address: Annotated[str, Field(description="First address of the range.")],
    end_address: Annotated[str, Field(description="Last address of the range.")],
    network: Annotated[
        str | None, Field(default=None, description="Owning network CIDR, if known.")
    ] = None,
) -> str:
    """Propose adding a DHCP range — creates a change request, does not apply it.

    State-changing: this never writes to the appliance. The framework gate creates
    a ``ddi_record`` ChangeRequest draft and returns it for approval; the
    Automation Agent applies the change only after approval (ADR-0022 §3). Use
    this when the user asks to *add* a DHCP range / address pool.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "add_dhcp_range must not execute inline; the ChangeRequest gate handles it"
    )


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.DDI_RECORD,
    target_refs=_dhcp_target_refs,
)
async def delete_dhcp_range(
    device_id: Annotated[str, Field(description="UUID of the target DDI appliance.")],
    object_ref: Annotated[
        str, Field(description="Opaque DDI handle (WAPI _ref) of the range to delete.")
    ],
) -> str:
    """Propose deleting a DHCP range — creates a change request, does not apply it.

    State-changing: this never writes to the appliance. The framework gate creates
    a ``ddi_record`` ChangeRequest draft and returns it for approval; the
    Automation Agent applies the delete only after approval (ADR-0022 §3). Use
    this when the user asks to *remove* a DHCP range / address pool.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "delete_dhcp_range must not execute inline; the ChangeRequest gate handles it"
    )


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

DDI_READ_TOOLS = [
    lookup_dns_records,
    resolve_dns_path,
    dns_mismatch_vs_inventory,
    scope_utilization,
    lookup_dhcp_lease,
    check_dhcp_conflicts,
]

DDI_WRITE_TOOLS = [
    add_dns_record,
    modify_dns_record,
    delete_dns_record,
    add_dhcp_range,
    delete_dhcp_range,
]

DDI_TOOLS = [*DDI_READ_TOOLS, *DDI_WRITE_TOOLS]

__all__ = [
    "DDI_READ_TOOLS",
    "DDI_TOOLS",
    "DDI_WRITE_TOOLS",
    "add_dhcp_range",
    "add_dns_record",
    "check_dhcp_conflicts",
    "delete_dhcp_range",
    "delete_dns_record",
    "dns_mismatch_vs_inventory",
    "lookup_dhcp_lease",
    "lookup_dns_records",
    "modify_dns_record",
    "resolve_dns_path",
    "scope_utilization",
]
