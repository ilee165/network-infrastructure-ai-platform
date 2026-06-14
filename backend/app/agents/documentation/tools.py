"""Documentation Agent typed tool wrappers (M4 task 10, read-only).

All tools are classified READ_ONLY. The Documentation Agent *generates*
documentation artifacts deterministically — no LLM is involved in inventory
or diagram generation (ADR-0019 §2: "deterministic render of normalized tables
to Markdown + CSV; exit criterion is a round-trip equality test against
normalized-table content, so generation is pure/templated, not model-narrated").

This module owns the ``generate_inventory`` tool (T10). The ``generate_diagram``
and ``generate_runbook`` tools are added in the next two tasks (T11, T12).

Module boundary: these wrappers are the *only* point where the documentation
agent touches data. No code outside this module may import ``app.engines`` or
``app.models`` directly from within ``agents.documentation`` — the NetOpsTool
wrappers are the typed bridge the import-linter contract enforces
(REPO-STRUCTURE §3.2 row 11).

Design (ADR-0019 §2):
- ``generate_inventory`` accepts pre-fetched normalized-table data as plain
  dicts (the caller — a Celery worker or API handler — did the audited DB read
  and passes the rows in). The tool itself holds no DB session and does no
  transport I/O.
- The tool renders to Markdown *or* CSV depending on the ``fmt`` argument.
- Optional ``site`` / ``vendor_id`` scope filters narrow the rows before
  rendering, matching the ADR-0019 "scoped by site/vendor" requirement.
- The return value is a JSON string with ``kind``, ``format``, ``title``, and
  ``content`` — the exact fields of the ``Document`` model (ADR-0019 §1) so the
  caller can persist the artifact directly.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool

# ---------------------------------------------------------------------------
# Internal rendering helpers (pure functions, no I/O)
# ---------------------------------------------------------------------------

#: Column headers for each normalized table section.
_DEVICE_COLS = [
    "id",
    "hostname",
    "mgmt_ip",
    "vendor_id",
    "model",
    "os_version",
    "serial",
    "status",
    "site",
]
_IFACE_COLS = [
    "device_id",
    "name",
    "description",
    "admin_status",
    "oper_status",
    "ip_address",
    "mac_address",
    "speed_mbps",
]
_NEIGHBOR_COLS = [
    "device_id",
    "protocol",
    "local_interface",
    "neighbor_name",
    "neighbor_interface",
    "neighbor_platform",
    "neighbor_address",
]
_ROUTE_COLS = ["device_id", "prefix", "protocol", "next_hop", "interface", "vrf"]


def _cell(value: Any) -> str:
    """Render a cell value as a non-None string (empty string for None/missing)."""
    if value is None:
        return ""
    return str(value)


def _md_table(cols: list[str], rows: list[dict[str, Any]]) -> str:
    """Render *rows* as a GitHub-flavoured Markdown table with *cols* headers.

    Returns an empty-body table (header + separator only) when *rows* is empty,
    so every section is structurally present even for an empty scope.
    """
    header = "| " + " | ".join(cols) + " |"
    separator = "| " + " | ".join("---" for _ in cols) + " |"
    lines = [header, separator]
    for row in rows:
        cells = [_cell(row.get(col)) for col in cols]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _render_markdown(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    *,
    title: str,
) -> str:
    """Render all four normalized-table sections to a Markdown document.

    ADR-0019 §2: devices, interfaces, neighbors, routes. Each section has a
    level-2 heading and a GFM table. All values are rendered verbatim from the
    input dicts — no LLM, no transformation (round-trip equality contract).
    """
    parts: list[str] = [f"# {title}", ""]
    parts += ["## Devices", "", _md_table(_DEVICE_COLS, devices), ""]
    parts += ["## Interfaces", "", _md_table(_IFACE_COLS, interfaces), ""]
    parts += ["## Neighbors", "", _md_table(_NEIGHBOR_COLS, neighbors), ""]
    parts += ["## Routes", "", _md_table(_ROUTE_COLS, routes), ""]
    return "\n".join(parts)


def _render_csv(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
) -> str:
    """Render all four sections as a flat CSV with a ``section`` discriminator.

    All rows from all tables are concatenated into one CSV file; a ``section``
    column ("devices" / "interfaces" / "neighbors" / "routes") discriminates
    which normalized table a row came from. The superset of all columns is used
    as the header; missing columns for a given section are left empty.

    This gives a single parseable CSV that satisfies the "round-trip equality"
    exit criterion: every field value appears verbatim in the output.
    """
    all_cols_ordered = (
        ["section"]
        + _DEVICE_COLS
        + [c for c in _IFACE_COLS if c not in _DEVICE_COLS]
        + [c for c in _NEIGHBOR_COLS if c not in _DEVICE_COLS and c not in _IFACE_COLS]
        + [
            c
            for c in _ROUTE_COLS
            if c not in _DEVICE_COLS and c not in _IFACE_COLS and c not in _NEIGHBOR_COLS
        ]
    )
    # Deduplicate while preserving order (device_id appears in all four tables).
    seen: set[str] = set()
    header_cols: list[str] = []
    for col in all_cols_ordered:
        if col not in seen:
            header_cols.append(col)
            seen.add(col)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header_cols, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()

    def _write_section(section_name: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            record = {"section": section_name}
            record.update(row)
            writer.writerow(record)

    _write_section("devices", devices)
    _write_section("interfaces", interfaces)
    _write_section("neighbors", neighbors)
    _write_section("routes", routes)
    return buf.getvalue()


def _apply_scope(
    devices: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    *,
    site: str | None,
    vendor_id: str | None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Apply site/vendor scope filters to all four table slices.

    ADR-0019 §2: "scoped by site/vendor". The device table is filtered first;
    the remaining tables are filtered to only include rows whose ``device_id``
    belongs to a device that passed the device-level filter. This ensures
    interfaces/neighbors/routes for out-of-scope devices are excluded.
    """
    filtered_devices = devices
    if site is not None:
        filtered_devices = [d for d in filtered_devices if d.get("site") == site]
    if vendor_id is not None:
        filtered_devices = [d for d in filtered_devices if d.get("vendor_id") == vendor_id]

    in_scope_ids = {d["id"] for d in filtered_devices}

    filtered_interfaces = [r for r in interfaces if r.get("device_id") in in_scope_ids]
    filtered_neighbors = [r for r in neighbors if r.get("device_id") in in_scope_ids]
    filtered_routes = [r for r in routes if r.get("device_id") in in_scope_ids]

    return filtered_devices, filtered_interfaces, filtered_neighbors, filtered_routes


# ---------------------------------------------------------------------------
# generate_inventory
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def generate_inventory(
    devices: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from the ``devices`` normalized table. Each dict must contain at "
                "minimum: id, hostname, mgmt_ip, vendor_id, status. Optional fields: "
                "model, os_version, serial, site."
            )
        ),
    ],
    interfaces: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from the ``normalized_interfaces`` table. Each dict must contain "
                "at minimum: device_id, name, admin_status, oper_status."
            )
        ),
    ],
    neighbors: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from the ``normalized_neighbors`` table. Each dict must contain "
                "at minimum: device_id, protocol, local_interface, neighbor_name."
            )
        ),
    ],
    routes: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from the ``normalized_routes`` table. Each dict must contain "
                "at minimum: device_id, prefix, protocol."
            )
        ),
    ],
    fmt: Annotated[
        str,
        Field(
            description=(
                "Output format: 'md' for GitHub-flavoured Markdown, 'csv' for a "
                "flat CSV with a section discriminator column. "
                "(ADR-0019 §2: Markdown + CSV are both supported.)"
            )
        ),
    ] = "md",
    site: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional site name to scope the inventory to. Only devices whose "
                "``site`` field matches are included; interfaces/neighbors/routes for "
                "out-of-scope devices are excluded. Omit to include all sites."
            ),
        ),
    ] = None,
    vendor_id: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional vendor_id to scope the inventory to (e.g. 'cisco_ios', 'eos'). "
                "Only devices with a matching vendor_id are included. "
                "Omit to include all vendors."
            ),
        ),
    ] = None,
) -> str:
    """Generate a deterministic network inventory from normalized-table data.

    Renders the four normalized tables (devices, interfaces, neighbors, routes)
    to either GitHub-flavoured Markdown or a flat CSV, optionally scoped by
    site and/or vendor. **No LLM is used.** All values are rendered verbatim
    from the input rows — the round-trip equality exit criterion (ADR-0019 §2)
    is therefore satisfied by construction: every field value that enters the
    tool appears unchanged in the output.

    Returns a JSON string with the following fields (mirroring the ``Document``
    model — ADR-0019 §1), ready for the caller to persist as a ``documents``
    row:

    - ``kind``: always ``"inventory"``
    - ``format``: ``"md"`` or ``"csv"``
    - ``title``: a human-readable title including scope qualifiers
    - ``content``: the rendered Markdown or CSV text

    An ``"error"`` key is returned instead when an unsupported ``fmt`` is
    requested. Read-only — no device or DB write occurs inside this tool.
    """
    if fmt not in ("md", "csv"):
        return json.dumps({"error": f"unsupported format {fmt!r}; use 'md' or 'csv'"})

    # Apply scope filters before rendering (ADR-0019 §2: "scoped by site/vendor").
    scoped_devices, scoped_interfaces, scoped_neighbors, scoped_routes = _apply_scope(
        devices,
        interfaces,
        neighbors,
        routes,
        site=site,
        vendor_id=vendor_id,
    )

    # Build a human-readable title that encodes the scope qualifiers.
    scope_parts: list[str] = []
    if site:
        scope_parts.append(f"site={site}")
    if vendor_id:
        scope_parts.append(f"vendor={vendor_id}")
    scope_suffix = f" ({', '.join(scope_parts)})" if scope_parts else ""
    title = f"Network Inventory{scope_suffix}"

    if fmt == "md":
        content = _render_markdown(
            scoped_devices,
            scoped_interfaces,
            scoped_neighbors,
            scoped_routes,
            title=title,
        )
    else:  # fmt == "csv"
        content = _render_csv(
            scoped_devices,
            scoped_interfaces,
            scoped_neighbors,
            scoped_routes,
        )

    return json.dumps(
        {
            "kind": "inventory",
            "format": fmt,
            "title": title,
            "content": content,
        }
    )


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

#: All Documentation Agent tools registered for M4 T10.
#: T11 (generate_diagram) and T12 (generate_runbook) extend this list.
DOCUMENTATION_TOOLS = [
    generate_inventory,
]

__all__ = [
    "DOCUMENTATION_TOOLS",
    "generate_inventory",
]
