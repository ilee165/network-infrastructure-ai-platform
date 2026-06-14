"""Documentation Agent typed tool wrappers (M4 task 10, read-only).

All tools are classified READ_ONLY. The Documentation Agent *generates*
documentation artifacts deterministically — no LLM is involved in inventory
or diagram generation (ADR-0019 §2: "deterministic render of normalized tables
to Markdown + CSV; exit criterion is a round-trip equality test against
normalized-table content, so generation is pure/templated, not model-narrated").

This module owns the ``generate_inventory`` tool (T10) and the
``generate_diagram`` tool (T11). The ``generate_runbook`` tool is added in the
next task (T12).

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
import logging
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool

_log = logging.getLogger(__name__)

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
    """Render a cell value as a non-None string (empty string for None/missing).

    Pipe characters are escaped as ``\\|`` so that a GFM parser reconstructing
    the table always sees the correct column count (ADR-0019 §2 round-trip
    equality: a literal ``|`` in a field value — e.g. an interface description
    like "WAN | core uplink" or a Cisco banner — must not produce an extra GFM
    column). The CSV path is unaffected; stdlib ``DictWriter`` handles quoting.
    """
    if value is None:
        return ""
    return str(value).replace("|", r"\|")


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
# generate_diagram — Mermaid from the Neo4j projection (T11, ADR-0019 §3)
# ---------------------------------------------------------------------------
#
# ADR-0019 §3: "Diagrams — Mermaid source generated deterministically from the
# Neo4j projection (nodes/edges -> Mermaid `graph` syntax). Mermaid is the
# stored, diffable, embeddable diagram-of-record; it satisfies the exit
# criterion (diagram node/edge set matches the projection) by construction.
# PNG is rendered client-side". No server-side render dependency is added.
#
# The tool accepts the projection in the exact JSON-safe shape that
# ``app.knowledge.topology_read.fetch_graph`` returns — ``{"nodes": [...],
# "edges": [...], "projected_at": <iso|None>}`` where each node carries
# ``label``/``key``/``properties`` and each edge carries
# ``type``/``source``/``target``/``properties``. The caller (a ``docs``-queue
# worker or API handler) performs the audited Neo4j read via the ``knowledge/``
# client and passes the result in; this tool holds no driver and does no I/O,
# respecting the module boundary (REPO-STRUCTURE §3.2 — agents touch data only
# through these typed wrappers, never importing the Neo4j driver directly).


#: Mermaid edge direction header (top-down). Deterministic, stable across runs.
_MERMAID_HEADER = "graph TD"

#: How each projected node label is shown in the diagram. Devices are far more
#: legible by hostname than by their ``pg_id`` UUID; everything else uses its
#: natural key (cidr / vlan_id / name) which is already human-readable.
_LABEL_DISPLAY_PROPERTY = {"Device": "hostname"}


def _mermaid_node_id(index: int) -> str:
    """Stable, syntactically-safe Mermaid node id for the *index*-th node.

    Projection keys are UUIDs / CIDRs / arbitrary strings that are not valid
    Mermaid identifiers, so we assign deterministic synthetic ids (``n0``,
    ``n1`` …) in projection order. Order is fixed by the caller's node list, so
    the same projection always yields byte-identical output.
    """
    return f"n{index}"


def _node_display_text(node: dict[str, Any]) -> str:
    """Human-readable label text for *node* (hostname for devices, else key)."""
    label = node.get("label")
    properties = node.get("properties") or {}
    display_prop = _LABEL_DISPLAY_PROPERTY.get(str(label))
    text: Any = None
    if display_prop is not None:
        text = properties.get(display_prop)
    if text is None:
        text = node.get("key")
    if text is None:
        text = label
    return str(text)


def _escape_mermaid_label(text: str) -> str:
    r"""Make *text* safe inside a Mermaid ``["..."]`` quoted label.

    Double quotes and square brackets would otherwise terminate the node label
    and corrupt the graph. Mermaid has no backslash escape inside a quoted
    string, so we substitute HTML entities (``#quot;`` / ``#91;`` / ``#93;``),
    which Mermaid renders as the literal characters. This keeps every node
    declaration well-formed regardless of hostname content.
    """
    return text.replace('"', "#quot;").replace("[", "#91;").replace("]", "#93;")


def _render_mermaid(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    """Render the projection *nodes*/*edges* to deterministic Mermaid source.

    Each node becomes one ``n<i>["<label> <display>"]`` declaration in
    projection order; each edge becomes one ``n<src> -->|"<type>"| n<dst>`` link
    resolved through the same ``(label, key) -> n<i>`` map. The node/edge *set*
    of the output therefore equals the projection's by construction (the T11
    exit criterion). Edges whose endpoints are not in the node set are skipped
    (a self-consistent projection has none).
    """
    # Map each projected node's identity (label, key) to its synthetic id.
    id_by_identity: dict[tuple[Any, Any], str] = {}
    lines: list[str] = [_MERMAID_HEADER]

    for index, node in enumerate(nodes):
        node_id = _mermaid_node_id(index)
        id_by_identity[(node.get("label"), node.get("key"))] = node_id
        display = _escape_mermaid_label(f"{node.get('label')}: {_node_display_text(node)}")
        lines.append(f'    {node_id}["{display}"]')

    # Edges reference endpoints by the node *key* (topology_read emits
    # source/target as the endpoint key values). Build a key -> mermaid_id map,
    # but flag keys that appear under more than one label (cross-label collision)
    # — those are ambiguous and any edge targeting them is skipped with a warning
    # so we never silently mis-route an edge to the wrong node.
    id_by_key: dict[Any, str] = {}
    ambiguous_keys: set[Any] = set()
    for node in nodes:
        k = node.get("key")
        mermaid_id = id_by_identity[(node.get("label"), k)]
        if k in id_by_key and id_by_key[k] != mermaid_id:
            # Two distinct nodes share the same key value — mark ambiguous.
            ambiguous_keys.add(k)
            _log.warning(
                "_render_mermaid: key %r is shared by multiple node labels; "
                "edges referencing this key will be omitted to avoid mis-routing.",
                k,
            )
        else:
            id_by_key[k] = mermaid_id
    for edge in edges:
        src_key = edge.get("source")
        dst_key = edge.get("target")
        if src_key in ambiguous_keys or dst_key in ambiguous_keys:
            _log.warning(
                "_render_mermaid: skipping edge %r->%r — endpoint key is ambiguous.",
                src_key,
                dst_key,
            )
            continue
        source_id = id_by_key.get(src_key)
        target_id = id_by_key.get(dst_key)
        if source_id is None or target_id is None:
            continue
        rel_type = _escape_mermaid_label(str(edge.get("type", "")))
        lines.append(f'    {source_id} -->|"{rel_type}"| {target_id}')

    return "\n".join(lines)


@netops_tool(classification=ToolClassification.READ_ONLY)
async def generate_diagram(
    projection: Annotated[
        dict[str, Any],
        Field(
            description=(
                "The Neo4j topology projection in the shape returned by the "
                "``knowledge/`` topology reader (``fetch_graph``): a dict with "
                "``nodes`` (each ``{label, key, properties}``), ``edges`` (each "
                "``{type, source, target, properties}`` where source/target are "
                "node ``key`` values), and an optional ``projected_at`` "
                "watermark. The caller performs the audited Neo4j read and "
                "passes the result in; this tool does no transport I/O."
            )
        ),
    ],
) -> str:
    """Render the Neo4j topology projection to deterministic Mermaid source.

    ADR-0019 §3: diagrams are emitted as **Mermaid source** generated
    deterministically from the projection (nodes/edges -> Mermaid ``graph``
    syntax). Mermaid is the stored, diffable, embeddable diagram-of-record;
    **PNG is rendered client-side** (no server-side render dependency). The
    generated node/edge set equals the projection's node/edge set by
    construction, satisfying the T11 exit criterion. **No LLM is used.**

    Returns a JSON string with the fields of the ``Document`` model
    (ADR-0019 §1), ready for the caller to persist as a ``documents`` row:

    - ``kind``: always ``"diagram"``
    - ``format``: always ``"mermaid"``
    - ``title``: a human-readable title
    - ``content``: the Mermaid graph source

    Read-only — no device, DB, or graph write occurs inside this tool.
    """
    nodes = list(projection.get("nodes") or [])
    edges = list(projection.get("edges") or [])
    content = _render_mermaid(nodes, edges)
    return json.dumps(
        {
            "kind": "diagram",
            "format": "mermaid",
            "title": "Network Topology Diagram",
            "content": content,
        }
    )


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

#: All Documentation Agent tools registered for M4 (T10 inventory, T11 diagram).
#: T12 (generate_runbook) extends this list.
DOCUMENTATION_TOOLS = [
    generate_inventory,
    generate_diagram,
]

__all__ = [
    "DOCUMENTATION_TOOLS",
    "generate_diagram",
    "generate_inventory",
]
