"""Documentation Agent typed tool wrappers (M4, read-only).

All tools are classified READ_ONLY. Inventory and diagram generation use no LLM
(ADR-0019 §2-3: "deterministic render of normalized tables / the Neo4j
projection; the round-trip / set-equality exit criteria are satisfied by
construction"). Runbook generation (T12) is the one LLM path: a deterministic
fact template plus a grounded narrative the model writes — every grounding fact
is redacted at the A9 LLM boundary first (ADR-0019 §4, ADR-0017 §3).

This module owns ``generate_inventory`` (T10), ``generate_diagram`` (T11), and
``generate_runbook`` (T12).

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
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.llm.redaction import redact_prompt

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

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
# generate_runbook — template + grounded, redacted LLM narrative (T12, §4)
# ---------------------------------------------------------------------------
#
# ADR-0019 §4: "Runbooks — template + LLM narrative grounded in
# inventory/topology. A per-device/per-site Markdown template is filled with
# deterministic facts (from normalized tables + the projection); the LLM writes
# only the narrative sections, grounded in those facts and instructed to cite
# them. ALL grounding content passes through the A9 redaction layer before
# reaching the model (configs/inventory can carry secret-bearing fields —
# ADR-0017 §3). Provider via the D9 registry (``local`` default)."
#
# Security model (A9 — SECURITY-CRITICAL). Inventory/topology facts can carry
# secret-bearing values (an interface description echoing a key, a banner, a
# neighbor string). EVERY fact this tool emits — into the deterministic template
# tables AND into the prompt handed to the model — is run through
# :func:`~app.llm.redaction.redact_prompt` FIRST. The model the D9 registry
# returns is itself wrapped in :class:`~app.llm.redaction.RedactingChatModel`
# (a second, bypass-proof line of defence), but this tool does not rely on that:
# the grounding text is already redacted before it leaves this module, so a
# secret value never reaches the provider even through the narrative path.
#
# Grounding. The narrative sections are written by the model from ONLY the
# redacted facts placed in the prompt; the model is instructed to ground every
# statement in those facts and not to invent device details. The deterministic
# fact tables remain the source of truth — a weak model degrades prose, never
# correctness (ADR-0019 §4 consequence).


#: System directive constraining the model to grounded, cited narrative only.
_RUNBOOK_SYSTEM_PROMPT = (
    "You are a senior network engineer writing the narrative sections of an "
    "operational runbook. You are given a set of GROUNDING FACTS about one "
    "device (already redacted of any secret values). Write clear, concise "
    "operational prose for the requested section. You MUST ground every "
    "statement strictly in the provided facts: never invent hostnames, "
    "addresses, interfaces, neighbors, routes, or vendor details that are not "
    "present in the facts. When you reference a fact, cite it by its value "
    "(e.g. the hostname or interface name) so the reader can trace it. If the "
    "facts do not support a statement, omit it. Do not output Markdown headings "
    "— write only the body text for the section."
)

#: Narrative sections the LLM fills, in document order. Each is (heading, brief).
_RUNBOOK_NARRATIVE_SECTIONS: list[tuple[str, str]] = [
    (
        "Overview",
        "Summarize what this device is and its role, grounded in the facts.",
    ),
    (
        "Operational Procedures",
        "Describe how an operator would verify this device's health and its key "
        "interfaces/neighbors/routes, grounded in the facts.",
    ),
]


def _facts_block(
    device: dict[str, Any],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
) -> str:
    """Render the (already-redacted) grounding facts as compact text for the LLM.

    The facts are the same normalized-table rows the deterministic template
    renders, so the narrative and the tables draw from one redacted source.
    """
    lines = ["Device:", json.dumps(device, sort_keys=True)]
    lines += ["Interfaces:", json.dumps(interfaces, sort_keys=True)]
    lines += ["Neighbors:", json.dumps(neighbors, sort_keys=True)]
    lines += ["Routes:", json.dumps(routes, sort_keys=True)]
    return "\n".join(lines)


def _redact_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Redact every string value in each row at the LLM boundary (A9).

    Non-string values (ints such as ``speed_mbps``) are passed through; only
    text fields can carry a secret pattern.
    """
    redacted: list[dict[str, Any]] = []
    for row in rows:
        clean: dict[str, Any] = {}
        for key, value in row.items():
            clean[key] = redact_prompt(value) if isinstance(value, str) else value
        redacted.append(clean)
    return redacted


def _render_runbook_markdown(
    device: dict[str, Any],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    *,
    title: str,
    narratives: dict[str, str],
    topology: str | None,
) -> str:
    """Assemble the runbook Markdown: narrative sections + deterministic tables.

    The fact tables are rendered with the same verbatim helpers the inventory
    tool uses (so they are exact), and the narrative sections carry the
    model-written prose. All inputs here are already redacted.
    """
    parts: list[str] = [f"# {title}", ""]
    parts += ["## Overview", "", narratives.get("Overview", "").strip(), ""]
    parts += ["## Device Facts", "", _md_table(_DEVICE_COLS, [device]), ""]
    parts += ["## Interfaces", "", _md_table(_IFACE_COLS, interfaces), ""]
    parts += ["## Neighbors", "", _md_table(_NEIGHBOR_COLS, neighbors), ""]
    parts += ["## Routes", "", _md_table(_ROUTE_COLS, routes), ""]
    if topology:
        parts += ["## Topology", "", "```mermaid", topology, "```", ""]
    parts += [
        "## Operational Procedures",
        "",
        narratives.get("Operational Procedures", "").strip(),
        "",
    ]
    return "\n".join(parts)


async def render_runbook(
    device: dict[str, Any],
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    *,
    model: BaseChatModel,
    topology: str | None = None,
) -> dict[str, Any]:
    """Build a grounded, redacted per-device runbook (ADR-0019 §4).

    The implementation behind :func:`generate_runbook`, factored out with an
    injectable *model* so it is fully testable offline with a fake chat model.

    Steps:

    1. **Redact every grounding fact (A9).** The device row, interface/neighbor/
       route rows, and the topology source are all passed through
       :func:`~app.llm.redaction.redact_prompt` BEFORE either the template or the
       model sees them — secret-bearing fields never leave this function in the
       clear (ADR-0017 §3).
    2. **LLM narrative.** For each narrative section the (already-redacted) facts
       are placed in the prompt and the model writes grounded prose. *model* is
       the D9-registry chat model (``local`` default), itself redaction-wrapped
       as a second line of defence.
    3. **Template assembly.** The narrative is interleaved with deterministic,
       verbatim fact tables (the source of truth) into a single Markdown body.

    Returns a dict with the ``Document`` fields (ADR-0019 §1) — ``kind``
    (``"runbook"``), ``format`` (``"md"``), ``title``, ``content``, and
    ``source_refs`` recording the device id the runbook was generated from.
    """
    # 1. Redact all grounding facts at the LLM boundary (A9) before any use.
    red_device = _redact_rows([device])[0]
    red_interfaces = _redact_rows(interfaces)
    red_neighbors = _redact_rows(neighbors)
    red_routes = _redact_rows(routes)
    red_topology = redact_prompt(topology) if topology else None

    hostname = str(red_device.get("hostname") or red_device.get("id") or "device")
    title = f"Runbook: {hostname}"

    facts = _facts_block(red_device, red_interfaces, red_neighbors, red_routes)

    # 2. LLM writes each narrative section from the redacted facts only.
    from langchain_core.messages import HumanMessage, SystemMessage

    narratives: dict[str, str] = {}
    for heading, brief in _RUNBOOK_NARRATIVE_SECTIONS:
        prompt = f"GROUNDING FACTS (redacted):\n{facts}\n\nWrite the '{heading}' section. {brief}"
        response = await model.ainvoke(
            [
                SystemMessage(content=_RUNBOOK_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content
        narratives[heading] = content if isinstance(content, str) else str(content)

    # 3. Assemble the template with deterministic, verbatim (redacted) tables.
    content = _render_runbook_markdown(
        red_device,
        red_interfaces,
        red_neighbors,
        red_routes,
        title=title,
        narratives=narratives,
        topology=red_topology,
    )

    return {
        "kind": "runbook",
        "format": "md",
        "title": title,
        "content": content,
        "source_refs": {"device_id": device.get("id")},
    }


@netops_tool(classification=ToolClassification.READ_ONLY)
async def generate_runbook(
    device: Annotated[
        dict[str, Any],
        Field(
            description=(
                "The device row from the ``devices`` normalized table the runbook is "
                "for. Must contain at minimum: id, hostname, mgmt_ip, vendor_id, status. "
                "Optional: model, os_version, serial, site."
            )
        ),
    ],
    interfaces: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from ``normalized_interfaces`` for this device "
                "(device_id, name, admin_status, oper_status, ...)."
            )
        ),
    ],
    neighbors: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from ``normalized_neighbors`` for this device "
                "(device_id, protocol, local_interface, neighbor_name, ...)."
            )
        ),
    ],
    routes: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Rows from ``normalized_routes`` for this device "
                "(device_id, prefix, protocol, ...)."
            )
        ),
    ],
    topology: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional Mermaid topology source (from ``generate_diagram``) scoped to "
                "this device's neighborhood, embedded in the runbook's Topology section."
            ),
        ),
    ] = None,
) -> str:
    """Generate a per-device runbook: template + grounded, redacted LLM narrative.

    ADR-0019 §4. A per-device Markdown template is filled with deterministic,
    verbatim fact tables (devices/interfaces/neighbors/routes); the LLM writes
    ONLY the narrative sections (Overview, Operational Procedures), grounded in
    those facts and instructed to cite them.

    **SECURITY-CRITICAL (A9 / ADR-0017 §3).** Every grounding fact — into the
    template tables AND into the model prompt — is redacted via the A9 layer
    (:func:`~app.llm.redaction.redact_prompt`) before use, so no secret value
    (SNMP community, enable secret, key) reaches the provider. The provider is
    resolved from the D9 registry (:func:`~app.llm.providers.get_chat_model`,
    ``local`` default), itself wrapped in the redacting model as a second,
    bypass-proof line of defence.

    Returns a JSON string with the ``Document`` fields (ADR-0019 §1): ``kind``
    (``"runbook"``), ``format`` (``"md"``), ``title``, ``content``, and
    ``source_refs`` (the device id). The caller persists it as a ``documents``
    row and embeds it via the T8 pipeline. Read-only — no device or DB write.
    """
    from app.llm.providers import get_chat_model

    model = get_chat_model()
    payload = await render_runbook(
        device,
        interfaces,
        neighbors,
        routes,
        model=model,
        topology=topology,
    )
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# generate_incident_report — grounded + A9-redacted incident narrative (M5 T12)
# ---------------------------------------------------------------------------

#: System prompt for the incident-report LLM narrative sections.
#: Mirrors _RUNBOOK_SYSTEM_PROMPT but scoped to incident investigation.
_INCIDENT_SYSTEM_PROMPT = (
    "You are a network operations engineer writing a formal incident report. "
    "Write concisely and professionally. Ground every claim in the provided "
    "GROUNDING FACTS — do not invent details not present in those facts. "
    "Cite the evidence references supplied. "
    "Output only the section prose, no section headings."
)

#: (heading, brief) pairs the LLM writes for the incident report narrative.
_INCIDENT_NARRATIVE_SECTIONS: list[tuple[str, str]] = [
    (
        "Summary",
        "Write a concise executive summary of the incident, its impact, and resolution.",
    ),
    (
        "Root Cause",
        "Describe the root cause identified, grounded in the findings and timeline evidence.",
    ),
]


def _render_timeline_table(timeline: list[dict[str, Any]]) -> str:
    """Render the timeline as a GFM table with timestamp, step, and evidence columns."""
    cols = ["ts", "step", "evidence"]
    header = "| " + " | ".join(cols) + " |"
    separator = "| " + " | ".join("---" for _ in cols) + " |"
    lines = [header, separator]
    for entry in timeline:
        cells = [_cell(entry.get(col)) for col in cols]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _render_cr_table(change_requests: list[dict[str, Any]]) -> str:
    """Render the remediation ChangeRequests as a GFM table."""
    cols = ["id", "kind", "state", "description"]
    header = "| " + " | ".join(cols) + " |"
    separator = "| " + " | ".join("---" for _ in cols) + " |"
    lines = [header, separator]
    for cr in change_requests:
        cells = [_cell(cr.get(col)) for col in cols]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _render_incident_markdown(
    session: dict[str, Any],
    change_requests: list[dict[str, Any]],
    *,
    title: str,
    narratives: dict[str, str],
) -> str:
    """Assemble the incident report Markdown: narrative sections + deterministic tables.

    Structure (ADR-0019 §1 / M5 T12):
    - Summary narrative (LLM, grounded)
    - Timeline table (deterministic, verbatim from session facts)
    - Evidence References (deterministic list)
    - Root Cause narrative (LLM, grounded)
    - Findings (verbatim session fact)
    - Remediation ChangeRequests table (deterministic)
    All inputs are already A9-redacted before this function is called.
    """
    timeline: list[dict[str, Any]] = session.get("timeline") or []
    evidence_refs: list[str] = session.get("evidence_refs") or []
    findings: str = str(session.get("findings") or "")

    parts: list[str] = [f"# {title}", ""]

    # LLM narrative — Summary
    parts += ["## Summary", "", narratives.get("Summary", "").strip(), ""]

    # Deterministic timeline table
    parts += ["## Timeline", "", _render_timeline_table(timeline), ""]

    # Deterministic evidence references
    parts += ["## Evidence References", ""]
    if evidence_refs:
        for ref in evidence_refs:
            parts.append(f"- {_cell(ref)}")
    else:
        parts.append("_No evidence references recorded._")
    parts.append("")

    # LLM narrative — Root Cause
    parts += ["## Root Cause", "", narratives.get("Root Cause", "").strip(), ""]

    # Verbatim findings
    parts += ["## Findings", "", findings.strip(), ""]

    # Deterministic remediation table
    parts += ["## Remediation", "", _render_cr_table(change_requests), ""]

    return "\n".join(parts)


def _session_facts_block(session: dict[str, Any], change_requests: list[dict[str, Any]]) -> str:
    """Render the (already-redacted) session facts as compact text for the LLM."""
    lines = [
        "Session:",
        json.dumps(
            {
                k: v
                for k, v in session.items()
                if k not in ("timeline", "evidence_refs")
            },
            sort_keys=True,
        ),
        "Timeline:",
        json.dumps(session.get("timeline") or [], sort_keys=True),
        "Evidence refs:",
        json.dumps(session.get("evidence_refs") or [], sort_keys=True),
        "Change requests:",
        json.dumps(change_requests, sort_keys=True),
    ]
    return "\n".join(lines)


def _redact_session(session: dict[str, Any]) -> dict[str, Any]:
    """Redact every string value in the session dict (A9 boundary)."""

    def _redact_value(v: Any) -> Any:
        if isinstance(v, str):
            return redact_prompt(v)
        if isinstance(v, list):
            return [_redact_value(i) for i in v]
        if isinstance(v, dict):
            return {k: _redact_value(val) for k, val in v.items()}
        return v

    return {k: _redact_value(v) for k, v in session.items()}


def _redact_change_requests(change_requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Redact every string value in the change request list (A9 boundary)."""
    return _redact_rows(change_requests)


async def render_incident_report(
    session: dict[str, Any],
    change_requests: list[dict[str, Any]],
    *,
    model: BaseChatModel,
) -> dict[str, Any]:
    """Build a grounded, redacted incident report from a troubleshooting session.

    The implementation behind :func:`generate_incident_report`, factored out
    with an injectable *model* so it is fully testable offline with a fake chat
    model (mirrors :func:`render_runbook`).

    Steps:

    1. **Redact every grounding fact (A9).** The session dict and change
       requests are passed through :func:`~app.llm.redaction.redact_prompt`
       BEFORE either the template or the model sees them — secret-bearing fields
       (SNMP communities, passwords, API keys) never leave this function in the
       clear (ADR-0017 §3 / ADR-0019 §4).
    2. **LLM narrative.** For each narrative section the (already-redacted)
       session facts are placed in the prompt and the model writes grounded
       prose. *model* is the D9-registry chat model (``local`` default), itself
       redaction-wrapped as a second line of defence.
    3. **Template assembly.** The narrative is interleaved with deterministic,
       verbatim tables (timeline, evidence refs, change requests) into a single
       Markdown body.

    Returns a dict with the ``Document`` fields (ADR-0019 §1): ``kind``
    (``"incident_report"``), ``format`` (``"md"``), ``title``, ``content``,
    and ``source_refs`` recording the session id.
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    # 1. Redact all grounding facts at the LLM boundary (A9) before any use.
    red_session = _redact_session(session)
    red_crs = _redact_change_requests(change_requests)

    session_title = str(red_session.get("title") or red_session.get("session_id") or "incident")
    title = f"Incident Report: {session_title}"

    facts = _session_facts_block(red_session, red_crs)

    # 2. LLM writes each narrative section from the redacted facts only.
    narratives: dict[str, str] = {}
    for heading, brief in _INCIDENT_NARRATIVE_SECTIONS:
        prompt = f"GROUNDING FACTS (redacted):\n{facts}\n\nWrite the '{heading}' section. {brief}"
        response = await model.ainvoke(
            [
                SystemMessage(content=_INCIDENT_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content
        narratives[heading] = content if isinstance(content, str) else str(content)

    # 3. Assemble the template with deterministic, verbatim (redacted) tables.
    content = _render_incident_markdown(
        red_session,
        red_crs,
        title=title,
        narratives=narratives,
    )

    return {
        "kind": "incident_report",
        "format": "md",
        "title": title,
        "content": content,
        "source_refs": {"session_id": session.get("session_id")},
    }


@netops_tool(classification=ToolClassification.READ_ONLY)
async def generate_incident_report(
    session: Annotated[
        dict[str, Any],
        Field(
            description=(
                "Troubleshooting session dict. Must contain at minimum: "
                "session_id, title, started_at, findings. "
                "Optional: resolved_at, timeline (list of {ts, step, evidence} dicts), "
                "evidence_refs (list of command/log refs), affected_devices (list of device ids)."
            )
        ),
    ],
    change_requests: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "ChangeRequest dicts linked to the remediation. Each dict may contain: "
                "id, kind, state, description, target_refs. Pass an empty list if none."
            )
        ),
    ] = [],  # noqa: B006 — pydantic default, not shared state
) -> str:
    """Generate an incident report from a troubleshooting session (M5 T12).

    Produces a Markdown incident report with timeline, evidence references,
    findings, and remediation ChangeRequests. The LLM writes only the Summary
    and Root Cause narrative sections, grounded in the session facts.

    **SECURITY-CRITICAL (A9 / ADR-0017 §3 / ADR-0019 §4).** Every grounding
    fact — session fields, timeline entries, findings, and CR descriptions —
    is redacted via the A9 layer (:func:`~app.llm.redaction.redact_prompt`)
    before use, so no secret value reaches the provider. The provider is
    resolved from the D9 registry (:func:`~app.llm.providers.get_chat_model`,
    ``local`` default), itself wrapped in the redacting model as a second
    line of defence.

    Returns a JSON string with the ``Document`` fields (ADR-0019 §1): ``kind``
    (``"incident_report"``), ``format`` (``"md"``), ``title``, ``content``,
    and ``source_refs`` (the session id). The caller persists it as a
    ``documents`` row and embeds it via the T8 pgvector pipeline. Read-only —
    no device or DB write.
    """
    from app.llm.providers import get_chat_model

    model = get_chat_model()
    payload = await render_incident_report(
        session,
        change_requests,
        model=model,
    )
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

#: All Documentation Agent tools registered for M4 (T10 inventory, T11 diagram,
#: T12 runbook) and M5 T12 (incident report).
DOCUMENTATION_TOOLS = [
    generate_inventory,
    generate_diagram,
    generate_runbook,
    generate_incident_report,
]

__all__ = [
    "DOCUMENTATION_TOOLS",
    "generate_diagram",
    "generate_incident_report",
    "generate_inventory",
    "generate_runbook",
    "render_incident_report",
    "render_runbook",
]
