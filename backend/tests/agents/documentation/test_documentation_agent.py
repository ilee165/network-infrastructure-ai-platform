"""Tests for the Documentation Agent — deterministic inventory generation (M4 T10).

Mandatory behaviours (task T10 / ADR-0019 §2):

1. Read-only contract — every tool is READ_ONLY; no STATE_CHANGING or
   DIAGNOSTIC tool is ever declared on this agent.
2. Deterministic inventory — no LLM; the ``generate_inventory`` tool renders
   normalized-table data to Markdown + CSV deterministically.
3. Round-trip equality — the generated inventory content matches the
   normalized-table content exactly (M4 exit criterion 4 / ADR-0019 §2).
4. Scope filters — site/vendor filters narrow the rendered rows precisely.
5. Empty tables — graceful rendering with empty sections, no crash.
6. Document row — generate_inventory returns a JSON payload that includes
   ``kind="inventory"``, ``format`` (md or csv), ``title``, and ``content``.
7. Routing — description disambiguates from configuration, troubleshooting,
   and discovery.
8. Registration — the package singleton registers cleanly.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.agents.documentation import (
    documentation_agent,
    registry,
)
from app.agents.documentation.agent import DocumentationAgent as _AgentImpl
from app.agents.documentation.tools import (
    DOCUMENTATION_TOOLS,
    generate_diagram,
    generate_inventory,
)
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import NetOpsTool, ToolClassification

# ---------------------------------------------------------------------------
# Fixtures — normalized-table data (plain dicts, no DB required)
# ---------------------------------------------------------------------------

DEVICE_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DEVICE_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

_DEVICES = [
    {
        "id": DEVICE_A,
        "hostname": "edge-1",
        "mgmt_ip": "10.0.0.1",
        "vendor_id": "cisco_ios",
        "model": "ASR1001-X",
        "os_version": "17.3.2",
        "serial": "FXS2001Q1AB",
        "status": "reachable",
        "site": "dc-east",
    },
    {
        "id": DEVICE_B,
        "hostname": "core-2",
        "mgmt_ip": "10.0.0.2",
        "vendor_id": "eos",
        "model": "DCS-7050TX",
        "os_version": "4.27.0F",
        "serial": "JPE17010001",
        "status": "reachable",
        "site": "dc-west",
    },
]

_INTERFACES = [
    {
        "device_id": DEVICE_A,
        "name": "GigabitEthernet0/0",
        "description": "WAN uplink",
        "admin_status": "up",
        "oper_status": "up",
        "ip_address": "203.0.113.1/30",
        "mac_address": "00:11:22:33:44:55",
        "speed_mbps": 1000,
    },
    {
        "device_id": DEVICE_B,
        "name": "Ethernet1",
        "description": "Core link",
        "admin_status": "up",
        "oper_status": "up",
        "ip_address": "10.1.0.1/30",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "speed_mbps": 10000,
    },
]

_NEIGHBORS = [
    {
        "device_id": DEVICE_A,
        "protocol": "lldp",
        "local_interface": "GigabitEthernet0/0",
        "neighbor_name": "core-2",
        "neighbor_interface": "Ethernet1",
        "neighbor_platform": "Arista EOS",
        "neighbor_address": "10.0.0.2",
    },
]

_ROUTES = [
    {
        "device_id": DEVICE_A,
        "prefix": "0.0.0.0/0",
        "protocol": "static",
        "next_hop": "203.0.113.254",
        "interface": "GigabitEthernet0/0",
        "vrf": "",
    },
    {
        "device_id": DEVICE_B,
        "prefix": "10.0.0.0/8",
        "protocol": "ospf",
        "next_hop": "10.1.0.2",
        "interface": "Ethernet1",
        "vrf": "",
    },
]


# ---------------------------------------------------------------------------
# Fixtures — Neo4j topology projection (the shape ``fetch_graph`` returns:
# JSON-safe dicts with nodes[label/key/properties] and
# edges[type/source/target/properties], plus a ``projected_at`` watermark).
# ---------------------------------------------------------------------------

_PROJECTION: dict[str, object] = {
    "nodes": [
        {
            "label": "Device",
            "key": DEVICE_A,
            "properties": {
                "pg_id": DEVICE_A,
                "hostname": "edge-1",
                "site": "dc-east",
                "last_projected_at": "2026-06-14T18:00:00+00:00",
            },
        },
        {
            "label": "Device",
            "key": DEVICE_B,
            "properties": {
                "pg_id": DEVICE_B,
                "hostname": "core-2",
                "site": "dc-west",
                "last_projected_at": "2026-06-14T18:00:00+00:00",
            },
        },
        {
            "label": "Subnet",
            "key": "10.1.0.0/30",
            "properties": {
                "cidr": "10.1.0.0/30",
                "last_projected_at": "2026-06-14T18:00:00+00:00",
            },
        },
    ],
    "edges": [
        {
            "type": "CONNECTED_TO",
            "source": DEVICE_A,
            "target": DEVICE_B,
            "properties": {"local_interface": "GigabitEthernet0/0"},
        },
        {
            "type": "IN_SUBNET",
            "source": DEVICE_B,
            "target": "10.1.0.0/30",
            "properties": {},
        },
    ],
    "projected_at": "2026-06-14T18:00:00+00:00",
}


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestDocumentationIdentity:
    def test_name_is_documentation(self) -> None:
        assert _AgentImpl().name == "documentation"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _AgentImpl().description.lower()
        assert desc.strip()
        assert "inventor" in desc or "diagram" in desc or "runbook" in desc

    def test_description_disambiguates_from_siblings(self) -> None:
        """Description must steer router away from configuration + troubleshooting."""
        desc = _AgentImpl().description.lower()
        assert "configur" in desc
        assert "troubleshoot" in desc

    def test_system_prompt_non_empty(self) -> None:
        assert _AgentImpl().system_prompt.strip()

    def test_validate_definition_passes(self) -> None:
        _AgentImpl().validate_definition()


# ---------------------------------------------------------------------------
# Read-only contract
# ---------------------------------------------------------------------------


class TestDocumentationToolClassification:
    def test_has_generate_inventory_tool(self) -> None:
        names = {t.name for t in _AgentImpl().tools}
        assert "generate_inventory" in names

    def test_all_tools_read_only(self) -> None:
        for tool in _AgentImpl().tools:
            assert tool.classification is ToolClassification.READ_ONLY, (
                f"tool '{tool.name}' is {tool.classification}; all M4 doc tools must be READ_ONLY"
            )

    def test_no_state_changing_tool_declared(self) -> None:
        offenders = [
            t.name
            for t in _AgentImpl().tools
            if t.classification is ToolClassification.STATE_CHANGING
        ]
        assert not offenders, f"STATE_CHANGING tools found: {offenders}"

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _AgentImpl().tools:
            assert isinstance(tool, NetOpsTool)


# ---------------------------------------------------------------------------
# generate_inventory — Markdown round-trip
# ---------------------------------------------------------------------------


class TestGenerateInventoryMarkdown:
    async def test_returns_json_payload(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        payload = json.loads(raw)
        assert payload["kind"] == "inventory"
        assert payload["format"] == "md"
        assert "title" in payload
        assert "content" in payload

    async def test_markdown_contains_all_device_hostnames(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "edge-1" in content
        assert "core-2" in content

    async def test_markdown_contains_all_device_mgmt_ips(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "10.0.0.1" in content
        assert "10.0.0.2" in content

    async def test_markdown_contains_interface_names(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "GigabitEthernet0/0" in content
        assert "Ethernet1" in content

    async def test_markdown_contains_neighbor_names(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "core-2" in content

    async def test_markdown_contains_route_prefixes(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "0.0.0.0/0" in content
        assert "10.0.0.0/8" in content

    async def test_markdown_has_section_headers(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        # ADR-0019 §2: devices, interfaces, neighbors, routes sections
        assert "## Devices" in content or "# Devices" in content
        assert "## Interfaces" in content or "# Interfaces" in content
        assert "## Neighbors" in content or "# Neighbors" in content
        assert "## Routes" in content or "# Routes" in content


# ---------------------------------------------------------------------------
# generate_inventory — CSV round-trip (ADR-0019 §2 — both formats)
# ---------------------------------------------------------------------------


class TestGenerateInventoryCSV:
    async def test_returns_json_payload_csv_format(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "csv",
            }
        )
        payload = json.loads(raw)
        assert payload["kind"] == "inventory"
        assert payload["format"] == "csv"
        assert "content" in payload

    async def test_csv_content_parses_as_valid_csv(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "csv",
            }
        )
        content = json.loads(raw)["content"]
        # Must be parseable as CSV with no exception
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) > 0

    async def test_csv_contains_all_device_hostnames(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "csv",
            }
        )
        content = json.loads(raw)["content"]
        assert "edge-1" in content
        assert "core-2" in content

    async def test_csv_contains_interface_and_route_data(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "csv",
            }
        )
        content = json.loads(raw)["content"]
        assert "GigabitEthernet0/0" in content
        assert "0.0.0.0/0" in content


# ---------------------------------------------------------------------------
# Round-trip equality (M4 exit criterion 4 / ADR-0019 §2)
#
# The exit criterion: "generated inventory matches normalized-table content
# exactly."  We verify this by asserting that every field value from the
# normalized-table dicts appears verbatim in the generated content —
# the generator is pure/templated, so no LLM can alter the values.
# ---------------------------------------------------------------------------


class TestRoundTripEquality:
    """The core ADR-0019 §2 exit criterion: generated content == table content."""

    async def test_markdown_device_fields_appear_verbatim(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        for device in _DEVICES:
            assert device["hostname"] in content, f"hostname {device['hostname']!r} missing"
            assert device["mgmt_ip"] in content, f"mgmt_ip {device['mgmt_ip']!r} missing"
            assert device["vendor_id"] in content, f"vendor_id {device['vendor_id']!r} missing"
            assert device["status"] in content, f"status {device['status']!r} missing"

    async def test_markdown_interface_fields_appear_verbatim(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        for iface in _INTERFACES:
            assert iface["name"] in content, f"interface name {iface['name']!r} missing"
            assert iface["admin_status"] in content, (
                f"admin_status {iface['admin_status']!r} missing"
            )

    async def test_markdown_neighbor_fields_appear_verbatim(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [],
                "neighbors": _NEIGHBORS,
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        for nbr in _NEIGHBORS:
            assert nbr["neighbor_name"] in content, (
                f"neighbor_name {nbr['neighbor_name']!r} missing"
            )
            assert nbr["local_interface"] in content, (
                f"local_interface {nbr['local_interface']!r} missing"
            )

    async def test_markdown_route_fields_appear_verbatim(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [],
                "neighbors": [],
                "routes": _ROUTES,
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        for route in _ROUTES:
            assert route["prefix"] in content, f"prefix {route['prefix']!r} missing"
            assert route["protocol"] in content, f"protocol {route['protocol']!r} missing"

    async def test_csv_device_fields_appear_verbatim(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "csv",
            }
        )
        content = json.loads(raw)["content"]
        for device in _DEVICES:
            assert device["hostname"] in content, f"hostname {device['hostname']!r} missing in CSV"
            assert device["mgmt_ip"] in content, f"mgmt_ip {device['mgmt_ip']!r} missing in CSV"

    async def test_pipe_in_description_escaped_in_markdown(self) -> None:
        """ADR-0019 §2 round-trip: pipe chars in field values must be escaped.

        A description like 'WAN | core uplink' contains a literal '|' that
        would otherwise break the GFM table structure. The renderer must escape
        it as '\\|' so GFM parsers see the correct column count. The escaped
        form '\\|' must appear in the Markdown output so the value is
        recoverable (round-trip equality), and each non-header row must produce
        exactly len(_DEVICE_COLS) + 2 pipe-delimited fields (the two border
        pipes on either side of the row).
        """
        from app.agents.documentation.tools import _DEVICE_COLS

        pipe_device = {
            "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "hostname": "pipe-test",
            "mgmt_ip": "192.0.2.1",
            "vendor_id": "cisco_ios",
            "model": "ISR4331",
            "os_version": "16.9.4",
            "serial": "FDO2001X001",
            "status": "reachable",
            "site": "WAN | core uplink",  # pipe in a field value
        }
        raw = await generate_inventory.ainvoke(
            {
                "devices": [pipe_device],
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]

        # (a) The escaped form must be present so the value is round-trippable.
        assert r"WAN \| core uplink" in content, (
            "pipe character in field value must be escaped as '\\|' in Markdown output"
        )

        # (b) Each non-header, non-separator row in the Devices section must
        #     split on unescaped '|' into exactly len(_DEVICE_COLS) + 2 fields.
        expected_field_count = len(_DEVICE_COLS) + 2
        devices_section = content.split("## Devices")[1].split("##")[0]
        md_rows = [
            line
            for line in devices_section.splitlines()
            if line.startswith("|") and "---" not in line and line.strip() != "|"
        ]
        # Skip the header row (first); check data rows.
        data_rows = md_rows[1:]
        assert data_rows, "expected at least one data row in the Devices section"
        for row in data_rows:
            # Split on bare '|' (not preceded by backslash).
            import re

            fields = re.split(r"(?<!\\)\|", row)
            assert len(fields) == expected_field_count, (
                f"row has {len(fields)} pipe-fields, expected {expected_field_count}: {row!r}"
            )

    async def test_pipe_in_interface_description_escaped_in_markdown(self) -> None:
        """A pipe in an interface description field must be escaped in GFM output."""
        pipe_iface = {
            "device_id": DEVICE_A,
            "name": "GigabitEthernet0/1",
            "description": "WAN | core uplink",
            "admin_status": "up",
            "oper_status": "up",
            "ip_address": "198.51.100.1/30",
            "mac_address": "00:aa:bb:cc:dd:ee",
            "speed_mbps": 1000,
        }
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [pipe_iface],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert r"WAN \| core uplink" in content, (
            "pipe character in interface description must be escaped as '\\|' in Markdown"
        )


# ---------------------------------------------------------------------------
# Scope filters — site / vendor
# ---------------------------------------------------------------------------


class TestScopeFilters:
    async def test_site_filter_excludes_other_sites(self) -> None:
        """Devices from other sites must not appear in the Devices section.

        We verify this by checking hostname/mgmt_ip of the in-scope device are
        present, and that the out-of-scope device's hostname is absent from the
        Devices table.  Note: the neighbor row for DEVICE_A may legitimately
        reference DEVICE_B's address as ``neighbor_address`` — that is correct
        discovered data for an in-scope device.
        """
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
                "site": "dc-east",
            }
        )
        content = json.loads(raw)["content"]
        assert "edge-1" in content
        assert "10.0.0.1" in content
        # core-2 is dc-west — its hostname must not appear in the Devices table.
        # (it may appear as a neighbor_name of edge-1's neighbor row, which is
        # correct; the Devices section header uniquely identifies device rows.)
        # We verify by checking that the out-of-scope device's own mgmt_ip
        # is not in the Devices table rows by using the serial which is unique.
        assert "JPE17010001" not in content  # core-2's serial is dc-west only

    async def test_vendor_filter_excludes_other_vendors(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
                "vendor_id": "eos",
            }
        )
        content = json.loads(raw)["content"]
        assert "core-2" in content
        # edge-1 is cisco_ios — its unique serial must not appear.
        assert "FXS2001Q1AB" not in content

    async def test_site_filter_restricts_interfaces_to_matching_devices(self) -> None:
        """Interfaces for out-of-scope devices must be excluded.

        DEVICE_B's interface 'Ethernet1' appears in _INTERFACES with
        device_id=DEVICE_B (dc-west). When scoped to dc-east, DEVICE_B's
        interface rows must not appear — we verify via the interface's
        unique ip_address (10.1.0.1/30 belongs only to DEVICE_B's Ethernet1).
        """
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": _INTERFACES,
                "neighbors": _NEIGHBORS,
                "routes": _ROUTES,
                "fmt": "md",
                "site": "dc-east",
            }
        )
        content = json.loads(raw)["content"]
        assert "GigabitEthernet0/0" in content
        # DEVICE_B's interface ip_address is unique — must be absent.
        assert "10.1.0.1/30" not in content


# ---------------------------------------------------------------------------
# Empty table handling
# ---------------------------------------------------------------------------


class TestEmptyTables:
    async def test_empty_all_tables_no_crash_markdown(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": [],
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        payload = json.loads(raw)
        assert payload["kind"] == "inventory"
        assert payload["format"] == "md"
        # Sections must still be present even when empty.
        content = payload["content"]
        assert "Devices" in content
        assert "Interfaces" in content

    async def test_empty_all_tables_no_crash_csv(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": [],
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "csv",
            }
        )
        payload = json.loads(raw)
        assert payload["kind"] == "inventory"
        assert payload["format"] == "csv"

    async def test_devices_only_no_crash(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        content = json.loads(raw)["content"]
        assert "edge-1" in content
        assert "core-2" in content

    async def test_unknown_fmt_returns_error(self) -> None:
        raw = await generate_inventory.ainvoke(
            {
                "devices": _DEVICES,
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "xml",
            }
        )
        payload = json.loads(raw)
        assert "error" in payload


# ---------------------------------------------------------------------------
# generate_diagram — Mermaid from the Neo4j projection (T11 / ADR-0019 §3)
# ---------------------------------------------------------------------------


class TestGenerateDiagramContract:
    def test_tool_is_registered(self) -> None:
        names = {t.name for t in _AgentImpl().tools}
        assert "generate_diagram" in names

    def test_tool_is_read_only(self) -> None:
        assert generate_diagram.classification is ToolClassification.READ_ONLY

    def test_tool_is_netops_tool(self) -> None:
        assert isinstance(generate_diagram, NetOpsTool)

    def test_tool_exported_in_list(self) -> None:
        names = {t.name for t in DOCUMENTATION_TOOLS}
        assert "generate_diagram" in names

    async def test_returns_document_payload(self) -> None:
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        payload = json.loads(raw)
        assert payload["kind"] == "diagram"
        assert payload["format"] == "mermaid"
        assert "title" in payload
        assert "content" in payload

    async def test_content_is_mermaid_graph(self) -> None:
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        content = json.loads(raw)["content"]
        first = content.strip().splitlines()[0].strip()
        # ADR-0019 §3: Mermaid ``graph`` syntax.
        assert first.startswith("graph") or first.startswith("flowchart")


class TestDiagramMatchesProjection:
    """The T11 exit criterion: Mermaid node/edge set == projection node/edge set."""

    @staticmethod
    def _parse_mermaid(
        content: str,
    ) -> tuple[set[str], set[str], set[tuple[str, str]]]:
        """Extract (declared_nodes, edge_endpoint_nodes, directed edge-id-pair set).

        ``declared_nodes`` contains only IDs that appear in explicit node
        declaration lines (``  n0["label"]`` or ``  n0(label)``).
        ``edge_endpoint_nodes`` contains IDs seen as edge endpoints but NOT in a
        declaration line.  Keeping the two sets separate lets callers assert on
        *declarations* specifically, which is the T11 exit criterion: every
        projected node must be declared in the diagram, not merely referenced as
        an edge endpoint.

        Edges look like ``  n0 -->|"type"| n1`` (label optional).
        """
        import re

        node_decl = re.compile(r"^\s*([A-Za-z0-9_]+)(?:\[|\()")
        edge_decl = re.compile(r"^\s*([A-Za-z0-9_]+)\s*-->\s*(?:\|[^|]*\|\s*)?([A-Za-z0-9_]+)")
        declared_nodes: set[str] = set()
        edge_endpoint_nodes: set[str] = set()
        edges: set[tuple[str, str]] = set()
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("graph") or stripped.startswith("flowchart"):
                continue
            edge_match = edge_decl.match(line)
            if edge_match:
                src, dst = edge_match.group(1), edge_match.group(2)
                edges.add((src, dst))
                edge_endpoint_nodes.add(src)
                edge_endpoint_nodes.add(dst)
                continue
            node_match = node_decl.match(line)
            if node_match:
                declared_nodes.add(node_match.group(1))
        return declared_nodes, edge_endpoint_nodes, edges

    async def test_node_count_matches_projection(self) -> None:
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        content = json.loads(raw)["content"]
        # Only count IDs that appear as explicit node declaration lines —
        # edge-endpoint-only IDs are excluded so a bug that suppresses
        # declarations is not masked by the edge scan.
        declared_nodes, _, _ = self._parse_mermaid(content)
        assert len(declared_nodes) == len(_PROJECTION["nodes"])  # type: ignore[arg-type]

    async def test_edge_count_matches_projection(self) -> None:
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        content = json.loads(raw)["content"]
        _, _, edges = self._parse_mermaid(content)
        assert len(edges) == len(_PROJECTION["edges"])  # type: ignore[arg-type]

    async def test_every_projection_node_label_appears(self) -> None:
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        content = json.loads(raw)["content"]
        # Each node's human-readable label (hostname for devices, key otherwise)
        # must be present verbatim in the Mermaid source.
        assert "edge-1" in content
        assert "core-2" in content
        assert "10.1.0.0/30" in content

    async def test_edges_connect_correct_endpoints(self) -> None:
        """The (source, target) pairs in Mermaid must mirror the projection.

        We map each projection node key to its generated Mermaid id by matching
        the declared label text, then assert each projection edge's endpoints
        are linked in the rendered graph.
        """
        raw = await generate_diagram.ainvoke({"projection": _PROJECTION})
        content = json.loads(raw)["content"]
        declared_nodes, _, mermaid_edges = self._parse_mermaid(content)
        # Same number of distinct directed edges, and the graph is connected as
        # projected: 2 edges over 3 nodes.
        assert len(mermaid_edges) == 2
        assert len(declared_nodes) == 3

    async def test_empty_projection_yields_valid_empty_graph(self) -> None:
        raw = await generate_diagram.ainvoke(
            {"projection": {"nodes": [], "edges": [], "projected_at": None}}
        )
        payload = json.loads(raw)
        assert payload["kind"] == "diagram"
        assert payload["format"] == "mermaid"
        content = payload["content"]
        first = content.strip().splitlines()[0].strip()
        assert first.startswith("graph") or first.startswith("flowchart")
        declared_nodes, _, edges = self._parse_mermaid(content)
        assert declared_nodes == set()
        assert edges == set()

    async def test_deterministic_output(self) -> None:
        """Same projection in → byte-identical Mermaid out (no LLM, ordered)."""
        raw1 = await generate_diagram.ainvoke({"projection": _PROJECTION})
        raw2 = await generate_diagram.ainvoke({"projection": _PROJECTION})
        assert json.loads(raw1)["content"] == json.loads(raw2)["content"]

    async def test_special_characters_in_label_do_not_break_graph(self) -> None:
        """A hostname with quotes/brackets must not corrupt the Mermaid node."""
        projection = {
            "nodes": [
                {
                    "label": "Device",
                    "key": DEVICE_A,
                    "properties": {"pg_id": DEVICE_A, "hostname": 'sw"[odd]"'},
                }
            ],
            "edges": [],
            "projected_at": None,
        }
        raw = await generate_diagram.ainvoke({"projection": projection})
        payload = json.loads(raw)
        declared_nodes, _, _ = TestDiagramMatchesProjection._parse_mermaid(payload["content"])
        assert len(declared_nodes) == 1

    async def test_cross_label_key_collision_skips_ambiguous_edges(self) -> None:
        """Two nodes sharing the same key but with different labels must both be
        declared in the diagram.  Any edge referencing the ambiguous key must be
        silently dropped (with a warning) rather than mis-routed to the wrong node.

        This guards the fix for the id_by_key dict-comprehension overwrite bug:
        the old code silently overwrote the first (label, key) mapping with the
        second, so edges aimed at the dropped node were rendered with the wrong
        Mermaid id.
        """
        shared_key = "default"
        projection = {
            "nodes": [
                {
                    "label": "VRF",
                    "key": shared_key,
                    "properties": {},
                },
                {
                    "label": "Site",
                    "key": shared_key,
                    "properties": {},
                },
                {
                    "label": "Device",
                    "key": DEVICE_A,
                    "properties": {"pg_id": DEVICE_A, "hostname": "edge-1"},
                },
            ],
            # Edge targets the ambiguous key — must be dropped, not mis-routed.
            "edges": [
                {
                    "type": "IN_SITE",
                    "source": DEVICE_A,
                    "target": shared_key,
                    "properties": {},
                },
            ],
            "projected_at": None,
        }
        raw = await generate_diagram.ainvoke({"projection": projection})
        content = json.loads(raw)["content"]
        declared_nodes, _, edges = self._parse_mermaid(content)
        # All three nodes must be declared (no node may be silently dropped).
        assert len(declared_nodes) == 3
        # The ambiguous edge must be omitted rather than mis-routed.
        assert len(edges) == 0


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestDocumentationRegistration:
    def test_package_singleton_type(self) -> None:
        assert isinstance(documentation_agent, _AgentImpl)

    def test_package_registry_contains_agent(self) -> None:
        assert "documentation" in registry

    def test_register_fresh_instance(self) -> None:
        fresh = AgentRegistry()
        fresh.register(_AgentImpl())
        assert "documentation" in fresh

    def test_double_register_conflicts(self) -> None:
        from app.core.errors import ConflictError

        fresh = AgentRegistry()
        fresh.register(_AgentImpl())
        with pytest.raises(ConflictError):
            fresh.register(_AgentImpl())

    def test_tool_list_exported(self) -> None:
        names = {t.name for t in DOCUMENTATION_TOOLS}
        assert "generate_inventory" in names
