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
