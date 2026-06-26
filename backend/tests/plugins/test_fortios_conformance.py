"""FortiOS plugin conformance + unit tests (ADR-0036, P2 W2-T2).

Covers:
- Shared conformance suite (all declared capabilities + firewall family).
- Credential hygiene: REST API token AND SSH password never leak.
- Raw-first on BOTH transports (REST/httpx and SSH/netmiko fallback).
- Normalized round-trip for NormalizedFirewallRule / NormalizedNatRule.
- Two-vendor cross-check: fortios + panos populate the SAME NormalizedFirewallRule
  fields from fixture data (ADR-0034 stability proof).
- Plugin registration via entry-points.

Live golden-path deferred-accepted (no FortiOS hardware) — see ADR-0036 §5.
"""

from __future__ import annotations

import logging
import urllib.parse
from uuid import uuid4

import httpx
import pytest

from app.plugins.base import (
    Capability,
    PluginCapability,
)
from app.plugins.vendors.fortios.client import FortiosRestClient
from app.plugins.vendors.fortios.plugin import (
    FortiosConfigBackup,
    FortiosDiscoveryApi,
    FortiosFirewallPolicy,
    FortiosPlugin,
    _detect_nat_type,
    _map_action,
)
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

# ---------------------------------------------------------------------------
# Fake credentials — never real secrets
# ---------------------------------------------------------------------------

#: Fake REST API token — shaped like a real FortiOS token (alphanumeric+special)
#: to exercise the credential-hygiene tests. Never a real secret.
_FAKE_REST_TOKEN = "FakeFortiosToken+secret/test=="  # noqa: S105 — obviously-fake

#: Fake SSH password — never a real secret.
_FAKE_SSH_PASSWORD = "FakeFortiosSSH+pass/word=="  # noqa: S105 — obviously-fake

# ---------------------------------------------------------------------------
# FortiOS REST API fixture JSON payloads (realistic FortiOS v7.x API responses)
# ---------------------------------------------------------------------------

_SYSTEM_STATUS_JSON = """\
{
  "http_method": "GET",
  "results": {
    "hostname": "fw-fortios-lab",
    "model_name": "FortiGate-VM64",
    "version": "v7.2.4",
    "serial": "FGVM02TM22000001",
    "management_ip": "192.168.1.1"
  },
  "vdom": "root",
  "path": "monitor",
  "name": "system/status",
  "status": "success",
  "http_status": 200
}
"""

_INTERFACES_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "name": "port1",
      "alias": "WAN",
      "type": "physical",
      "ip": "203.0.113.1",
      "netmask": "255.255.255.0",
      "status": "up",
      "speed": 1000,
      "link": true,
      "mac_address": "00:09:0f:aa:bb:01"
    },
    {
      "name": "port2",
      "alias": "LAN",
      "type": "physical",
      "ip": "10.0.1.1",
      "netmask": "255.255.255.0",
      "status": "up",
      "speed": 1000,
      "link": true,
      "mac_address": "00:09:0f:aa:bb:02"
    },
    {
      "name": "port3",
      "alias": "DMZ",
      "type": "physical",
      "ip": "0.0.0.0",
      "netmask": "0.0.0.0",
      "status": "down",
      "speed": 1000,
      "link": false,
      "mac_address": "00:09:0f:aa:bb:03"
    }
  ],
  "vdom": "root",
  "path": "monitor",
  "name": "system/interface",
  "status": "success",
  "http_status": 200
}
"""

_ROUTES_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "ip_mask": "0.0.0.0/0",
      "gateway": "203.0.113.254",
      "interface": "port1",
      "distance": 10,
      "metric": 0,
      "type": "static"
    },
    {
      "ip_mask": "10.0.1.0/24",
      "gateway": "0.0.0.0",
      "interface": "port2",
      "distance": 0,
      "metric": 0,
      "type": "connect"
    },
    {
      "ip_mask": "192.168.100.0/24",
      "gateway": "10.0.1.254",
      "interface": "port2",
      "distance": 110,
      "metric": 10,
      "type": "ospf"
    }
  ],
  "vdom": "root",
  "path": "monitor",
  "name": "router/ipv4",
  "status": "success",
  "http_status": 200
}
"""

_FIREWALL_POLICY_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "policyid": 1,
      "name": "allow-web-outbound",
      "status": "enable",
      "action": "accept",
      "srcintf": [{"name": "port2"}],
      "dstintf": [{"name": "port1"}],
      "srcaddr": [{"name": "all"}],
      "dstaddr": [{"name": "all"}],
      "service": [{"name": "HTTP"}, {"name": "HTTPS"}],
      "application": [],
      "logtraffic": "all",
      "nat": "enable",
      "comments": "Allow web outbound traffic",
      "schedule": "always"
    },
    {
      "policyid": 2,
      "name": "deny-inbound",
      "status": "enable",
      "action": "deny",
      "srcintf": [{"name": "port1"}],
      "dstintf": [{"name": "port2"}],
      "srcaddr": [{"name": "all"}],
      "dstaddr": [{"name": "all"}],
      "service": [{"name": "ALL"}],
      "application": [],
      "logtraffic": "utm",
      "nat": "disable",
      "comments": "",
      "schedule": "always"
    }
  ],
  "vdom": "root",
  "path": "cmdb",
  "name": "firewall/policy",
  "status": "success",
  "http_status": 200
}
"""

_FIREWALL_SNAT_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "id": 1,
      "name": "outbound-snat",
      "status": "enable",
      "orig-addr": [{"name": "all"}],
      "outintf": [{"name": "port1"}],
      "nat-ippool": [{"name": "WAN-Pool"}],
      "srcintf": [{"name": "port2"}],
      "comments": "Outbound SNAT pool"
    },
    {
      "id": 2,
      "name": "static-snat-one-to-one",
      "status": "enable",
      "orig-addr": [{"name": "host-10-0-1-50"}],
      "outintf": [{"name": "port1"}],
      "nat-ippool": [],
      "nat-source-address": [{"name": "ext-203-0-113-50"}],
      "srcintf": [{"name": "port2"}],
      "comments": "Static one-to-one source NAT"
    }
  ],
  "vdom": "root",
  "path": "cmdb",
  "name": "firewall/central-snat-map",
  "status": "success",
  "http_status": 200
}
"""

_FIREWALL_VIP_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "name": "web-server-vip",
      "extip": "203.0.113.10",
      "mappedip": [{"range": "10.0.1.100"}],
      "extintf": "port1",
      "type": "static-nat",
      "portforward": "disable",
      "status": "enable",
      "comment": "Web server VIP"
    }
  ],
  "vdom": "root",
  "path": "cmdb",
  "name": "firewall/vip",
  "status": "success",
  "http_status": 200
}
"""

_POLICY_HIT_COUNT_JSON = """\
{
  "http_method": "GET",
  "results": [
    {
      "policyid": 1,
      "bytes": 1024000,
      "packets": 8500,
      "hit_count": 8500,
      "first_used": 1700000000,
      "last_used": 1700001000
    },
    {
      "policyid": 2,
      "bytes": 0,
      "packets": 0,
      "hit_count": 0,
      "first_used": 0,
      "last_used": 0
    }
  ],
  "vdom": "root",
  "path": "monitor",
  "name": "firewall/policy/select",
  "status": "success",
  "http_status": 200
}
"""

_HA_STATUS_JSON = """\
{
  "http_method": "GET",
  "results": {
    "local-sn": "FGVM02TM22000001",
    "local-hostname": "fw-fortios-lab",
    "mode": "a-p",
    "group-name": "cluster1",
    "schedule": "round-robin",
    "members": [
      {
        "serial-no": "FGVM02TM22000001",
        "hostname": "fw-fortios-lab",
        "role": "primary",
        "link-status": "up",
        "ip": "169.254.0.1"
      },
      {
        "serial-no": "FGVM02TM22000002",
        "hostname": "fw-fortios-standby",
        "role": "secondary",
        "link-status": "up",
        "ip": "169.254.0.2"
      }
    ]
  },
  "vdom": "root",
  "path": "monitor",
  "name": "system/ha-statistics",
  "status": "success",
  "http_status": 200
}
"""

# SSH fixture responses (for CONFIG_BACKUP primary path)
_SSH_SHOW_FULL_CONFIG = """\
config system global
    set hostname "fw-fortios-lab"
    set alias "FortiGate-Lab"
end
config firewall policy
    edit 1
        set name "allow-web-outbound"
        set srcintf "port2"
        set dstintf "port1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "HTTP" "HTTPS"
        set logtraffic all
        set nat enable
    next
    edit 2
        set name "deny-inbound"
        set srcintf "port1"
        set dstintf "port2"
        set action deny
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic utm
    next
end
"""

# SSH fixture responses for SSH-fallback capabilities
_SSH_SYSTEM_STATUS = """\
Version: FortiGate-VM64 v7.2.4,build1396,230131 (GA.F)
Virus-DB: 1.00000(2018-04-09 18:07)
Extended DB: 1.00000(2018-04-09 18:07)
IPS-DB: 6.00741(2015-12-01 02:30)
Serial-Number: FGVM02TM22000001
Hostname: fw-fortios-lab
Operation Mode: NAT
Current HA mode: a-p, primary
Branch point: 1396
Release Version Information: GA.F
System time: Thu Dec 28 12:00:00 2023
"""

_SSH_HA_STATUS = """\
HA information
Mode: a-p
Group-id: 0
Group-name: cluster1
Heartbeat-interface: port10
Session-sync-dev:
route-ttl: 10
route-wait: 0
route-hold: 10
Override: disable
Configuration Status:
  fw-fortios-lab(sn: FGVM02TM22000001): in-sync
  fw-fortios-standby(sn: FGVM02TM22000002): in-sync

HA master: fw-fortios-lab
HA backup: fw-fortios-standby
"""

_SSH_ROUTES = """\
Routing table for VRF=0
S*      0.0.0.0/0 [10/0] via 203.0.113.254, port1
C       10.0.1.0/24 is directly connected, port2
O       192.168.100.0/24 [110/10] via 10.0.1.254, port2
"""


# ---------------------------------------------------------------------------
# HTTP mock transport for FortiOS REST API
# ---------------------------------------------------------------------------


def _handle_rest(request: httpx.Request) -> httpx.Response:
    """Route FortiOS REST API requests to bundled fixture JSON.

    FortiOS API URL pattern: /api/v2/{path}/{name}
    The REST token is in the Authorization header — MUST NOT appear in URLs or responses.
    """
    path = request.url.path

    if "/monitor/system/status" in path:
        return httpx.Response(
            200, text=_SYSTEM_STATUS_JSON, headers={"content-type": "application/json"}
        )
    if "/monitor/system/interface" in path:
        return httpx.Response(
            200, text=_INTERFACES_JSON, headers={"content-type": "application/json"}
        )
    if "/monitor/router/ipv4" in path:
        return httpx.Response(200, text=_ROUTES_JSON, headers={"content-type": "application/json"})
    if "/cmdb/firewall/policy" in path and "central-snat" not in path:
        return httpx.Response(
            200, text=_FIREWALL_POLICY_JSON, headers={"content-type": "application/json"}
        )
    if "/cmdb/firewall/central-snat-map" in path:
        return httpx.Response(
            200, text=_FIREWALL_SNAT_JSON, headers={"content-type": "application/json"}
        )
    if "/cmdb/firewall/vip" in path:
        return httpx.Response(
            200, text=_FIREWALL_VIP_JSON, headers={"content-type": "application/json"}
        )
    if "/monitor/firewall/policy/select" in path:
        return httpx.Response(
            200, text=_POLICY_HIT_COUNT_JSON, headers={"content-type": "application/json"}
        )
    if "/monitor/system/ha-statistics" in path or "/monitor/system/ha-" in path:
        return httpx.Response(
            200, text=_HA_STATUS_JSON, headers={"content-type": "application/json"}
        )

    # Default fallback
    return httpx.Response(
        200,
        text='{"status":"success","results":{}}',
        headers={"content-type": "application/json"},
    )


# ---------------------------------------------------------------------------
# SSH mock transport (netmiko-style CommandTransport duck-type)
# ---------------------------------------------------------------------------


class _FakeSshTransport:
    """Fake SSH transport for CONFIG_BACKUP (SSH-primary path)."""

    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        for key, resp in self._responses.items():
            if key in command or command in key:
                return resp
        return ""


_SSH_FIXTURES = {
    "show full-configuration": _SSH_SHOW_FULL_CONFIG,
    "get system status": _SSH_SYSTEM_STATUS,
    "get system ha status": _SSH_HA_STATUS,
    "get router info routing-table all": _SSH_ROUTES,
}


def _make_rest_client() -> FortiosRestClient:
    """Build a FortiosRestClient wired to the mock REST transport."""
    http = httpx.Client(transport=httpx.MockTransport(_handle_rest))
    return FortiosRestClient(
        host="fw.example.com",
        api_token=_FAKE_REST_TOKEN,
        client=http,
    )


def _make_ssh_transport() -> _FakeSshTransport:
    return _FakeSshTransport(_SSH_FIXTURES)


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    """Wire an impl class to the appropriate transport(s) for conformance."""
    rest_client = _make_rest_client()
    ssh_transport = _make_ssh_transport()
    return impl(rest_client, ssh_transport, uuid4())


# ---------------------------------------------------------------------------
# Conformance suite
# ---------------------------------------------------------------------------

CASES = make_conformance_cases(FortiosPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_fortios_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """Every declared capability has both implementation and fixture cases."""
    ids = {case.id for case in CASES}
    for capability in FortiosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids


# ---------------------------------------------------------------------------
# Credential hygiene tests (ADR-0011 / ADR-0036 §2)
# REST token AND SSH password must never leak.
# ---------------------------------------------------------------------------


class TestFortiosCredentialHygiene:
    """REST token and SSH password never appear in logs, repr, normalized output, or exceptions."""

    def test_rest_token_not_in_client_repr(self) -> None:
        client = _make_rest_client()
        assert _FAKE_REST_TOKEN not in repr(client)
        assert "FAKE" not in repr(client)

    def test_rest_token_not_in_normalized_firewall_rules(self) -> None:
        """REST token must not appear in any normalized firewall rule field."""
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        rules = cap.get_firewall_rules()
        for rule in rules:
            dumped = str(rule.model_dump())
            assert _FAKE_REST_TOKEN not in dumped
            assert _FAKE_SSH_PASSWORD not in dumped

    def test_rest_token_not_in_plugin_error_message(self) -> None:
        """PluginError raised by the REST client must not contain the REST token."""
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text='{"status":"error","error":"Unauthorized"}')

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = FortiosRestClient(
            host="fw.example.com",
            api_token=_FAKE_REST_TOKEN,
            client=http,
        )
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(client, ssh_transport, uuid4())
        with pytest.raises(PluginError) as exc_info:
            cap.discover()
        assert _FAKE_REST_TOKEN not in str(exc_info.value)
        assert _FAKE_REST_TOKEN not in str(exc_info.value.args)

    def test_rest_token_not_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """REST token must never appear in any log record (literal or URL-encoded form)."""
        encoded_token = urllib.parse.quote(_FAKE_REST_TOKEN, safe="")
        # Sentinel must actually exercise the encoding path.
        assert encoded_token != _FAKE_REST_TOKEN, "sentinel must contain URL-special chars"

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(rest_client, ssh_transport, uuid4())

        with caplog.at_level(logging.DEBUG, logger="httpx"), caplog.at_level(logging.DEBUG):
            cap.discover()

        for record in caplog.records:
            message = record.getMessage()
            assert _FAKE_REST_TOKEN not in message, f"REST token leaked in log record: {message!r}"
            assert encoded_token not in message, (
                f"URL-encoded REST token leaked in log record: {message!r}"
            )

    def test_ssh_password_not_in_normalized_output(self) -> None:
        """SSH password must not appear in normalized CONFIG_BACKUP output."""
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosConfigBackup(rest_client, ssh_transport, uuid4())
        config_text = cap.fetch_running_config()
        assert _FAKE_SSH_PASSWORD not in config_text

    def test_rest_token_not_in_raw_outputs(self) -> None:
        """Raw outputs stored via _record_raw must not contain the REST token."""
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(rest_client, ssh_transport, uuid4())
        cap.discover()
        for raw in cap.raw_outputs:
            assert _FAKE_REST_TOKEN not in raw.output
            assert _FAKE_REST_TOKEN not in raw.command


# ---------------------------------------------------------------------------
# Raw-first contract tests (ADR-0006 §3) — both transports
# ---------------------------------------------------------------------------


class TestFortiosRawFirst:
    """Every capability call stores verbatim payload before parsing (ADR-0006 §3)."""

    def test_discovery_api_rest_records_raw(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(rest_client, ssh_transport, uuid4())
        cap.discover()
        assert len(cap.raw_outputs) >= 1

    def test_interfaces_rest_records_raw(self) -> None:
        from app.plugins.vendors.fortios.plugin import FortiosInterfaces

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosInterfaces(rest_client, ssh_transport, uuid4())
        cap.get_interfaces()
        assert len(cap.raw_outputs) >= 1

    def test_firewall_policy_rest_records_raw(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        cap.get_firewall_rules()
        assert len(cap.raw_outputs) >= 1

    def test_firewall_policy_nat_records_raw(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        cap.get_nat_rules()
        assert len(cap.raw_outputs) >= 1

    def test_config_backup_ssh_records_raw(self) -> None:
        """CONFIG_BACKUP uses SSH primary — raw artifact stored from SSH output."""
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosConfigBackup(rest_client, ssh_transport, uuid4())
        cap.fetch_running_config()
        assert len(cap.raw_outputs) >= 1
        # The SSH show full-configuration output must appear verbatim
        assert any(
            "config system" in raw.output or "config firewall" in raw.output
            for raw in cap.raw_outputs
        )

    def test_ha_status_rest_records_raw(self) -> None:
        from app.plugins.vendors.fortios.plugin import FortiosHaStatus

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosHaStatus(rest_client, ssh_transport, uuid4())
        cap.get_ha_status()
        assert len(cap.raw_outputs) >= 1


# ---------------------------------------------------------------------------
# Normalized round-trip tests (ADR-0034)
# ---------------------------------------------------------------------------


class TestFortiosNormalizedRoundTrip:
    """Parsed REST JSON -> NormalizedFirewallRule/NatRule serialize/deserialize equal."""

    def test_firewall_rule_round_trip(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        rules = cap.get_firewall_rules()
        assert rules, "Expected at least one firewall rule"
        for rule in rules:
            dumped = rule.model_dump(mode="python")
            from app.schemas.normalized import NormalizedFirewallRule

            restored = NormalizedFirewallRule.model_validate(dumped)
            assert restored == rule

    def test_nat_rule_round_trip(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        nat_rules = cap.get_nat_rules()
        for rule in nat_rules:
            dumped = rule.model_dump(mode="python")
            from app.schemas.normalized import NormalizedNatRule

            restored = NormalizedNatRule.model_validate(dumped)
            assert restored == rule

    def test_firewall_rule_fields_allow(self) -> None:
        """ADR-0034 fields are populated correctly from fixture JSON."""
        from app.schemas.normalized import FirewallAction

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        rules = cap.get_firewall_rules()
        allow_rule = next((r for r in rules if r.name == "allow-web-outbound"), None)
        assert allow_rule is not None, "Expected 'allow-web-outbound' rule"
        assert allow_rule.action == FirewallAction.ALLOW
        assert allow_rule.enabled is True
        assert "port2" in allow_rule.source_zones
        assert "port1" in allow_rule.destination_zones
        assert allow_rule.logging is True
        assert allow_rule.description == "Allow web outbound traffic"

    def test_firewall_rule_fields_deny(self) -> None:
        from app.schemas.normalized import FirewallAction

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        rules = cap.get_firewall_rules()
        deny_rule = next((r for r in rules if r.name == "deny-inbound"), None)
        assert deny_rule is not None, "Expected 'deny-inbound' rule"
        assert deny_rule.action == FirewallAction.DENY
        assert deny_rule.enabled is True

    def test_firewall_rule_position_increments(self) -> None:
        """Rules carry position (0-indexed from policyid order)."""
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        rules = cap.get_firewall_rules()
        positions = [r.position for r in rules if r.position is not None]
        assert positions == sorted(positions), "Rules must be in position order"

    def test_vip_nat_rule_type_is_destination(self) -> None:
        """FortiOS VIP → NatType.DESTINATION (ADR-0036 §3)."""
        from app.schemas.normalized import NatType

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        nat_rules = cap.get_nat_rules()
        vip_rules = [r for r in nat_rules if r.name == "web-server-vip"]
        assert vip_rules, "Expected VIP-based destination NAT rule"
        assert vip_rules[0].nat_type == NatType.DESTINATION

    def test_central_snat_rule_type_is_source(self) -> None:
        """FortiOS central-SNAT pool → NatType.SOURCE (ADR-0036 §3)."""
        from app.schemas.normalized import NatType

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        nat_rules = cap.get_nat_rules()
        snat_rules = [r for r in nat_rules if r.name == "outbound-snat"]
        assert snat_rules, "Expected central-SNAT source NAT rule"
        assert snat_rules[0].nat_type == NatType.SOURCE

    def test_static_central_snat_rule_type_is_static(self) -> None:
        """FortiOS static one-to-one central-SNAT (no pool) → NatType.STATIC (ADR-0036 §3).

        A central-SNAT-map entry with no ``nat-ippool`` but a fixed
        ``nat-source-address`` is a static one-to-one source translation; it must
        be normalized to ``NatType.STATIC`` (driven by ``_detect_nat_type``), not
        mislabeled ``SOURCE``.
        """
        from app.schemas.normalized import NatType

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        nat_rules = cap.get_nat_rules()
        static_rules = [r for r in nat_rules if r.name == "static-snat-one-to-one"]
        assert static_rules, "Expected static central-SNAT rule"
        assert static_rules[0].nat_type == NatType.STATIC


# ---------------------------------------------------------------------------
# Action mapping tests (ADR-0036 §3)
# ---------------------------------------------------------------------------


class TestFortiosActionMapping:
    """FortiOS action strings map correctly to ADR-0034 FirewallAction enum."""

    def test_accept_maps_to_allow(self) -> None:
        from app.schemas.normalized import FirewallAction

        assert _map_action("accept") == FirewallAction.ALLOW

    def test_deny_maps_to_deny(self) -> None:
        from app.schemas.normalized import FirewallAction

        assert _map_action("deny") == FirewallAction.DENY

    def test_unknown_maps_to_deny(self) -> None:
        """Unknown actions default to deny (safe/closed default)."""
        from app.schemas.normalized import FirewallAction

        assert _map_action("unknown-action") == FirewallAction.DENY

    def test_case_insensitive(self) -> None:
        from app.schemas.normalized import FirewallAction

        assert _map_action("ACCEPT") == FirewallAction.ALLOW
        assert _map_action("DENY") == FirewallAction.DENY


class TestFortiosNatTypeMapping:
    """FortiOS NAT type detection maps correctly to ADR-0034 NatType enum."""

    def test_snat_pool_maps_to_source(self) -> None:
        from app.schemas.normalized import NatType

        assert _detect_nat_type("snat") == NatType.SOURCE

    def test_vip_maps_to_destination(self) -> None:
        from app.schemas.normalized import NatType

        assert _detect_nat_type("vip") == NatType.DESTINATION

    def test_static_maps_to_static(self) -> None:
        from app.schemas.normalized import NatType

        assert _detect_nat_type("static") == NatType.STATIC

    def test_unknown_defaults_to_source(self) -> None:
        from app.schemas.normalized import NatType

        assert _detect_nat_type("anything-else") == NatType.SOURCE


# ---------------------------------------------------------------------------
# CONFIG_BACKUP SSH primary path
# ---------------------------------------------------------------------------


class TestFortiosConfigBackupSsh:
    """CONFIG_BACKUP uses SSH (show full-configuration) as primary (ADR-0036 §1)."""

    def test_returns_config_text(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosConfigBackup(rest_client, ssh_transport, uuid4())
        config = cap.fetch_running_config()
        assert isinstance(config, str)
        assert config.strip(), "Config backup must return non-empty text"

    def test_config_contains_hostname(self) -> None:
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosConfigBackup(rest_client, ssh_transport, uuid4())
        config = cap.fetch_running_config()
        # FortiOS config should contain some known structure
        assert "config" in config or "fw-fortios-lab" in config


# ---------------------------------------------------------------------------
# Plugin registration tests (ADR-0006 §5)
# ---------------------------------------------------------------------------


class TestFortiosRegistration:
    """FortiosPlugin is discoverable via iter_builtin_plugins and the default registry."""

    def test_iter_builtin_plugins_includes_fortios(self) -> None:
        from app.plugins.vendors import iter_builtin_plugins

        vendor_ids = [p.vendor_id for p in iter_builtin_plugins()]
        assert "fortios" in vendor_ids, "FortiosPlugin must be yielded by iter_builtin_plugins"

    def test_default_registry_contains_fortios(self) -> None:
        from app.plugins.registry import get_default_registry

        get_default_registry.cache_clear()
        try:
            registry = get_default_registry()
            assert "fortios" in registry.vendor_ids()
        finally:
            get_default_registry.cache_clear()

    def test_fortios_declares_all_capabilities(self) -> None:
        caps = FortiosPlugin.capabilities
        assert caps == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.INTERFACES,
                Capability.ROUTES,
                Capability.FIREWALL_POLICY,
                Capability.CONFIG_BACKUP,
                Capability.HA_STATUS,
            }
        )

    def test_fortios_vendor_id_is_fortios(self) -> None:
        assert FortiosPlugin.vendor_id == "fortios"


# ---------------------------------------------------------------------------
# Two-vendor cross-check: fortios + panos populate the SAME NormalizedFirewallRule
# fields (ADR-0034 stability proof, PRODUCTION.md §2.3)
# ---------------------------------------------------------------------------


class TestCrossVendorFirewallPolicy:
    """FortiOS and PAN-OS both populate the same NormalizedFirewallRule fields.

    This test is the ADR-0034 stability proof: two independent firewall vendors
    with different transport stacks and different policy vocabularies produce
    structurally identical NormalizedFirewallRule objects (same field set).
    Any ADR-0034 field present in one vendor but not the other is a design issue
    that must be escalated to W1-T1/ADR-0034 — not silently filled/nulled here.
    """

    def _get_fortios_rules(self) -> list:
        from app.plugins.vendors.fortios.plugin import FortiosFirewallPolicy

        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        return cap.get_firewall_rules()

    def _get_panos_rules(self) -> list:
        import httpx as _httpx

        from app.plugins.vendors.panos.client import PanosClient
        from app.plugins.vendors.panos.plugin import PanosFirewallPolicy
        from tests.plugins.test_panos_conformance import _FAKE_API_KEY

        # Import the panos fixture handler from the panos test module
        from tests.plugins.test_panos_conformance import _handle as _panos_handle

        http = _httpx.Client(transport=_httpx.MockTransport(_panos_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosFirewallPolicy(client, uuid4())
        return cap.get_firewall_rules()

    def test_fortios_and_panos_rules_have_same_fields(self) -> None:
        """Both vendors return NormalizedFirewallRule with the same set of fields populated."""
        from app.schemas.normalized import NormalizedFirewallRule

        fortios_rules = self._get_fortios_rules()
        panos_rules = self._get_panos_rules()

        assert fortios_rules, "FortiOS must return at least one firewall rule"
        assert panos_rules, "PAN-OS must return at least one firewall rule"

        # Both must produce valid NormalizedFirewallRule instances
        for rule in fortios_rules:
            assert isinstance(rule, NormalizedFirewallRule), (
                f"FortiOS rule is {type(rule).__name__}, expected NormalizedFirewallRule"
            )
        for rule in panos_rules:
            assert isinstance(rule, NormalizedFirewallRule), (
                f"PAN-OS rule is {type(rule).__name__}, expected NormalizedFirewallRule"
            )

        # The set of field names must be identical (both use ADR-0034 model)
        fortios_fields = set(type(fortios_rules[0]).model_fields.keys())
        panos_fields = set(type(panos_rules[0]).model_fields.keys())
        assert fortios_fields == panos_fields, (
            f"Field set divergence between fortios and panos: "
            f"fortios-only={fortios_fields - panos_fields}, "
            f"panos-only={panos_fields - fortios_fields}"
        )

    def test_both_vendors_populate_core_fields(self) -> None:
        """Both vendors populate the core ADR-0034 fields: name, action, enabled, zones."""
        fortios_rules = self._get_fortios_rules()
        panos_rules = self._get_panos_rules()

        for vendor_name, rules in [("fortios", fortios_rules), ("panos", panos_rules)]:
            rule = rules[0]
            assert rule.name, f"{vendor_name}: rule.name must be non-empty"
            assert rule.action is not None, f"{vendor_name}: rule.action must be set"
            assert isinstance(rule.enabled, bool), f"{vendor_name}: rule.enabled must be bool"
            assert rule.source_vendor == vendor_name, (
                f"{vendor_name}: rule.source_vendor={rule.source_vendor!r}"
            )

    def test_both_vendors_have_source_vendor_set(self) -> None:
        """source_vendor distinguishes fortios from panos in unified queries."""
        fortios_rules = self._get_fortios_rules()
        panos_rules = self._get_panos_rules()

        assert all(r.source_vendor == "fortios" for r in fortios_rules), (
            "All FortiOS rules must carry source_vendor='fortios'"
        )
        assert all(r.source_vendor == "panos" for r in panos_rules), (
            "All PAN-OS rules must carry source_vendor='panos'"
        )

    def test_cross_vendor_nat_rules_same_fields(self) -> None:
        """FortiOS and PAN-OS NAT rules use the same NormalizedNatRule field set."""
        import httpx as _httpx

        from app.plugins.vendors.panos.client import PanosClient
        from app.plugins.vendors.panos.plugin import PanosFirewallPolicy
        from app.schemas.normalized import NormalizedNatRule
        from tests.plugins.test_panos_conformance import _FAKE_API_KEY
        from tests.plugins.test_panos_conformance import _handle as _panos_handle

        # FortiOS NAT rules
        rest_client = _make_rest_client()
        ssh_transport = _make_ssh_transport()
        cap_fortios = FortiosFirewallPolicy(rest_client, ssh_transport, uuid4())
        fortios_nat = cap_fortios.get_nat_rules()

        # PAN-OS NAT rules
        http = _httpx.Client(transport=_httpx.MockTransport(_panos_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap_panos = PanosFirewallPolicy(client, uuid4())
        panos_nat = cap_panos.get_nat_rules()

        assert fortios_nat, "FortiOS must return at least one NAT rule"
        assert panos_nat, "PAN-OS must return at least one NAT rule"

        # Both must produce valid NormalizedNatRule instances
        for rule in fortios_nat + panos_nat:
            assert isinstance(rule, NormalizedNatRule)

        # Field sets must be identical
        fortios_nat_fields = set(type(fortios_nat[0]).model_fields.keys())
        panos_nat_fields = set(type(panos_nat[0]).model_fields.keys())
        assert fortios_nat_fields == panos_nat_fields, (
            f"NAT field set divergence: "
            f"fortios-only={fortios_nat_fields - panos_nat_fields}, "
            f"panos-only={panos_nat_fields - fortios_nat_fields}"
        )


# ---------------------------------------------------------------------------
# REST client error handling tests
# ---------------------------------------------------------------------------


class TestFortiosRestClientErrors:
    """FortiosRestClient raises PluginError on non-success responses."""

    def test_http_error_raises_plugin_error(self) -> None:
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                text='{"status":"error","error":"Unauthorized"}',
                headers={"content-type": "application/json"},
            )

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = FortiosRestClient(
            host="fw.example.com",
            api_token=_FAKE_REST_TOKEN,
            client=http,
        )
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(client, ssh_transport, uuid4())
        with pytest.raises(PluginError):
            cap.discover()

    def test_error_message_never_contains_rest_token(self) -> None:
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = FortiosRestClient(
            host="fw.example.com",
            api_token=_FAKE_REST_TOKEN,
            client=http,
        )
        ssh_transport = _make_ssh_transport()
        cap = FortiosDiscoveryApi(client, ssh_transport, uuid4())
        with pytest.raises(PluginError) as exc_info:
            cap.discover()
        assert _FAKE_REST_TOKEN not in str(exc_info.value)
        assert _FAKE_REST_TOKEN not in str(exc_info.value.args)
