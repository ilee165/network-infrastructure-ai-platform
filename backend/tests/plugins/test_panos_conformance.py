"""Palo Alto PAN-OS plugin run through the reusable conformance suite (ADR-0035 §6).

The platform's first firewall vendor plugin certified against the shared suite
(ADR-0034 / ADR-0035). Builds a capability factory wiring each capability to a
:class:`PanosClient` over source-derived PAN-OS XML fixtures (replayed via
:class:`httpx.MockTransport` — no respx, no network, D16), then parametrizes
over :func:`make_conformance_cases`. Each capability returns non-empty
normalized records carrying ``source_vendor == "panos"``.

The only credential anywhere in this module is the obviously-fake sentinel
``FAKE-panos-api-key-zzz`` — it is never a real secret.

Live golden-path deferred-accepted (no PAN-OS hardware) — documented for W5-T3.
"""

from __future__ import annotations

import logging
from uuid import uuid4

import httpx
import pytest

from app.plugins.base import (
    Capability,
    PluginCapability,
)
from app.plugins.vendors.panos.client import PanosClient
from app.plugins.vendors.panos.plugin import (
    PanosDiscoveryApi,
    PanosFirewallPolicy,
    PanosPlugin,
)
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

# ---------------------------------------------------------------------------
# Fake credential sentinel — never a real secret
# ---------------------------------------------------------------------------

#: A clearly-fake API key — never a real secret.
_FAKE_API_KEY = "FAKE-panos-api-key-zzz"  # noqa: S105 — obviously-fake test sentinel

# ---------------------------------------------------------------------------
# Fixture XML payloads (realistic PAN-OS XML API responses)
# ---------------------------------------------------------------------------

_SYSTEM_INFO_XML = """\
<response status="success">
  <result>
    <system>
      <hostname>fw-panos-lab</hostname>
      <model>PA-VM</model>
      <sw-version>10.2.3</sw-version>
      <serial>007200000000001</serial>
      <ip-address>192.168.1.1</ip-address>
    </system>
  </result>
</response>
"""

_INTERFACES_XML = """\
<response status="success">
  <result>
    <hw>
      <entry name="ethernet1/1">
        <name>ethernet1/1</name>
        <state>up</state>
        <mac>00:0c:29:ab:cd:ef</mac>
        <speed>1000full</speed>
        <duplex>full</duplex>
      </entry>
      <entry name="ethernet1/2">
        <name>ethernet1/2</name>
        <state>down</state>
        <mac>00:0c:29:ab:cd:f0</mac>
        <speed>10/100/1000</speed>
        <duplex>full</duplex>
      </entry>
    </hw>
  </result>
</response>
"""

# Config interfaces (to get IP addresses)
_INTERFACES_CONFIG_XML = """\
<response status="success">
  <result>
    <interface>
      <ethernet>
        <entry name="ethernet1/1">
          <layer3>
            <ip>
              <entry name="192.168.1.1/24"/>
            </ip>
          </layer3>
          <comment>Uplink interface</comment>
        </entry>
        <entry name="ethernet1/2">
          <layer3>
            <ip>
              <entry name="10.0.0.1/30"/>
            </ip>
          </layer3>
        </entry>
      </ethernet>
    </interface>
  </result>
</response>
"""

_ROUTES_XML = """\
<response status="success">
  <result>
    <entry>
      <destination>0.0.0.0/0</destination>
      <nexthop>192.168.1.254</nexthop>
      <metric>10</metric>
      <flags>A S</flags>
      <age>1234</age>
      <interface>ethernet1/1</interface>
      <route-table>unicast</route-table>
    </entry>
    <entry>
      <destination>10.0.0.0/30</destination>
      <nexthop/>
      <metric>0</metric>
      <flags>A C</flags>
      <age>5678</age>
      <interface>ethernet1/2</interface>
      <route-table>unicast</route-table>
    </entry>
  </result>
</response>
"""

_SECURITY_RULES_XML = """\
<response status="success">
  <result>
    <rules>
      <entry name="allow-web">
        <disabled>no</disabled>
        <action>allow</action>
        <from>
          <member>trust</member>
        </from>
        <to>
          <member>untrust</member>
        </to>
        <source>
          <member>any</member>
        </source>
        <destination>
          <member>any</member>
        </destination>
        <application>
          <member>web-browsing</member>
          <member>ssl</member>
        </application>
        <service>
          <member>application-default</member>
        </service>
        <log-end>yes</log-end>
        <description>Allow web traffic</description>
      </entry>
      <entry name="deny-all">
        <disabled>no</disabled>
        <action>deny</action>
        <from>
          <member>any</member>
        </from>
        <to>
          <member>any</member>
        </to>
        <source>
          <member>any</member>
        </source>
        <destination>
          <member>any</member>
        </destination>
        <application>
          <member>any</member>
        </application>
        <service>
          <member>any</member>
        </service>
        <log-end>no</log-end>
      </entry>
    </rules>
  </result>
</response>
"""

_NAT_RULES_XML = """\
<response status="success">
  <result>
    <rules>
      <entry name="outbound-nat">
        <disabled>no</disabled>
        <nat-type>ipv4</nat-type>
        <from>
          <member>trust</member>
        </from>
        <to>
          <member>untrust</member>
        </to>
        <source>
          <member>10.0.0.0/8</member>
        </source>
        <destination>
          <member>any</member>
        </destination>
        <source-translation>
          <dynamic-ip-and-port>
            <interface-address>
              <interface>ethernet1/1</interface>
            </interface-address>
          </dynamic-ip-and-port>
        </source-translation>
      </entry>
    </rules>
  </result>
</response>
"""

_HIT_COUNT_XML = """\
<response status="success">
  <result>
    <rule-hit-count>
      <vsys>
        <entry name="vsys1">
          <rule-base>
            <entry name="security">
              <rules>
                <entry name="allow-web">
                  <latest>
                    <hit-count>42</hit-count>
                    <last-reset-timestamp>0</last-reset-timestamp>
                  </latest>
                </entry>
                <entry name="deny-all">
                  <latest>
                    <hit-count>7</hit-count>
                    <last-reset-timestamp>0</last-reset-timestamp>
                  </latest>
                </entry>
              </rules>
            </entry>
          </rule-base>
        </entry>
      </vsys>
    </rule-hit-count>
  </result>
</response>
"""

_CONFIG_XML = """\
<response status="success">
  <result>
    <config>
      <devices>
        <entry name="localhost.localdomain">
          <vsys>
            <entry name="vsys1">
              <address/>
            </entry>
          </vsys>
        </entry>
      </devices>
    </config>
  </result>
</response>
"""

_HA_STATE_XML = """\
<response status="success">
  <result>
    <group>
      <local-info>
        <state>active</state>
      </local-info>
      <peer-info>
        <conn-status>up</conn-status>
        <state>passive</state>
        <mgmt-ip>192.168.1.2</mgmt-ip>
      </peer-info>
      <link-monitoring>
        <link-group/>
      </link-monitoring>
    </group>
  </result>
</response>
"""


def _handle(request: httpx.Request) -> httpx.Response:
    """Route PAN-OS XML API fixture requests by query parameters.

    Replicates the PAN-OS XML API URL structure so the capability layer can
    issue requests without a running appliance (D16). The API key is expected
    as a query parameter but MUST NOT appear in any log line or error message
    (ADR-0011 / ADR-0035 §2).

    Note: httpx decodes URL-encoded query parameters, so the ``cmd`` and
    ``xpath`` values arrive here as plain strings (e.g. ``<show><system>...``).
    """
    params = dict(request.url.params)
    req_type = params.get("type", "")
    cmd = params.get("cmd", "")
    xpath = params.get("xpath", "")
    action = params.get("action", "")

    if req_type == "op":
        # Match by XML tag content present in the cmd string
        if "<system>" in cmd or "system" in cmd and "info" in cmd:
            return httpx.Response(200, text=_SYSTEM_INFO_XML, headers={"content-type": "text/xml"})
        if "<interface>" in cmd:
            return httpx.Response(200, text=_INTERFACES_XML, headers={"content-type": "text/xml"})
        if "<route" in cmd and "routing" in cmd:
            return httpx.Response(200, text=_ROUTES_XML, headers={"content-type": "text/xml"})
        if "high-availability" in cmd:
            return httpx.Response(200, text=_HA_STATE_XML, headers={"content-type": "text/xml"})
        if "rule-hit-count" in cmd:
            return httpx.Response(200, text=_HIT_COUNT_XML, headers={"content-type": "text/xml"})
        # Fallback op
        return httpx.Response(
            200,
            text='<response status="success"><result/></response>',
            headers={"content-type": "text/xml"},
        )
    elif req_type == "config":
        if action == "get" and "/rulebase/security" in xpath:
            return httpx.Response(
                200, text=_SECURITY_RULES_XML, headers={"content-type": "text/xml"}
            )
        if action == "get" and "/rulebase/nat" in xpath:
            return httpx.Response(200, text=_NAT_RULES_XML, headers={"content-type": "text/xml"})
        if action == "get" and "interface" in xpath:
            return httpx.Response(
                200, text=_INTERFACES_CONFIG_XML, headers={"content-type": "text/xml"}
            )
        if action == "show":
            return httpx.Response(200, text=_CONFIG_XML, headers={"content-type": "text/xml"})
        # Fallback config
        return httpx.Response(
            200,
            text='<response status="success"><result/></response>',
            headers={"content-type": "text/xml"},
        )

    return httpx.Response(
        200,
        text='<response status="success"><result/></response>',
        headers={"content-type": "text/xml"},
    )


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    """Wire an impl class to a PanosClient over the MockTransport."""
    http = httpx.Client(transport=httpx.MockTransport(_handle))
    client = PanosClient(
        host="fw.example.com",
        api_key=_FAKE_API_KEY,
        client=http,
    )
    return impl(client, uuid4())


CASES = make_conformance_cases(PanosPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_panos_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """Every declared capability has a typed interface in _INTERFACE_SPECS, so
    each must get both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in PanosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids


# ---------------------------------------------------------------------------
# Credential hygiene tests (ADR-0011 / ADR-0035 §2)
# ---------------------------------------------------------------------------


class TestPanosCredentialHygiene:
    """The API key never appears in logs, normalized output, or exceptions (ADR-0011)."""

    def test_api_key_not_in_client_repr(self) -> None:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        assert _FAKE_API_KEY not in repr(client)
        assert "FAKE" not in repr(client)

    def test_api_key_not_in_normalized_firewall_rules(self) -> None:
        """API key must not appear in any normalized firewall rule field."""
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosFirewallPolicy(client, uuid4())
        rules = cap.get_firewall_rules()
        for rule in rules:
            dumped = str(rule.model_dump())
            assert _FAKE_API_KEY not in dumped

    def test_api_key_not_in_plugin_error_message(self) -> None:
        """PluginError raised by the client must not contain the API key."""
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="<response status='error'/>")

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        with pytest.raises(PluginError) as exc_info:
            cap.discover()
        assert _FAKE_API_KEY not in str(exc_info.value)

    def test_api_key_not_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """The API key must never appear in any log record (ADR-0011)."""
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        with caplog.at_level(logging.DEBUG):
            cap.discover()
        for record in caplog.records:
            assert _FAKE_API_KEY not in record.getMessage()
            assert _FAKE_API_KEY not in str(record.args)

    def test_api_key_not_in_raw_outputs(self) -> None:
        """Raw outputs stored via _record_raw must not contain the API key."""
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        cap.discover()
        for raw in cap.raw_outputs:
            assert _FAKE_API_KEY not in raw.output
            assert _FAKE_API_KEY not in raw.command


# ---------------------------------------------------------------------------
# Raw-first contract tests (ADR-0006 §3)
# ---------------------------------------------------------------------------


class TestPanosRawFirst:
    """Every capability call stores verbatim XML before parsing (ADR-0006 §3)."""

    def _client(self) -> PanosClient:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        return PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)

    def test_discovery_api_records_raw(self) -> None:
        cap = PanosDiscoveryApi(self._client(), uuid4())
        cap.discover()
        assert len(cap.raw_outputs) >= 1
        # Raw output should contain XML
        for raw in cap.raw_outputs:
            assert "<response" in raw.output or len(raw.output) > 0

    def test_firewall_policy_records_raw(self) -> None:
        cap = PanosFirewallPolicy(self._client(), uuid4())
        cap.get_firewall_rules()
        assert len(cap.raw_outputs) >= 1

    def test_firewall_policy_nat_records_raw(self) -> None:
        cap = PanosFirewallPolicy(self._client(), uuid4())
        cap.get_nat_rules()
        assert len(cap.raw_outputs) >= 1


# ---------------------------------------------------------------------------
# Normalized round-trip tests (ADR-0034)
# ---------------------------------------------------------------------------


class TestPanosNormalizedRoundTrip:
    """Parsed XML -> NormalizedFirewallRule/NormalizedNatRule serialize/deserialize equal."""

    def _client(self) -> PanosClient:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        return PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)

    def test_firewall_rule_round_trip(self) -> None:
        cap = PanosFirewallPolicy(self._client(), uuid4())
        rules = cap.get_firewall_rules()
        assert rules, "Expected at least one firewall rule"
        for rule in rules:
            dumped = rule.model_dump(mode="python")
            from app.schemas.normalized import NormalizedFirewallRule

            restored = NormalizedFirewallRule.model_validate(dumped)
            assert restored == rule

    def test_nat_rule_round_trip(self) -> None:
        cap = PanosFirewallPolicy(self._client(), uuid4())
        nat_rules = cap.get_nat_rules()
        assert nat_rules, "Expected at least one NAT rule"
        for rule in nat_rules:
            dumped = rule.model_dump(mode="python")
            from app.schemas.normalized import NormalizedNatRule

            restored = NormalizedNatRule.model_validate(dumped)
            assert restored == rule

    def test_firewall_rule_fields(self) -> None:
        """Key ADR-0034 fields are populated correctly from fixture XML."""
        from app.schemas.normalized import FirewallAction

        cap = PanosFirewallPolicy(self._client(), uuid4())
        rules = cap.get_firewall_rules()
        allow_web = next((r for r in rules if r.name == "allow-web"), None)
        assert allow_web is not None, "Expected 'allow-web' rule"
        assert allow_web.action == FirewallAction.ALLOW
        assert allow_web.enabled is True
        assert "trust" in allow_web.source_zones
        assert "untrust" in allow_web.destination_zones
        assert "web-browsing" in allow_web.applications
        assert allow_web.logging is True
        assert allow_web.description == "Allow web traffic"

    def test_deny_rule_mapped_correctly(self) -> None:
        from app.schemas.normalized import FirewallAction

        cap = PanosFirewallPolicy(self._client(), uuid4())
        rules = cap.get_firewall_rules()
        deny_all = next((r for r in rules if r.name == "deny-all"), None)
        assert deny_all is not None, "Expected 'deny-all' rule"
        assert deny_all.action == FirewallAction.DENY
        assert deny_all.logging is False

    def test_nat_rule_fields(self) -> None:
        """NAT rule fields map to ADR-0034 NormalizedNatRule."""
        from app.schemas.normalized import NatType

        cap = PanosFirewallPolicy(self._client(), uuid4())
        nat_rules = cap.get_nat_rules()
        outbound = next((r for r in nat_rules if r.name == "outbound-nat"), None)
        assert outbound is not None, "Expected 'outbound-nat' NAT rule"
        assert outbound.nat_type == NatType.SOURCE
        assert outbound.enabled is True
        assert "trust" in outbound.source_zones
        assert "untrust" in outbound.destination_zones

    def test_firewall_rule_position_increments(self) -> None:
        """Rules carry position (0-indexed rule order) from the XML."""
        cap = PanosFirewallPolicy(self._client(), uuid4())
        rules = cap.get_firewall_rules()
        positions = [r.position for r in rules if r.position is not None]
        assert positions == sorted(positions), "Rules must be returned in position order"


# ---------------------------------------------------------------------------
# Action mapping tests (ADR-0035 §4)
# ---------------------------------------------------------------------------


class TestPanosActionMapping:
    """PAN-OS action strings map correctly to ADR-0034 FirewallAction enum."""

    def test_allow_maps_to_allow(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("allow") == FirewallAction.ALLOW

    def test_deny_maps_to_deny(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("deny") == FirewallAction.DENY

    def test_drop_maps_to_drop(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("drop") == FirewallAction.DROP

    def test_reset_client_maps_to_reject(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("reset-client") == FirewallAction.REJECT

    def test_reset_server_maps_to_reject(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("reset-server") == FirewallAction.REJECT

    def test_reset_both_maps_to_reject(self) -> None:
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("reset-both") == FirewallAction.REJECT

    def test_unknown_action_defaults_to_deny(self) -> None:
        """Unknown actions default to deny (safe default, ADR-0035 §4)."""
        from app.plugins.vendors.panos.plugin import _map_action
        from app.schemas.normalized import FirewallAction

        assert _map_action("something-unknown") == FirewallAction.DENY


class TestPanosNatTypeMapping:
    """PAN-OS NAT detection maps correctly to ADR-0034 NatType enum."""

    def test_source_translation_maps_to_source(self) -> None:
        from app.plugins.vendors.panos.plugin import _detect_nat_type
        from app.schemas.normalized import NatType

        assert (
            _detect_nat_type(has_source=True, has_destination=False, has_static=False)
            == NatType.SOURCE
        )

    def test_destination_translation_maps_to_destination(self) -> None:
        from app.plugins.vendors.panos.plugin import _detect_nat_type
        from app.schemas.normalized import NatType

        assert (
            _detect_nat_type(has_source=False, has_destination=True, has_static=False)
            == NatType.DESTINATION
        )

    def test_static_translation_maps_to_static(self) -> None:
        from app.plugins.vendors.panos.plugin import _detect_nat_type
        from app.schemas.normalized import NatType

        assert (
            _detect_nat_type(has_source=False, has_destination=False, has_static=True)
            == NatType.STATIC
        )

    def test_default_when_ambiguous_is_source(self) -> None:
        """Default NAT type when no translation element found defaults to source."""
        from app.plugins.vendors.panos.plugin import _detect_nat_type
        from app.schemas.normalized import NatType

        assert (
            _detect_nat_type(has_source=False, has_destination=False, has_static=False)
            == NatType.SOURCE
        )


# ---------------------------------------------------------------------------
# Plugin registration tests (ADR-0006 §5)
# ---------------------------------------------------------------------------


class TestPanosRegistration:
    """PanosPlugin is discoverable via iter_builtin_plugins and the default registry."""

    def test_iter_builtin_plugins_includes_panos(self) -> None:
        from app.plugins.vendors import iter_builtin_plugins

        vendor_ids = [p.vendor_id for p in iter_builtin_plugins()]
        assert "panos" in vendor_ids, "PanosPlugin must be yielded by iter_builtin_plugins"

    def test_default_registry_contains_panos(self) -> None:
        from app.plugins.registry import get_default_registry

        get_default_registry.cache_clear()
        try:
            registry = get_default_registry()
            assert "panos" in registry.vendor_ids()
        finally:
            get_default_registry.cache_clear()

    def test_panos_declares_all_capabilities(self) -> None:
        caps = PanosPlugin.capabilities
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

    def test_panos_vendor_id_is_panos(self) -> None:
        assert PanosPlugin.vendor_id == "panos"


# ---------------------------------------------------------------------------
# Client XML parsing error handling
# ---------------------------------------------------------------------------


class TestPanosClientErrorHandling:
    """PanosClient raises PluginError on non-success responses (ADR-0035 §3)."""

    def test_error_response_raises_plugin_error(self) -> None:
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text='<response status="error"><msg>Authentication failed</msg></response>',
                headers={"content-type": "text/xml"},
            )

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        with pytest.raises(PluginError):
            cap.discover()

    def test_transport_error_raises_plugin_error(self) -> None:
        from app.core.errors import PluginError

        def _bad_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TransportError("connection refused")

        http = httpx.Client(transport=httpx.MockTransport(_bad_handler))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        with pytest.raises(PluginError, match="transport error"):
            cap.discover()

    def test_error_message_never_contains_api_key(self) -> None:
        """PluginError message must never contain the API key (ADR-0011)."""
        from app.core.errors import PluginError

        def _error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        http = httpx.Client(transport=httpx.MockTransport(_error_handler))
        client = PanosClient(host="fw.example.com", api_key=_FAKE_API_KEY, client=http)
        cap = PanosDiscoveryApi(client, uuid4())
        with pytest.raises(PluginError) as exc_info:
            cap.discover()
        assert _FAKE_API_KEY not in str(exc_info.value)
        assert _FAKE_API_KEY not in str(exc_info.value.args)
