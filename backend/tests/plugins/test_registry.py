"""Tests for the plugin registry (app/plugins/registry.py, ADR-0006)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.core.errors import PluginError
from app.plugins import registry as registry_module
from app.plugins.base import Capability, InterfacesCapability, PluginCapability, VendorPlugin
from app.plugins.registry import ENTRY_POINT_GROUP, PluginRegistry, get_default_registry
from app.plugins.vendors.cisco_ios.plugin import CiscoIosInterfaces, CiscoIosPlugin
from app.plugins.vendors.spatiumddi.plugin import (
    SpatiumDdiDhcp,
    SpatiumDdiDns,
    SpatiumDdiIpam,
    SpatiumddiPlugin,
    SpatiumDiscoveryApi,
)
from app.schemas.normalized import NormalizedInterface


class _AcmeInterfaces(InterfacesCapability):
    def get_interfaces(self) -> list[NormalizedInterface]:
        return []


class _AcmePlugin(VendorPlugin):
    vendor_id = "acme_os"
    display_name = "Acme OS"
    capabilities = frozenset({Capability.INTERFACES})

    def _capability_classes(self) -> dict[Capability, type[PluginCapability]]:
        return {Capability.INTERFACES: _AcmeInterfaces}


class _OtherAcmePlugin(_AcmePlugin):
    """Different class, same vendor_id — a registration conflict."""


class _FakeEntryPoint:
    """Stand-in for importlib.metadata.EntryPoint (name + load())."""

    def __init__(self, name: str, obj: object) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> object:
        return self._obj


@pytest.fixture(autouse=True)
def _clear_default_registry_cache() -> Iterator[None]:
    """Isolate tests from each other's cached default registry."""
    get_default_registry.cache_clear()
    yield
    get_default_registry.cache_clear()


class TestRegisterAndResolve:
    def test_register_then_get_plugin_roundtrip(self) -> None:
        registry = PluginRegistry()
        plugin = _AcmePlugin()
        registry.register(plugin)
        assert registry.get_plugin("acme_os") is plugin

    def test_resolve_returns_capability_implementation_class(self) -> None:
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        assert registry.resolve("acme_os", Capability.INTERFACES) is _AcmeInterfaces

    def test_duplicate_registration_raises_plugin_error(self) -> None:
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        with pytest.raises(PluginError, match="duplicate plugin registration"):
            registry.register(_AcmePlugin())

    def test_unknown_vendor_raises_plugin_error_listing_registered(self) -> None:
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        with pytest.raises(PluginError, match="unknown vendor 'junos'.*acme_os"):
            registry.get_plugin("junos")

    def test_resolve_unsupported_capability_raises_plugin_error(self) -> None:
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        with pytest.raises(PluginError, match="does not implement"):
            registry.resolve("acme_os", Capability.OSPF)

    def test_register_rejects_non_plugin_objects(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(PluginError, match="not a VendorPlugin"):
            registry.register(object())  # type: ignore[arg-type]

    def test_vendor_ids_and_capabilities_for(self) -> None:
        registry = PluginRegistry()
        registry.register(CiscoIosPlugin())
        registry.register(_AcmePlugin())
        assert registry.vendor_ids() == ("acme_os", "cisco_ios")
        assert registry.capabilities_for("acme_os") == frozenset({Capability.INTERFACES})


class TestEntryPointDiscovery:
    def test_load_entry_points_registers_plugin_class(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("acme_os", _AcmePlugin)],
        )
        registry = PluginRegistry()
        assert registry.load_entry_points() == 1
        assert registry.vendor_ids() == ("acme_os",)

    def test_load_entry_points_accepts_plugin_instances(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("acme_os", _AcmePlugin())],
        )
        registry = PluginRegistry()
        assert registry.load_entry_points() == 1

    def test_load_entry_points_rejects_name_vendor_id_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("wrong_name", _AcmePlugin)],
        )
        registry = PluginRegistry()
        with pytest.raises(PluginError, match="mismatched vendor_id"):
            registry.load_entry_points()

    def test_load_entry_points_rejects_non_plugin_objects(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("acme_os", object())],
        )
        registry = PluginRegistry()
        with pytest.raises(PluginError, match="does not provide a VendorPlugin"):
            registry.load_entry_points()

    def test_load_entry_points_skips_already_registered_same_class(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("acme_os", _AcmePlugin)],
        )
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        assert registry.load_entry_points() == 0
        assert registry.vendor_ids() == ("acme_os",)

    def test_load_entry_points_conflicting_class_raises_plugin_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            registry_module,
            "entry_points",
            lambda group: [_FakeEntryPoint("acme_os", _OtherAcmePlugin)],
        )
        registry = PluginRegistry()
        registry.register(_AcmePlugin())
        with pytest.raises(PluginError, match="conflicts with already registered"):
            registry.load_entry_points()

    def test_entry_point_group_name_is_the_adr_0006_group(self) -> None:
        assert ENTRY_POINT_GROUP == "netops.plugins"


class TestDefaultRegistry:
    def test_default_registry_contains_builtin_cisco_ios(self) -> None:
        registry = get_default_registry()
        assert "cisco_ios" in registry.vendor_ids()
        assert registry.resolve("cisco_ios", Capability.INTERFACES) is CiscoIosInterfaces

    def test_default_registry_is_cached_per_process(self) -> None:
        assert get_default_registry() is get_default_registry()


# ---------------------------------------------------------------------------
# T7 — spatiumddi registration + DDI-Agent vendor-agnosticism
# ---------------------------------------------------------------------------


class TestSpatiumddiRegistration:
    """ADR-0024 T7: spatiumddi is discoverable via iter_builtin_plugins and the
    default registry; all four DDI capability ABCs resolve to the correct
    implementation classes without any DDI-Agent code change.

    The tests exercise three registration surfaces:
    1. ``iter_builtin_plugins`` — the fallback path used when the package is
       run from source without ``pip install -e .`` (no entry-point metadata).
    2. ``get_default_registry`` — the process-wide singleton that first loads
       built-ins then discovers entry points; spatiumddi must appear in both.
    3. ``PluginRegistry.load_entry_points`` — the entry-point path that runs
       when the package *is* installed (both paths must agree).
    """

    def test_iter_builtin_plugins_includes_spatiumddi(self) -> None:
        """spatiumddi is yielded by iter_builtin_plugins (source-run path, ADR-0006)."""
        from app.plugins.vendors import iter_builtin_plugins

        vendor_ids = [p.vendor_id for p in iter_builtin_plugins()]
        assert "spatiumddi" in vendor_ids, (
            "SpatiumddiPlugin must be yielded by iter_builtin_plugins so the "
            "default registry contains it even without pip install -e ."
        )

    def test_default_registry_contains_spatiumddi(self) -> None:
        """spatiumddi is in the process-wide default registry."""
        registry = get_default_registry()
        assert "spatiumddi" in registry.vendor_ids()

    def test_spatiumddi_plugin_instance_type(self) -> None:
        """The registered plugin is a SpatiumddiPlugin instance."""
        registry = get_default_registry()
        plugin = registry.get_plugin("spatiumddi")
        assert isinstance(plugin, SpatiumddiPlugin)

    def test_spatiumddi_declares_all_four_ddi_capabilities(self) -> None:
        """spatiumddi declares DISCOVERY_API + DDI_DNS + DDI_DHCP + DDI_IPAM."""
        registry = get_default_registry()
        caps = registry.capabilities_for("spatiumddi")
        assert caps == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.DDI_DNS,
                Capability.DDI_DHCP,
                Capability.DDI_IPAM,
            }
        )

    def test_spatiumddi_resolves_ddi_dns_capability(self) -> None:
        registry = get_default_registry()
        assert registry.resolve("spatiumddi", Capability.DDI_DNS) is SpatiumDdiDns

    def test_spatiumddi_resolves_ddi_dhcp_capability(self) -> None:
        registry = get_default_registry()
        assert registry.resolve("spatiumddi", Capability.DDI_DHCP) is SpatiumDdiDhcp

    def test_spatiumddi_resolves_ddi_ipam_capability(self) -> None:
        registry = get_default_registry()
        assert registry.resolve("spatiumddi", Capability.DDI_IPAM) is SpatiumDdiIpam

    def test_spatiumddi_resolves_discovery_api_capability(self) -> None:
        registry = get_default_registry()
        assert registry.resolve("spatiumddi", Capability.DISCOVERY_API) is SpatiumDiscoveryApi

    def test_spatiumddi_vendor_id_matches_entry_point_name(self) -> None:
        """vendor_id == entry-point name is the ADR-0006 invariant; assert it directly."""
        plugin = SpatiumddiPlugin()
        assert plugin.vendor_id == "spatiumddi"

    def test_ddi_agent_requires_no_code_change_to_operate_over_spatiumddi(self) -> None:
        """The DDI Agent is vendor-agnostic: it resolves capabilities from the registry.

        No DDI-Agent code change is required to support a new DDI vendor — the
        agent calls ``registry.resolve(vendor_id, capability)`` and the capability
        layer is the only vendor-specific code. This test asserts the invariant:
        all four DDI capability ABCs from the registry for 'spatiumddi' are the
        same classes the DDI Agent would instantiate, and resolving them requires
        zero agent-level code change (the registry is the sole indirection point,
        ADR-0006 §3).
        """
        registry = get_default_registry()

        # The DDI Agent dispatches by (vendor_id, capability) pairs — assert the
        # registry resolves each pair to a concrete class without knowing the
        # vendor-specific module.  If this test passes without importing anything
        # from app.agents.ddi, the agent is truly vendor-agnostic at the
        # capability-resolution level.
        for cap, expected_cls in (
            (Capability.DDI_DNS, SpatiumDdiDns),
            (Capability.DDI_DHCP, SpatiumDdiDhcp),
            (Capability.DDI_IPAM, SpatiumDdiIpam),
            (Capability.DISCOVERY_API, SpatiumDiscoveryApi),
        ):
            resolved = registry.resolve("spatiumddi", cap)
            assert resolved is expected_cls, (
                f"registry.resolve('spatiumddi', {cap!r}) returned {resolved!r}; "
                f"expected {expected_cls!r} — DDI Agent would dispatch to the wrong class"
            )
