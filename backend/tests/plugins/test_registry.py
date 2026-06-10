"""Tests for the plugin registry (app/plugins/registry.py, ADR-0006)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.core.errors import PluginError
from app.plugins import registry as registry_module
from app.plugins.base import Capability, InterfacesCapability, PluginCapability, VendorPlugin
from app.plugins.registry import ENTRY_POINT_GROUP, PluginRegistry, get_default_registry
from app.plugins.vendors.cisco_ios.plugin import CiscoIosInterfaces, CiscoIosPlugin
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
