"""Plugin registry: ``(vendor_id, capability)`` resolution + entry-point discovery.

ADR-0006: engines call the registry and never import vendor packages; plugins
self-register under the ``"netops.plugins"`` entry-point group so third-party
vendor packages (``pip install acme-netops-plugin``) plug in with zero core
changes. Unsupported ``(vendor, capability)`` combinations fail fast with a
typed :class:`~app.core.errors.PluginError` agents can explain to users.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from app.core.errors import PluginError
from app.plugins.base import Capability, PluginCapability, VendorPlugin

__all__ = ["ENTRY_POINT_GROUP", "PluginRegistry", "get_default_registry"]

ENTRY_POINT_GROUP = "netops.plugins"
"""Entry-point group vendor plugins register under (D6, ADR-0006)."""


class PluginRegistry:
    """Maps ``vendor_id`` → :class:`VendorPlugin` and resolves capabilities.

    Instances are independent — tests build their own; the application uses
    the process-wide :func:`get_default_registry`.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, VendorPlugin] = {}

    def register(self, plugin: VendorPlugin) -> None:
        """Register *plugin* under its ``vendor_id``.

        Raises :class:`PluginError` if the object is not a
        :class:`VendorPlugin` or the ``vendor_id`` is already registered.
        """
        if not isinstance(plugin, VendorPlugin):
            raise PluginError(
                f"cannot register {type(plugin).__name__!r}: not a VendorPlugin instance"
            )
        if plugin.vendor_id in self._plugins:
            raise PluginError(f"duplicate plugin registration for vendor {plugin.vendor_id!r}")
        self._plugins[plugin.vendor_id] = plugin

    def get_plugin(self, vendor_id: str) -> VendorPlugin:
        """Return the plugin registered for *vendor_id* or raise :class:`PluginError`."""
        try:
            return self._plugins[vendor_id]
        except KeyError:
            registered = ", ".join(sorted(self._plugins)) or "none"
            raise PluginError(
                f"unknown vendor {vendor_id!r} (registered vendors: {registered})"
            ) from None

    def resolve(self, vendor_id: str, capability: Capability) -> type[PluginCapability]:
        """Resolve ``(vendor_id, capability)`` to an implementation class.

        The single entry point engines use (brief §3: engines depend on
        plugins only via the registry).
        """
        return self.get_plugin(vendor_id).get_capability(capability)

    def vendor_ids(self) -> tuple[str, ...]:
        """All registered vendor ids, sorted."""
        return tuple(sorted(self._plugins))

    def capabilities_for(self, vendor_id: str) -> frozenset[Capability]:
        """Declared capability set for *vendor_id* ("what can we do here?")."""
        return self.get_plugin(vendor_id).capabilities

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> int:
        """Discover and register plugins from the *group* entry-point group.

        Each entry point must load to a :class:`VendorPlugin` subclass (or
        instance) whose ``vendor_id`` equals the entry-point name
        (REPO-STRUCTURE §6 step 8). An entry point whose exact class is
        already registered is skipped silently (built-ins may also be
        declared as entry points); a *different* class under a registered
        ``vendor_id`` raises :class:`PluginError`. Returns the number of
        plugins newly registered.
        """
        registered = 0
        for entry_point in entry_points(group=group):
            loaded = entry_point.load()
            plugin = self._as_plugin(entry_point.name, loaded)
            if entry_point.name != plugin.vendor_id:
                raise PluginError(
                    f"entry point {entry_point.name!r} in group {group!r} loads plugin with "
                    f"mismatched vendor_id {plugin.vendor_id!r}"
                )
            existing = self._plugins.get(plugin.vendor_id)
            if existing is not None:
                if type(existing) is type(plugin):
                    continue
                raise PluginError(
                    f"entry point {entry_point.name!r} conflicts with already registered "
                    f"plugin {type(existing).__name__!r} for vendor {plugin.vendor_id!r}"
                )
            self._plugins[plugin.vendor_id] = plugin
            registered += 1
        return registered

    @staticmethod
    def _as_plugin(name: str, loaded: object) -> VendorPlugin:
        """Coerce an entry-point object into a plugin instance or fail typed."""
        if isinstance(loaded, type) and issubclass(loaded, VendorPlugin):
            return loaded()
        if isinstance(loaded, VendorPlugin):
            return loaded
        raise PluginError(
            f"entry point {name!r} does not provide a VendorPlugin (got {type(loaded).__name__!r})"
        )


@lru_cache(maxsize=1)
def get_default_registry() -> PluginRegistry:
    """The process-wide registry: built-in vendors + entry-point discoveries.

    Cached per process; tests call ``get_default_registry.cache_clear()``
    (same pattern as ``core.config.get_settings``).
    """
    # Local import: keeps registry/vendors import order acyclic at module load.
    from app.plugins.vendors import iter_builtin_plugins

    registry = PluginRegistry()
    for plugin in iter_builtin_plugins():
        registry.register(plugin)
    registry.load_entry_points()
    return registry
