"""Vendor plugin system (D6, ADR-0006; transports per D7, ADR-0007).

Layout (REPO-STRUCTURE §2):

- :mod:`app.plugins.base` — ``Capability`` enum, ``VendorPlugin`` ABC, typed
  capability interfaces, ``ConnectionParams``, ``RawOutput``, and the
  ``CommandTransport`` protocol.
- :mod:`app.plugins.registry` — ``(vendor_id, capability)`` resolution and
  entry-point discovery (group ``"netops.plugins"``).
- :mod:`app.plugins.vendors` — one package per vendor; ``cisco_ios`` is the
  M0 reference plugin.

Module boundary (brief §3): plugins may not import ``agents`` — or any other
feature module; only ``core`` and ``schemas`` are allowed.
"""

from app.plugins.base import (
    Capability,
    CommandTransport,
    ConnectionParams,
    PluginCapability,
    RawOutput,
    VendorPlugin,
)
from app.plugins.registry import ENTRY_POINT_GROUP, PluginRegistry, get_default_registry

__all__ = [
    "ENTRY_POINT_GROUP",
    "Capability",
    "CommandTransport",
    "ConnectionParams",
    "PluginCapability",
    "PluginRegistry",
    "RawOutput",
    "VendorPlugin",
    "get_default_registry",
]
