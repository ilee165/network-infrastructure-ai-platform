"""In-repo vendor plugin packages — one package per vendor (D6, ADR-0006).

M0 ships the reference plugin ``cisco_ios``; M1 adds ``cisco_iosxe`` and
``eos``; the remaining CLAUDE.md vendors follow per the roadmap. Vendor
packages are mutually independent (REPO-STRUCTURE §3.2 row 7) and are also
registered as ``"netops.plugins"`` entry points in ``backend/pyproject.toml``
so third-party packages and built-ins resolve identically.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.plugins.base import VendorPlugin

__all__ = ["iter_builtin_plugins"]


def iter_builtin_plugins() -> Iterator[VendorPlugin]:
    """Yield one instance of every in-repo vendor plugin.

    Used by :func:`app.plugins.registry.get_default_registry` so built-ins
    are available even before their entry points are installed (e.g. when
    the backend runs from source without ``pip install -e .``).
    """
    # Imports are local so a broken/optional vendor package never breaks
    # importing app.plugins.vendors itself.
    from app.plugins.vendors.cisco_ios.plugin import CiscoIosPlugin

    yield CiscoIosPlugin()
