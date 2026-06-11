"""Discovery contracts (M1): device identity facts collected by plugins.

:class:`DeviceFacts` is what a ``DISCOVERY_SSH`` / ``DISCOVERY_SNMP``
capability returns: the identity of one device as observed over the wire,
used by the discovery engine (M1-12) to confirm or enrich inventory rows.
SNMP collection is best-effort — only ``hostname`` and ``vendor_id`` are
guaranteed; ``model``/``os_version``/``serial`` are ``None`` when the source
does not expose them.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["DeviceFacts"]


class DeviceFacts(BaseModel):
    """Identity facts of one discovered device (frozen evidence, like
    :class:`~app.schemas.normalized.NormalizedRecord`)."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    hostname: str = Field(min_length=1, description="Device-reported hostname or sysName.")
    vendor_id: str = Field(
        min_length=1, description="vendor_id of the plugin that collected these facts."
    )
    model: str | None = Field(default=None, description="Hardware model (best-effort).")
    os_version: str | None = Field(default=None, description="OS version string (best-effort).")
    serial: str | None = Field(default=None, description="Chassis serial number (best-effort).")
