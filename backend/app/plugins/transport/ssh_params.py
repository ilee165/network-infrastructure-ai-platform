"""Shared SshParams construction for host-key policy (Wave 3 H7 / B4).

All SSH open sites (config, discovery, troubleshooting, packet) must materialize
``ssh_strict`` / pin the same way so lab opt-out and per-host pins apply
uniformly.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.core.config import Settings, get_settings
from app.plugins.transport.ssh import SshParams

__all__ = ["host_key_fingerprint_for", "ssh_params_from"]


def host_key_fingerprint_for(host: str, cred_params: Mapping[str, Any] | None) -> str | None:
    """Resolve a host-keyed pin from credential ``params`` (never a flat shared pin)."""
    if not cred_params:
        return None
    fps = cred_params.get("host_key_fingerprints")
    if not isinstance(fps, dict):
        return None
    raw = fps.get(host) or fps.get(str(host))
    return str(raw) if raw is not None else None


def ssh_params_from(
    *,
    host: str,
    device_type: str,
    username: str,
    password: str,
    cred_params: Mapping[str, Any] | None = None,
    settings: Settings | None = None,
    enable_secret: str | None = None,
    conn_timeout: float | None = None,
    read_timeout: float | None = None,
) -> SshParams:
    """Build :class:`SshParams` with host-key policy from settings + credential params."""
    cfg = settings if settings is not None else get_settings()
    params = dict(cred_params or {})
    port = int(params.get("port", 22))
    pin = host_key_fingerprint_for(host, params)
    kwargs: dict[str, Any] = {
        "host": host,
        "device_type": device_type,
        "username": username,
        "password": password,
        "port": port,
        "enable_secret": enable_secret,
        "commit_confirmed_minutes": cfg.junos_commit_confirmed_minutes,
        "ssh_strict": cfg.ssh_strict,
        # When a pin is present, still load system known_hosts when strict; the
        # pin policy (handshake-time) accepts the presented key if it matches.
        "system_host_keys": cfg.ssh_strict,
        "host_key_fingerprint": pin,
    }
    if conn_timeout is not None:
        kwargs["conn_timeout"] = conn_timeout
    if read_timeout is not None:
        kwargs["read_timeout"] = read_timeout
    return SshParams(**kwargs)
