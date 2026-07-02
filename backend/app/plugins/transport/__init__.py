"""Device transport layer: netmiko SSH + pysnmp SNMP v2c/v3 (ADR-0007).

Design rules (M1-08):

- Transports take plain params objects — they never touch the database or the
  credentials service; the caller (discovery runner / Celery task) materializes
  credentials and hands them over in memory (D11).
- All transports are blocking and run inside Celery worker tasks, never on the
  FastAPI event loop (ADR-0007 §3, ADR-0008).
- No params object or transport error ever exposes credential material in its
  ``repr``/``str`` (secure by default).
"""

from app.plugins.transport.snmp import (
    SnmpAuthProtocol,
    SnmpClient,
    SnmpPrivProtocol,
    SnmpTransportError,
    SnmpV2cParams,
    SnmpV3Params,
)
from app.plugins.transport.ssh import (
    NETMIKO_DEVICE_TYPES,
    SshParams,
    SshTransport,
    SshTransportError,
    netmiko_device_type,
)

__all__ = [
    "NETMIKO_DEVICE_TYPES",
    "SnmpAuthProtocol",
    "SnmpClient",
    "SnmpPrivProtocol",
    "SnmpTransportError",
    "SnmpV2cParams",
    "SnmpV3Params",
    "SshParams",
    "SshTransport",
    "SshTransportError",
    "netmiko_device_type",
]
