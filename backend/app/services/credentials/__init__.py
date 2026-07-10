"""Credential vault: envelope-encrypted device secrets + rotation (ADR-0011, ADR-0040)."""

from app.services.credentials.rotation import (
    ReWrapResult,
    RotationStatus,
    get_rotation_status,
    re_wrap_keys,
)
from app.services.credentials.secret_rotation import (
    DeviceVerifier,
    RotationOutcome,
    rotate_device_secret,
)
from app.services.credentials.service import (
    DecryptedSecret,
    audit_provider_select,
    autonomous_sessionmaker,
    create_credential,
    decrypt,
    disable_credential,
    rotate_kek,
    rotate_secret,
)

__all__ = [
    "DecryptedSecret",
    "DeviceVerifier",
    "ReWrapResult",
    "RotationOutcome",
    "RotationStatus",
    "audit_provider_select",
    "autonomous_sessionmaker",
    "create_credential",
    "decrypt",
    "disable_credential",
    "get_rotation_status",
    "re_wrap_keys",
    "rotate_device_secret",
    "rotate_kek",
    "rotate_secret",
]
