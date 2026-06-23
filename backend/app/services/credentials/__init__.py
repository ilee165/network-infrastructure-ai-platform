"""Credential vault: envelope-encrypted device secrets + rotation (ADR-0011)."""

from app.services.credentials.rotation import (
    ReWrapResult,
    RotationStatus,
    get_rotation_status,
    re_wrap_keys,
)
from app.services.credentials.service import (
    DecryptedSecret,
    audit_provider_select,
    autonomous_sessionmaker,
    create_credential,
    decrypt,
    rotate_kek,
    rotate_secret,
)

__all__ = [
    "DecryptedSecret",
    "ReWrapResult",
    "RotationStatus",
    "audit_provider_select",
    "autonomous_sessionmaker",
    "create_credential",
    "decrypt",
    "get_rotation_status",
    "re_wrap_keys",
    "rotate_kek",
    "rotate_secret",
]
