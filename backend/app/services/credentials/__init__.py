"""Credential vault: envelope-encrypted device secrets + rotation (ADR-0011)."""

from app.services.credentials.service import (
    DecryptedSecret,
    create_credential,
    decrypt,
    rotate_kek,
    rotate_secret,
)

__all__ = [
    "DecryptedSecret",
    "create_credential",
    "decrypt",
    "rotate_kek",
    "rotate_secret",
]
