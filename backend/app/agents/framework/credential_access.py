"""Audited credential acquisition for specialist live reads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class SshCredentialMaterial:
    """Ephemeral SSH material returned only to the requesting live-read path."""

    host: str
    username: str
    password: str = field(repr=False)
    params: dict[str, Any]


class CredentialUnavailable(Exception):
    """A device has no usable SSH credential."""


async def acquire_troubleshooting_ssh(
    device_id: UUID,
    key_provider: Any,
    *,
    expected_host: str,
    expected_vendor_id: str,
    expected_credential_id: UUID | None,
    actor: str,
    reason: str,
) -> SshCredentialMaterial:
    """Decrypt a device-bound SSH credential with an autonomous audit write."""
    import app.db as db
    from app.core.errors import NetOpsError
    from app.models import CredentialKind, Device, DeviceCredential
    from app.services import credentials

    async with db.get_sessionmaker()() as session:
        device = await session.get(Device, device_id)
        if device is None:
            raise CredentialUnavailable(f"device {device_id} not found")
        if (
            device.mgmt_ip != expected_host
            or device.vendor_id != expected_vendor_id
            or device.credential_id != expected_credential_id
        ):
            raise CredentialUnavailable(
                f"device {device_id} inventory changed during live-read preparation; retry"
            )
        if device.credential_id is None:
            raise CredentialUnavailable(
                f"device {device_id} has no bound credential; "
                "a live read opens an SSH session and needs one"
            )
        row = await session.get(DeviceCredential, device.credential_id)
        if row is None or row.kind is not CredentialKind.SSH:
            raise CredentialUnavailable(
                f"device {device_id} has no usable SSH credential; a live read opens a CLI session"
            )
        try:
            secret = await credentials.decrypt(
                session,
                key_provider,
                row,
                actor=actor,
                reason=reason,
                target=device,
                sessionmaker=credentials.autonomous_sessionmaker(session),
            )
        except NetOpsError:
            raise
        await session.commit()
        return SshCredentialMaterial(
            host=device.mgmt_ip,
            username=row.username or "",
            password=secret.plaintext.decode("utf-8"),
            params=dict(row.params or {}),
        )
