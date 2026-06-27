"""Device-credential rotation CronJob entrypoint (W4-T2, ADR-0040 §1; ADR-0015).

The Helm-rendered ``credential-rotation-cronjob.yaml`` invokes this module on a
cadence:

    python -m app.workers.tasks.credential_rotation

It runs the confirm-then-swap, fail-closed device-secret rotation pass over the
credentials bound to a device (ADR-0040 §1/§3). For each credential it STAGES a
fresh KMS-wrapped DEK for a newly generated secret via the existing ADR-0032
envelope, VERIFIES it against the device, and ACTIVATES it ONLY on success — the
prior credential stays valid until the swap is confirmed, so a failed rotation
never locks the device out. Repeated verify failure marks the credential DEGRADED;
the non-zero exit + the structured log line ARE the alert (ADR-0015). The heavy
lifting (stage/verify/activate, zeroize, audit) lives in
:func:`app.services.credentials.secret_rotation.rotate_device_secret`; this module
is the worker shell.

This rotates the platform's STORED copy only (ADR-0040 §4): changing the secret ON
the device is out of P2 scope and, when scoped in later, routes through the
ADR-0020 four-eyes ChangeRequest spine.

The DB session factory, the device verifier, and the new-secret factory are
INJECTED into :func:`run` so a unit test drives the EXACT pass path against an
in-memory engine with deterministic fakes (what the test asserts is what the Job
runs). ``_main`` wires the real transport-backed verifier and a CSPRNG secret
factory — both are HOST-LIMITED (they need live device transports), so the live
pass is a CI/runtime gate; the deterministic core is fully unit-tested.

Secure by default: the run summary and the log line carry ids/versions/counts +
terminal states ONLY (ADR-0040 §1 / ADR-0032 §6) — never secret material.
"""

from __future__ import annotations

import os
import secrets
import sys
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.crypto import KeyProvider, get_key_provider, require_production_grade
from app.core.logging import get_logger
from app.db import create_engine, create_sessionmaker
from app.models.inventory import Device, DeviceCredential
from app.services.credentials.secret_rotation import (
    DEFAULT_MAX_ATTEMPTS,
    DeviceVerifier,
    RotationState,
    rotate_device_secret,
)
from app.services.credentials.service import DecryptedSecret

_logger = get_logger(__name__)

#: Actor recorded on the rotation audit rows for a worker-driven pass.
_ACTOR = "system:credential_rotation"

#: The summary textfile dir the run summary is written under (mirrors the audit
#: verify job's no-pushgateway pattern); overridable via env for tests + the chart.
_SUMMARY_DIR_ENV = "CREDENTIAL_ROTATION_SUMMARY_DIR"

#: Env knob for the per-credential retry budget (chart: rotation.maxAttempts).
_MAX_ATTEMPTS_ENV = "CREDENTIAL_ROTATION_MAX_ATTEMPTS"

#: Summary file name within the summary dir.
_SUMMARY_FILENAME = "credential_rotation.prom"

#: Byte length of a freshly generated device secret (URL-safe token).
_NEW_SECRET_BYTES = 32

#: A factory for the new secret to rotate INTO. Injected so the pass is testable;
#: the default is a CSPRNG token.
SecretFactory = Callable[[DeviceCredential], str]


@dataclass(frozen=True, slots=True)
class RotationPassSummary:
    """Versions/counts-only outcome of one pass — carries NO secret material."""

    considered: int
    activated: int
    degraded: int


def _new_secret(_credential: DeviceCredential) -> str:
    """Generate a fresh URL-safe device secret (CSPRNG). The plaintext is transient.

    The returned string is handed straight to :func:`rotate_device_secret`, which
    zeroizes its transient buffer after wrap+verify; it is never logged or stored.
    """
    return secrets.token_urlsafe(_NEW_SECRET_BYTES)


def render_summary(summary: RotationPassSummary) -> str:
    """Render *summary* as node_exporter textfile-format metrics (no secret material)."""
    lines = [
        "# HELP credential_rotation_considered_total Credentials considered for rotation.",
        "# TYPE credential_rotation_considered_total gauge",
        f"credential_rotation_considered_total {summary.considered}",
        "# HELP credential_rotation_activated_total Credentials whose new secret was activated.",
        "# TYPE credential_rotation_activated_total gauge",
        f"credential_rotation_activated_total {summary.activated}",
        "# HELP credential_rotation_degraded_total Credentials degraded after repeated failure.",
        "# TYPE credential_rotation_degraded_total gauge",
        f"credential_rotation_degraded_total {summary.degraded}",
    ]
    return "\n".join(lines) + "\n"


def write_summary(summary: RotationPassSummary, *, summary_dir: Path) -> Path:
    """Atomically write the run summary to *summary_dir* and return its path."""
    summary_dir.mkdir(parents=True, exist_ok=True)
    target = summary_dir / _SUMMARY_FILENAME
    body = render_summary(summary)
    fd, tmp_name = tempfile.mkstemp(dir=summary_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


async def _due_credentials(session: AsyncSession) -> list[tuple[DeviceCredential, Device]]:
    """ONE entry per device-bound credential, paired with a representative device.

    ADR-0040 rotates the stored copy of a device login secret; a credential with no
    bound device has no target to verify against, so it is not in this pass's
    worklist.

    A single credential may be bound by N devices (``Device.credential_id`` is not
    unique). The rotation rewrites the credential ROW once, so the worklist is
    deduped to ONE entry per credential (CR C7): a join would yield the credential N
    times and rotate it N times, each activation overwriting the prior one and
    inflating the considered/activated counts. We verify the new secret against a
    SINGLE representative device — the device with the lowest id bound to the
    credential — because the stored secret is shared across every bound device, so
    confirming it on one is a sound proof for the swap (the device-secret is the
    same value everywhere it is used). Ordered by credential id for a stable,
    resumable worklist.
    """
    rows = (
        await session.execute(
            select(DeviceCredential, Device)
            .join(Device, Device.credential_id == DeviceCredential.id)
            .order_by(DeviceCredential.id, Device.id)
        )
    ).all()
    worklist: list[tuple[DeviceCredential, Device]] = []
    seen: set[uuid.UUID] = set()
    for credential, device in rows:
        if credential.id in seen:
            continue
        seen.add(credential.id)
        worklist.append((credential, device))
    return worklist


async def run(
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    provider: KeyProvider,
    verify: DeviceVerifier,
    summary_dir: Path,
    secret_factory: SecretFactory = _new_secret,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> int:
    """Run one rotation pass; write the summary; return an exit code.

    Iterates the device-bound credentials, rotating each confirm-then-swap. Each
    credential's row commits independently so a partial pass is durable. Returns
    ``1`` (the alert) if ANY credential degraded after repeated verify failure, else
    ``0``. A degrade never mutates the prior credential, so a non-zero exit means
    "some device needs attention", never "a device was locked out".
    """
    considered = 0
    activated = 0
    degraded = 0
    async with sessionmaker() as session:
        worklist = await _due_credentials(session)
    for credential, device in worklist:
        considered += 1
        async with sessionmaker() as session:
            outcome = await rotate_device_secret(
                session,
                provider,
                credential_id=credential.id,
                new_secret=secret_factory(credential),
                device=device,
                verify=verify,
                actor=_ACTOR,
                max_attempts=max_attempts,
                sessionmaker=sessionmaker,
            )
            await session.commit()
        if outcome.state is RotationState.ACTIVATED:
            activated += 1
        else:
            degraded += 1

    summary = RotationPassSummary(considered=considered, activated=activated, degraded=degraded)
    write_summary(summary, summary_dir=summary_dir)
    _logger.info(
        "credentials.rotation_pass_complete",
        considered=considered,
        activated=activated,
        degraded=degraded,
    )
    # A degraded credential is the loud signal (ADR-0015): non-zero exit so the Job
    # is marked Failed, while the prior (working) credential stays the record.
    return 1 if degraded else 0


def _key_provider() -> KeyProvider:
    """Build the configured KEK provider under the ADR-0032 §2 production-grade gate.

    Mirrors the W6-T3 re-wrap worker (CR10): the CronJob builds its own provider
    (it does not go through ``create_app()``), so it applies the SAME production
    posture gate the API composition root enforces.
    """
    settings = get_settings()
    provider = get_key_provider(settings)
    require_production_grade(provider, is_prod=settings.production)
    return provider


async def _live_verify(_device: Device, _secret: DecryptedSecret) -> bool:  # pragma: no cover
    """The real transport-backed device verifier — HOST-LIMITED.

    Authenticating a staged secret requires a live transport to the target device,
    which cannot run on the build host. The live pass is a CI/runtime gate; the
    deterministic rotation core is unit-tested with an injected verifier. Until a
    transport-backed verifier is wired (a named follow-up), this conservatively
    returns ``False`` so an unverifiable rotation degrades (fail-closed) rather than
    activating an unconfirmed secret.
    """
    return False


async def _main() -> int:  # pragma: no cover - exercised via run() in the test wrapper
    """Build the runtime engine + provider from settings and run one pass (the Job path)."""
    summary_dir = Path(os.environ.get(_SUMMARY_DIR_ENV, tempfile.gettempdir()))
    max_attempts = int(os.environ.get(_MAX_ATTEMPTS_ENV, str(DEFAULT_MAX_ATTEMPTS)))
    engine = create_engine(get_settings())
    try:
        maker = create_sessionmaker(engine)
        return await run(
            sessionmaker=maker,
            provider=_key_provider(),
            verify=_live_verify,
            summary_dir=summary_dir,
            max_attempts=max_attempts,
        )
    finally:
        await engine.dispose()


if __name__ == "__main__":  # pragma: no cover - exercised via run() in the test wrapper
    import asyncio

    sys.exit(asyncio.run(_main()))
