"""Operational lifecycle for discovery job rows."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID


async def create_discovery_run(
    *,
    seeds: Sequence[str],
    hop_limit: int,
    allowlist: Sequence[str],
    credential_names: Sequence[str],
) -> tuple[str, str]:
    """Create a pending discovery run and return its id and status."""
    import app.db as db
    from app.models import DiscoveryRun

    async with db.get_sessionmaker()() as session:
        run = DiscoveryRun(
            seeds=list(seeds),
            hop_limit=hop_limit,
            allowlist=list(allowlist),
            credential_names=list(credential_names),
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return str(run.id), run.status.value


async def mark_discovery_run_failed(run_id: str, error: str) -> None:
    """Mark a committed discovery run failed after broker dispatch refusal."""
    import app.db as db
    from app.models import DiscoveryRun, DiscoveryRunStatus

    async with db.get_sessionmaker()() as session:
        run = await session.get(DiscoveryRun, UUID(run_id))
        if run is not None:
            run.status = DiscoveryRunStatus.FAILED
            run.error = error
            await session.commit()
