"""Version-1 API: aggregates every v1 sub-router onto :data:`api_router`.

``app.main.create_app`` mounts :data:`api_router` under the canonical
``/api/v1`` prefix. Router set per REPO-STRUCTURE §2 / DECISIONS-BRIEF §5;
``health`` (M0), ``auth``/``devices``/``credentials``/``discovery`` (M1),
``topology`` (M2), ``agents`` (M3) exist — M4 adds ``config_snapshots``
sub-resources under ``devices`` and a ``docs`` router.
"""

from fastapi import APIRouter

from app.api.v1 import (
    agents,
    auth,
    config_snapshots,
    credentials,
    devices,
    discovery,
    docs,
    health,
    topology,
)

api_router = APIRouter()
api_router.include_router(agents.router)
api_router.include_router(auth.router)
api_router.include_router(config_snapshots.router, prefix="/devices")
api_router.include_router(credentials.router)
api_router.include_router(devices.router)
api_router.include_router(discovery.router)
api_router.include_router(docs.router)
api_router.include_router(health.router)
api_router.include_router(topology.router)

__all__ = ["api_router"]
