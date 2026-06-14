"""Version-1 API: aggregates every v1 sub-router onto :data:`api_router`.

``app.main.create_app`` mounts :data:`api_router` under the canonical
``/api/v1`` prefix. Router set per REPO-STRUCTURE §2 / DECISIONS-BRIEF §5;
``health`` (M0), ``auth``/``devices``/``credentials``/``discovery`` (M1),
``topology`` (M2), ``agents`` (M3) exist — changes/ddi/packets/docs/audit land
with their milestones.
"""

from fastapi import APIRouter

from app.api.v1 import agents, auth, credentials, devices, discovery, health, topology

api_router = APIRouter()
api_router.include_router(agents.router)
api_router.include_router(auth.router)
api_router.include_router(credentials.router)
api_router.include_router(devices.router)
api_router.include_router(discovery.router)
api_router.include_router(health.router)
api_router.include_router(topology.router)

__all__ = ["api_router"]
