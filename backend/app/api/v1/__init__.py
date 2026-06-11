"""Version-1 API: aggregates every v1 sub-router onto :data:`api_router`.

``app.main.create_app`` mounts :data:`api_router` under the canonical
``/api/v1`` prefix. Router set per REPO-STRUCTURE §2; ``health`` (M0) and
``auth`` (M1) exist — devices/discovery/topology/agents/changes/ddi/packets/
docs/audit land with their milestones (M1+).
"""

from fastapi import APIRouter

from app.api.v1 import auth, health

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(health.router)

__all__ = ["api_router"]
