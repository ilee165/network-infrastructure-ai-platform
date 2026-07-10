"""Version-1 API: aggregates every v1 sub-router onto :data:`api_router`.

``app.main.create_app`` mounts :data:`api_router` under the canonical
``/api/v1`` prefix. Router set per REPO-STRUCTURE §2 / DECISIONS-BRIEF §5;
``health`` (M0), ``auth``/``devices``/``credentials``/``discovery`` (M1),
``topology`` (M2), ``agents`` (M3) exist — M4 adds ``config_snapshots``
sub-resources under ``devices`` and a ``docs`` router. P4-W1-T3 adds ``adc``
and ``virtualization`` (read-only ADC/virtualization inventory surfacing);
P4-W2-T3 adds ``applications`` (manual application tagging, ADR-0052 §7).
"""

from fastapi import APIRouter, Depends

from app.api.deps import enforce_api_rate_limit
from app.api.v1 import (
    adc,
    agents,
    applications,
    auth,
    config_snapshots,
    credentials,
    devices,
    discovery,
    docs,
    health,
    integrations,
    topology,
    virtualization,
)

#: W6-T6 per-principal/per-token API rate limit (PRODUCTION.md §5). Applied to
#: the authenticated HTTP API routers only. Deliberately NOT applied at the
#: router level to:
#: - ``health`` — unauthenticated probes must never be throttled and carry no
#:   principal to key on;
#: - ``auth`` — the login path has its own throttle/lockout, and the bearer-keyed
#:   API budget would be a no-op for an unauthenticated login while double-counting
#:   token-bearing refresh/me calls;
#: - ``agents`` — it exposes a WebSocket streaming route (``/stream``) whose
#:   ``HTTPBearer``-based dependency cannot resolve on a WebSocket scope, so a
#:   router-level dependency would break it. Its authenticated HTTP routes ARE
#:   budgeted: ``agents`` applies this limit per-route on every ``@router.{get,
#:   post}`` (see ``app.api.v1.agents._API_RATE_LIMIT``), leaving only the
#:   ``@router.websocket`` route unbound.
_api_rate_limit = [Depends(enforce_api_rate_limit)]

api_router = APIRouter()
api_router.include_router(adc.router, dependencies=_api_rate_limit)
api_router.include_router(agents.router)
api_router.include_router(applications.router, dependencies=_api_rate_limit)
api_router.include_router(auth.router)
api_router.include_router(config_snapshots.router, prefix="/devices", dependencies=_api_rate_limit)
api_router.include_router(credentials.router, dependencies=_api_rate_limit)
api_router.include_router(devices.router, dependencies=_api_rate_limit)
api_router.include_router(discovery.router, dependencies=_api_rate_limit)
api_router.include_router(docs.router, dependencies=_api_rate_limit)
api_router.include_router(health.router)
api_router.include_router(integrations.router)
api_router.include_router(topology.router, dependencies=_api_rate_limit)
api_router.include_router(virtualization.router, dependencies=_api_rate_limit)

__all__ = ["api_router"]
