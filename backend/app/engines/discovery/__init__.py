"""Discovery engine (M1-12): plan validation, seed expansion, per-device
collection orchestration.

Pure logic — no DB access (persistence is M1-13) and no Celery wiring
(M1-14). The engine consumes the D6 plugin contract
(:mod:`app.plugins.base`) and produces normalized records plus verbatim raw
outputs for later persistence to ``raw_artifacts``.
"""

from app.engines.discovery.engine import DeviceCollectionResult, collect_device
from app.engines.discovery.expansion import next_wave
from app.engines.discovery.planner import DiscoveryPlan

__all__ = [
    "DeviceCollectionResult",
    "DiscoveryPlan",
    "collect_device",
    "next_wave",
]
