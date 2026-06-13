"""SQLAlchemy models (system of record, D4).

Every model module is imported here so that ``Base.metadata`` is complete the
moment ``app.models`` is imported — Alembic autogenerate and the test-suite
``create_all`` both rely on this. One module per aggregate (REPO-STRUCTURE §2).
"""

from app.models.agents import (
    AgentSession,
    AgentSessionStatus,
    ReasoningTraceRow,
    ReasoningTraceStep,
    TraceStepKind,
)
from app.models.audit import AuditLog
from app.models.base import Base
from app.models.identity import Role, User
from app.models.inventory import (
    CredentialKind,
    Device,
    DeviceCredential,
    DeviceStatus,
    DiscoveryRun,
    DiscoveryRunStatus,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)
from app.models.mixins import TimestampMixin, UuidPkMixin
from app.models.topology import TopologySnapshot

__all__ = [
    "AgentSession",
    "AgentSessionStatus",
    "AuditLog",
    "Base",
    "CredentialKind",
    "Device",
    "DeviceCredential",
    "DeviceStatus",
    "DiscoveryRun",
    "DiscoveryRunStatus",
    "NormalizedInterfaceRow",
    "NormalizedNeighborRow",
    "NormalizedRouteRow",
    "RawArtifact",
    "ReasoningTraceRow",
    "ReasoningTraceStep",
    "Role",
    "TimestampMixin",
    "TopologySnapshot",
    "TraceStepKind",
    "User",
    "UuidPkMixin",
]
