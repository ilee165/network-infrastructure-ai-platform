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
from app.models.change_requests import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.models.config_mgmt import (
    EMBEDDING_DIM,
    CompliancePolicy,
    ConfigSnapshot,
    ConfigSource,
    Document,
    DocumentFormat,
    DocumentKind,
    Embedding,
)
from app.models.identity import RefreshSession, Role, SystemSetting, User
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
from app.models.pcap_metadata import PcapMetadata
from app.models.topology import TopologySnapshot

__all__ = [
    "EMBEDDING_DIM",
    "AgentSession",
    "AgentSessionStatus",
    "Approval",
    "ApprovalDecision",
    "AuditLog",
    "Base",
    "ChangeRequest",
    "ChangeRequestKind",
    "ChangeRequestState",
    "CompliancePolicy",
    "ConfigSnapshot",
    "ConfigSource",
    "CredentialKind",
    "Device",
    "DeviceCredential",
    "DeviceStatus",
    "DiscoveryRun",
    "DiscoveryRunStatus",
    "Document",
    "DocumentFormat",
    "DocumentKind",
    "Embedding",
    "NormalizedInterfaceRow",
    "NormalizedNeighborRow",
    "NormalizedRouteRow",
    "PcapMetadata",
    "RawArtifact",
    "ReasoningTraceRow",
    "ReasoningTraceStep",
    "RefreshSession",
    "Role",
    "SystemSetting",
    "TimestampMixin",
    "TopologySnapshot",
    "TraceStepKind",
    "User",
    "UuidPkMixin",
]
