"""OIDC / SSO identity-federation service (ADR-0028).

Ties the pure JOSE/flow core (:mod:`app.core.oidc`) to the platform: a
single-use pending-auth store (state→verifier/nonce), deny-default IdP
group→RBAC mapping, and JIT 1:1 provisioning anchored on the immutable
``(idp_iss, idp_subject)`` pair.
"""

from app.services.oidc.mapping import RoleMappingError, map_groups_to_role
from app.services.oidc.pending import InMemoryPendingAuthStore, PendingAuth, PendingAuthStore
from app.services.oidc.service import (
    OidcDenied,
    provision_or_link_user,
    resolve_display_claims,
)

__all__ = [
    "InMemoryPendingAuthStore",
    "OidcDenied",
    "PendingAuth",
    "PendingAuthStore",
    "RoleMappingError",
    "map_groups_to_role",
    "provision_or_link_user",
    "resolve_display_claims",
]
