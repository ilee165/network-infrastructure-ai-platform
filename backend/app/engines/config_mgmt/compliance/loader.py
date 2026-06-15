"""Compliance policy loading (M4; ADR-0018).

Parses operator-authored YAML policy documents into validated
:class:`~app.engines.config_mgmt.compliance.schema.Policy` objects and exposes
the seeded ``baseline-hardening`` pack as a loadable default (ADR-0018 §6).

YAML is parsed with ``yaml.safe_load`` (never ``load``) — policy documents are
operator-supplied data, never trusted to construct arbitrary Python objects.
Pydantic validation rejects unknown keys, malformed regexes, and malformed
assertions at load time, so a typo in a policy fails loudly here rather than
silently passing a device at evaluation.
"""

from __future__ import annotations

from importlib import resources
from typing import Any

import yaml

from app.engines.config_mgmt.compliance.schema import Policy

__all__ = [
    "DEFAULT_PACK_RESOURCE",
    "load_default_pack",
    "load_policy_yaml",
]

#: Package + filename of the seeded baseline-hardening policy (ADR-0018 §6).
_POLICY_PACKAGE = "app.engines.config_mgmt.compliance.policies"
DEFAULT_PACK_RESOURCE = "baseline_hardening.yaml"


def load_policy_yaml(document: str) -> Policy:
    """Parse and validate one YAML policy *document* into a :class:`Policy`.

    :raises ValueError: if the document is not a YAML mapping.
    :raises pydantic.ValidationError: if the mapping violates the policy schema
        (unknown key, bad regex, malformed assertion, duplicate rule id, …).
    """
    parsed: Any = yaml.safe_load(document)
    if not isinstance(parsed, dict):
        raise ValueError("a compliance policy document must be a YAML mapping")
    return Policy.model_validate(parsed)


def load_default_pack() -> Policy:
    """Load the seeded ``baseline-hardening`` policy shipped with the package."""
    document = (
        resources.files(_POLICY_PACKAGE).joinpath(DEFAULT_PACK_RESOURCE).read_text(encoding="utf-8")
    )
    return load_policy_yaml(document)
