"""Narrow structural types for authenticated audit actors."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID


class AuthenticatedActor(Protocol):
    """Identity facts required by HTTP authorization and service audits."""

    @property
    def id(self) -> UUID: ...

    @property
    def username(self) -> str: ...
