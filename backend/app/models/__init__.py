"""SQLAlchemy models (system of record, D4).

M0 ships only :class:`~app.models.base.Base`. M1: device, credential,
discovery, normalized_*, user/role and audit models join — one module per
aggregate per REPO-STRUCTURE §2.
"""

from app.models.base import Base

__all__ = ["Base"]
