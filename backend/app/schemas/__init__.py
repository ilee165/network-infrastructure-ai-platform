"""Pydantic v2 contracts — pure data, no I/O (D2, REPO-STRUCTURE §2).

Submodules:

- :mod:`app.schemas.normalized` — vendor-agnostic network models, the plugin
  output contract (brief §4, ADR-0006/0007). Available at M0.
- API request/response schema modules (``common``, ``device``, ``change``, …)
  land with the routers that consume them (M1+).
"""
