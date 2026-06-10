"""Celery task modules, one per queue (ADR-0008).

M0 ships only ``system`` (healthcheck). M1+: ``discovery.py``, ``config.py``,
``packet.py``, ``docs.py`` — thin wrappers around engine functions, named
``"<queue>.<verb>_<noun>"``.
"""
