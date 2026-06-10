"""AI Network Operations Platform - backend package root.

Modular-monolith backend (ADR-0001): one codebase, two runtime containers
(``api`` via :func:`app.main.create_app`, ``worker`` via
:data:`app.workers.celery_app.celery_app`).
"""
