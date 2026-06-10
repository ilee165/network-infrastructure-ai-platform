"""Celery worker layer (ADR-0008) — composition root for the ``worker`` container.

Start a worker per queue from the same image as the api, e.g.::

    celery -A app.workers.celery_app worker -Q discovery
"""
