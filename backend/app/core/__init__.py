"""Cross-cutting foundations: config, logging, errors, security.

Boundary rule (REPO-STRUCTURE §3.2 row 1): ``app.core`` imports **nothing**
app-internal — enforced by import-linter in CI.

M1: ``crypto.py`` (credential-vault envelope encryption), ``audit.py``
(append-only audit-write primitive), ``redis.py`` (cache / rate-limit client)
and ``observability.py`` (Prometheus / OTel) join this package.
"""
