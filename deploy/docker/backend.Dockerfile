# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# AI Network Operations Platform - backend image (ADR-0013 / D13).
#
# ONE image serves BOTH backend containers ("one image per container" read as
# one image *assigned* to each container, per ADR-0013 Decision 2):
#   api    -> default CMD below (uvicorn)
#   worker -> compose overrides the command:
#             celery -A app.workers.celery_app worker -Q discovery,config,packet,docs,system
#
# The build context is the REPOSITORY ROOT (docker-compose.yml sets
# `context: ../..`), so paths below are repo-relative:
#   docker build -f deploy/docker/backend.Dockerfile .
# ---------------------------------------------------------------------------

# ---- builder: install the project + dependencies into a relocatable venv ----
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build

# Dependencies are FROZEN in backend/pyproject.toml (the single source of
# truth); the app package is required for the hatchling build.
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
RUN pip install .

# ---- runtime: slim, non-root, venv + migrations only ------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Non-root runtime user (ADR-0013 / DECISIONS-BRIEF section 7: containers run
# non-root). Fixed UID/GID for predictable volume ownership.
RUN groupadd --gid 10001 netops \
    && useradd --uid 10001 --gid netops --create-home --shell /usr/sbin/nologin netops

# The venv already contains the installed `app` package and all entrypoints
# (uvicorn, celery, alembic).
COPY --from=builder /opt/venv /opt/venv

WORKDIR /srv/netops

# Alembic migration environment (D4: Alembic owns the schema). M0 ships no
# revisions; from M1: `docker compose ... exec api alembic upgrade head`.
COPY --chown=netops:netops backend/alembic.ini ./alembic.ini
COPY --chown=netops:netops backend/alembic ./alembic

USER netops

EXPOSE 8000

# Liveness probe against the canonical no-dependency endpoint (ADR-0015).
# python:3.12-slim ships no curl/wget, so probe via the stdlib. The worker
# container does not serve HTTP and overrides this check in docker-compose.yml.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=3).status == 200 else 1)"]

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
