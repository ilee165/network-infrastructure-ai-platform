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
# The `packet-analysis` STAGE (ADR-0049 blocker 7) extends `runtime` with tshark +
# libseccomp2 for the untrusted-pcap dissection tier. It is a SEPARATE build target
# (`--target packet-analysis`, image netops-backend-packet) so the shared api/worker
# image stays slim and free of tshark's CVE-bearing C dissectors.
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

# Layer-cache strategy (Wave 5 / perf #13): install the hash-pinned lockfile
# BEFORE copying application source so a source-only change reuses the dep
# layer (typically 2–5 min saved per rebuild). The lock is the resolved
# floor for CI + images (docs/security/supply-chain-scanning.md); pyproject
# remains the human-edited constraint surface.
#
#   1. pip install --require-hashes -r requirements.lock.txt  (deps only)
#   2. COPY app + pyproject
#   3. pip install --no-deps .  (project package only — hatchling wheel)
COPY backend/requirements.lock.txt ./requirements.lock.txt
RUN pip install --require-hashes -r requirements.lock.txt

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
RUN pip install --no-deps .

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
# start-interval=2s (Wave 5 / perf #14): poll faster during start-period so
# compose "healthy" flips sooner after uvicorn binds.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=2s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=3).status == 200 else 1)"]

# Single entrypoint shape (Wave 5 / startup M6): module-level ``app`` in
# ``app.main`` — matches Helm ``app.main:app``. Do NOT use ``--factory`` here:
# that would call create_app() twice (import-time + factory).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---- packet-analysis: runtime + tshark + libseccomp (ADR-0049 blocker 7) --------
# The UNTRUSTED-pcap dissection tier. This stage extends the slim `runtime` with
# ONLY what the executor-split child needs — tshark (the CVE-bearing C dissectors)
# and libseccomp.so.2 (the pyseccomp ctypes binding target the child loads its
# strict filter through). Kept OUT of the shared api/worker image so that image
# does not carry tshark's dissector attack surface. Build/consume via
# `--target packet-analysis` (compose service `packet-analysis`,
# image netops-backend-packet). pyseccomp itself is a pure-python wheel already
# installed into /opt/venv by the builder — no compiler/headers are needed here.
FROM runtime AS packet-analysis

# Root only to apt-install; drop back to the non-root netops user immediately.
USER root

# tshark for file dissection (never live capture — the analysis tier holds no
# CAP_NET_RAW) + libseccomp2 for the child's runtime seccomp filter. Preseed
# wireshark-common so dumpcap is NOT installed setuid-root: this tier dissects
# files, never captures, so a setuid raw-capture helper would be unused standing
# privilege. --no-install-recommends keeps the layer minimal.
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends tshark libseccomp2; \
    rm -rf /var/lib/apt/lists/*; \
    # Defence in depth: ensure no setuid dumpcap survives (file dissection needs none).
    if [ -e /usr/bin/dumpcap ]; then chmod u-s /usr/bin/dumpcap || true; fi

USER netops

# Build-time self-check (ADR-0049 blocker 7): import the seccomp binding, load the
# PACKAGED strict profile, and COMPILE the filter (no kernel load). A missing
# pyseccomp wheel, a missing libseccomp.so.2, or a profile that failed to package
# into the wheel fails the BUILD here — not the first production analysis job.
RUN ["python", "-m", "app.engines.packet.executor", "--self-check"]

# Inherit the runtime healthcheck/CMD; compose + Helm override the command to
# `celery ... -Q packet_analysis`.
