# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# AI Network Operations Platform - frontend image (ADR-0012 / ADR-0013).
#
# Multi-stage: node:22 builds the Vite SPA, nginx:alpine serves the static
# bundle on the unprivileged port 8080 and proxies /api/ to the `api`
# compose service (deploy/docker/nginx.conf).
#
# The build context is the REPOSITORY ROOT (docker-compose.yml sets
# `context: ../..`), so paths below are repo-relative:
#   docker build -f deploy/docker/frontend.Dockerfile .
# ---------------------------------------------------------------------------

# ---- build: Vite production bundle -----------------------------------------
FROM node:22-alpine AS build

WORKDIR /build

# Reproducible installs from the lockfile; layer-cached until deps change.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---- runtime: nginx, non-root ------------------------------------------------
FROM nginx:alpine AS runtime

# Patch base-image OS packages to the latest Alpine security revisions before
# dropping to the non-root user. The CI Trivy gate fails on FIXABLE CRITICAL/
# HIGH CVEs (unfixed base-image CVEs are ignored via ignore-unfixed); this keeps
# the shipped image current on patched packages (e.g. openssl, libxml2). Runs as
# root — the default for nginx:alpine until the USER directive below.
#
# NOTE: the build uses GitHub Actions layer cache (cache-from/to type=gha,
# scope=frontend in .github/workflows/ci.yml), so this layer is reused across
# runs. When the CVE feed surfaces a NEW fixable base-image CVE, the cached
# layer ships stale packages and the Trivy gate fails even though a patch
# exists. Bump the cache-bust date below to invalidate this layer so
# `apk upgrade` re-fetches the latest patched packages.
RUN apk upgrade --no-cache  # cache-bust: 2026-07-10 (c-ares CVE-2026-33630 → 1.34.8-r0)

# Full nginx configuration (replaces the stock root-oriented config): SPA on
# 8080, /api/ reverse proxy, pid + temp paths under /tmp so the non-root
# `nginx` user (uid 101, built into the image) can run the master process.
COPY deploy/docker/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /build/dist /usr/share/nginx/html

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
