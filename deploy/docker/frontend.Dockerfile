# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# AI Network Operations Platform - frontend image (ADR-0012 / ADR-0013).
#
# Multi-stage: node:20 builds the Vite SPA, nginx:alpine serves the static
# bundle on the unprivileged port 8080 and proxies /api/ to the `api`
# compose service (deploy/docker/nginx.conf).
#
# The build context is the REPOSITORY ROOT (docker-compose.yml sets
# `context: ../..`), so paths below are repo-relative:
#   docker build -f deploy/docker/frontend.Dockerfile .
# ---------------------------------------------------------------------------

# ---- build: Vite production bundle -----------------------------------------
FROM node:20-alpine AS build

WORKDIR /build

# Reproducible installs from the lockfile; layer-cached until deps change.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---- runtime: nginx, non-root ------------------------------------------------
FROM nginx:alpine AS runtime

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
