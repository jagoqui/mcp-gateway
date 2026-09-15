# syntax=docker/dockerfile:1
#
# Builds the vendored engram-monitor dashboard (services/engram-monitor/src/,
# gitignored — see the root .gitignore comment and README for the manual
# `git clone` step) and serves the static Vite output via nginx.

FROM node:22-bookworm-slim AS build

# git is required at install time, not for the app itself: engram-monitor's
# `prepare` script runs `lefthook install` (a git-hooks manager) against
# the cloned source's own .git directory (copied in below, alongside the
# source, since services/engram-monitor/src/ is a real git clone).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global pnpm@9

WORKDIR /app
COPY src/ .

# engram-monitor's backend base URL (src/config/engram.ts) is read at BUILD
# TIME via `import.meta.env.VITE_ENGRAM_URL` and baked into the compiled JS
# bundle that runs in the VISITOR'S OWN BROWSER — it is NOT re-readable at
# container runtime; changing it requires rebuilding this image.
#
# This dashboard has no auth mechanism of its own — gated instead at
# Caddy's forward_auth against auth-gateway's /admin/verify (same admin
# session as the rest of /admin/*), never exposed unauthenticated. Same-
# origin, relative default (/api under whatever base path this build is
# served at — see VITE_BASE_PATH), which nginx.conf proxies internally to
# engram-serve-bridge: `engram serve` sends no Access-Control-Allow-Origin
# header, so a cross-origin baseURL gets its responses blocked by the
# browser regardless of network reachability.
ARG VITE_ENGRAM_URL=/api
ENV VITE_ENGRAM_URL=${VITE_ENGRAM_URL}

# Served under a shared domain's /monitor/ subpath (see nginx.conf) instead
# of its own dedicated host — every asset reference the build emits must
# carry this same prefix, or the browser resolves them against the domain
# root instead of /monitor/ and the page loads with no CSS/JS. See
# vite.config.ts's `base`.
ARG VITE_BASE_PATH=/
ENV VITE_BASE_PATH=${VITE_BASE_PATH}

RUN pnpm install && pnpm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
