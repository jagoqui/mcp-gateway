# syntax=docker/dockerfile:1
#
# Builds the vendored engram-monitor dashboard (services/engram-monitor/src/,
# gitignored — see the root .gitignore comment and README for the manual
# `git clone` step) and serves the static Vite output via nginx.

FROM node:22-bookworm-slim AS build

RUN npm install --global pnpm@9

WORKDIR /app
COPY src/ .

# engram-monitor's backend base URL (src/config/engram.ts) is read at BUILD
# TIME via `import.meta.env.VITE_ENGRAM_URL` and baked into the compiled JS
# bundle — it is NOT re-readable at container runtime like a normal env var.
# Changing it requires rebuilding this image.
#
# UNVERIFIED ASSUMPTION: engram-monitor's own README/source describe it as a
# dashboard for a plain `engram serve` local API (observation search/browse,
# default http://127.0.0.1:7437). Our `engram-cloud` service runs the
# DIFFERENT `engram cloud serve` mode (port 18080), which per public docs
# only exposes /health, /sync/pull, /sync/push, /dashboard/* — not
# necessarily the same API surface this dashboard's UI calls. We point this
# at engram-cloud as the best available target; it must be smoke-tested in
# Phase 4 (tasks.md 5.x). See README.md's "engram-monitor compatibility
# caveat" section for the full explanation and fallback options.
ARG VITE_ENGRAM_URL=http://engram-cloud:18080
ENV VITE_ENGRAM_URL=${VITE_ENGRAM_URL}

RUN pnpm install && pnpm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
