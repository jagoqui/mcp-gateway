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
# Deliberately NOT a public URL: this dashboard has no auth mechanism of
# its own (see README.md's "engram-monitor backend" section), so it is
# never routed through Caddy. Defaults to the host's own `engram serve`
# process — the plain local API this dashboard's UI actually calls — and
# is only ever reached via an SSH tunnel to the VPS (see docker-compose.yml
# for the loopback-only port publish).
ARG VITE_ENGRAM_URL=http://127.0.0.1:7437
ENV VITE_ENGRAM_URL=${VITE_ENGRAM_URL}

RUN pnpm install && pnpm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
