# syntax=docker/dockerfile:1
#
# auth-gateway runtime image. Plain Node 22, no build step for the app
# itself (JSDoc-typed ESM, type-checked at CI time via `tsc --noEmit`, not
# at image build time). Two stages because better-sqlite3 needs node-gyp
# (python3/make/g++) to compile its native addon; `deps` carries that
# toolchain and is discarded, `runtime` ships only the resulting
# node_modules on a slim base. Mirrors the non-root user pattern from the
# root Dockerfile.

FROM node:22-bookworm-slim AS deps

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-bookworm-slim AS runtime

RUN groupadd --system app \
    && useradd --system --create-home --gid app --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown app:app /data

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/
COPY bin/ ./bin/

USER app

EXPOSE 3000

CMD ["node", "src/app.js"]
