# syntax=docker/dockerfile:1
#
# auth-gateway runtime image. Plain Node 22, no build step (JSDoc-typed ESM,
# type-checked at CI time via `tsc --noEmit`, not at image build time).
# Mirrors the non-root user pattern from the root Dockerfile.

FROM node:22-bookworm-slim

RUN groupadd --system app \
    && useradd --system --create-home --gid app --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown app:app /data

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src/ ./src/
COPY bin/ ./bin/

USER app

EXPOSE 3000

CMD ["node", "src/app.js"]
