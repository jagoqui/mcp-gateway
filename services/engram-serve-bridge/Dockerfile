# syntax=docker/dockerfile:1
#
# engram-serve-bridge: a small Node reverse-proxy wrapper that spawns a
# single, multi-project `engram serve` process and exposes it on
# 0.0.0.0:<port> — `engram serve` itself only ever binds 127.0.0.1, with no
# CLI flag or env var to change the bind host (confirmed against source),
# so without this wrapper no other container could ever reach it.
#
# Same engram-binary-fetch-and-verify stage as engram-router's own
# Dockerfile (kept in sync manually, see that file's own comment) — no
# supergateway stage needed here, `engram serve` speaks plain HTTP itself.

ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --create-home --gid app --shell /usr/sbin/nologin app

# ---------------------------------------------------------------------------
# Stage: artifacts — same checksum-verified engram binary resolution as the
# root Dockerfile / engram-router's Dockerfile.
# ---------------------------------------------------------------------------
FROM base AS artifacts

ARG ENGRAM_VERSION=""
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    REPO="Gentleman-Programming/engram"; \
    case "${TARGETARCH}" in \
        amd64) ARCH="amd64" ;; \
        arm64) ARCH="arm64" ;; \
        *) echo "engram: unsupported TARGETARCH '${TARGETARCH}'" >&2; exit 1 ;; \
    esac; \
    if [ -z "${ENGRAM_VERSION}" ]; then \
        TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | jq -r '.tag_name')"; \
    else \
        TAG="${ENGRAM_VERSION}"; \
    fi; \
    if [ -z "${TAG}" ] || [ "${TAG}" = "null" ]; then \
        echo "engram: could not resolve a release tag" >&2; exit 1; \
    fi; \
    mkdir -p /tmp/engram-dl /out; \
    cd /tmp/engram-dl; \
    curl -fsSL -o checksums.txt \
        "https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"; \
    ASSET="$(grep -iE "linux.*${ARCH}" checksums.txt | awk '{print $2}' | head -n1)"; \
    if [ -z "${ASSET}" ]; then \
        echo "engram: no linux/${ARCH} asset found in checksums.txt for ${TAG}" >&2; \
        exit 1; \
    fi; \
    curl -fsSL -o "${ASSET}" \
        "https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"; \
    grep -F " ${ASSET}" checksums.txt > engram.sha256; \
    if [ ! -s engram.sha256 ]; then \
        echo "engram: no checksums.txt entry matches ${ASSET}" >&2; \
        exit 1; \
    fi; \
    sha256sum -c engram.sha256; \
    tar -xzf "${ASSET}" engram; \
    install -m 0755 engram /out/engram; \
    rm -rf /tmp/engram-dl
RUN /out/engram --help >/dev/null

# ---------------------------------------------------------------------------
# Stage: deps — install this service's own (dev-free at runtime) dependencies.
# ---------------------------------------------------------------------------
FROM base AS deps

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# ---------------------------------------------------------------------------
# Stage: runtime
# ---------------------------------------------------------------------------
FROM base AS runtime

COPY --from=artifacts /out/engram /usr/local/bin/engram

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY bin ./bin

# Same lesson engram-router's Dockerfile already learned: engram defaults to
# ~/.engram/engram.db and must exist, owned by `app`, BEFORE the persistent
# volume mounts here — otherwise Docker auto-creates the mount point as
# root:root and every write from the non-root `app` user fails with SQLite
# error 14 (SQLITE_CANTOPEN). Applied from the start here, not learned the
# hard way twice.
RUN mkdir -p /home/app/.engram && chown -R app:app /home/app/.engram

USER app
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "bin/engram-serve-bridge.js"]
