# syntax=docker/dockerfile:1
#
# engram-router: a small Node app that terminates one Streamable HTTP MCP
# endpoint per authenticated gateway identity, bridging each to its own
# supergateway-wrapped `engram mcp` child. Own Dockerfile (not the root
# `x-mcp-image` anchor) because this service, unlike the other three
# mcp-* services, ships real application source, not just a fixed CLI
# invocation — see openspec/changes/engram-remote-mcp/design.md's
# "own Dockerfile, not the shared x-mcp-image anchor" decision.
#
# The `artifacts`/`nodetools` stages below are intentionally the same
# shape as the root Dockerfile's (engram binary, checksum-verified;
# pinned `supergateway`) — this service spawns those same tools as
# per-identity children, so it needs them present in its own image too.

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
# root Dockerfile. Kept in sync manually; if this drifts twice, factor both
# into a shared base image (see design.md's Open Questions/tradeoff note).
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
# Stage: nodetools — pinned supergateway only (no context7-mcp needed here).
# ---------------------------------------------------------------------------
FROM base AS nodetools

ARG SUPERGATEWAY_VERSION=3.4.3

RUN mkdir -p /opt/node-tools \
    && npm install --global --prefix /opt/node-tools "supergateway@${SUPERGATEWAY_VERSION}"

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
COPY --from=nodetools /opt/node-tools /opt/node-tools
ENV PATH="/opt/node-tools/bin:${PATH}"

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY bin ./bin

# engram defaults to ~/.engram/engram.db (local SQLite: sync_enrolled_projects
# + any not-yet-synced memory) — must exist, owned by `app`, BEFORE the
# engram_router_data volume mounts here, or Docker auto-creates the mount
# point as root:root and every write from the non-root `app` user fails with
# SQLite error 14 (SQLITE_CANTOPEN), which is exactly what happened before
# this line existed.
RUN mkdir -p /home/app/.engram && chown -R app:app /home/app/.engram

USER app
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "bin/engram-router.js"]
