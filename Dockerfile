# syntax=docker/dockerfile:1
#
# Shared multi-stage runtime image for the mcp-gateway pilot MCP servers.
# One image, many roles: compose runs this image under different `command`s
# per service (context7 / mcp-atlassian / engram). See design.md for the
# stage layout rationale.

ARG NODE_IMAGE=node:22-bookworm-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.5.11

# Named stage so `pytools` can `COPY --from=uv_source` below — BuildKit
# doesn't support variable expansion directly in COPY --from for an image
# reference, only for a named stage.
FROM ${UV_IMAGE} AS uv_source

# ---------------------------------------------------------------------------
# Stage: base
# Common OS packages and the non-root runtime user shared by every stage.
# ---------------------------------------------------------------------------
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
# Stage: artifacts
# Resolves the `engram` GitHub release (or ENGRAM_VERSION pin), downloads
# the linux/<arch> asset, and verifies it against the release's
# checksums.txt before install. Fails the build on any verification miss.
# The release asset is a .tar.gz (CHANGELOG.md/LICENSE/README.md/engram at
# its root), not a raw binary — must extract before install, or the
# installed "binary" is actually gzip data and fails at runtime with
# "exec format error".
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
        echo "engram: resolving latest release via GitHub API"; \
        TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | jq -r '.tag_name')"; \
    else \
        TAG="${ENGRAM_VERSION}"; \
    fi; \
    if [ -z "${TAG}" ] || [ "${TAG}" = "null" ]; then \
        echo "engram: could not resolve a release tag" >&2; exit 1; \
    fi; \
    echo "engram: using release ${TAG} (arch ${ARCH})"; \
    mkdir -p /tmp/engram-dl /out; \
    cd /tmp/engram-dl; \
    curl -fsSL -o checksums.txt \
        "https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"; \
    ASSET="$(grep -iE "linux.*${ARCH}" checksums.txt | awk '{print $2}' | head -n1)"; \
    if [ -z "${ASSET}" ]; then \
        echo "engram: no linux/${ARCH} asset found in checksums.txt for ${TAG}" >&2; \
        exit 1; \
    fi; \
    echo "engram: downloading asset ${ASSET}"; \
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
# Build-time functional check, not just a checksum: a corrupted extraction
# or wrong-arch binary can still pass sha256sum and `tar` cleanly while
# being unusable (this is exactly how the raw-tarball-as-binary bug above
# slipped past verification — checksum matched, install "succeeded", and
# only a manual runtime smoke test caught the exec format error). Fails
# the build immediately instead of shipping a broken image.
RUN /out/engram --help >/dev/null

# ---------------------------------------------------------------------------
# Stage: pytools
# uv + pinned mcp-atlassian, installed as a `uv tool` (native streamable-http
# transport, no supergateway wrapper needed). 0.23.1 minimum: earlier
# releases pin fastmcp<2.4.0 with an unbounded pydantic>=2.10.6, so `uv tool
# install` (no lockfile) resolves today's newest pydantic and breaks fastmcp
# at import time ("cannot specify both default and default_factory").
# ---------------------------------------------------------------------------
FROM base AS pytools

ARG MCP_ATLASSIAN_VERSION=0.23.1
COPY --from=uv_source /uv /uvx /usr/local/bin/

ENV UV_TOOL_DIR=/opt/uv-tools \
    UV_TOOL_BIN_DIR=/opt/uv-tools/bin \
    UV_PYTHON_INSTALL_DIR=/opt/uv-tools/python \
    UV_COMPILE_BYTECODE=1

RUN mkdir -p "${UV_TOOL_DIR}" \
    && uv tool install "mcp-atlassian==${MCP_ATLASSIAN_VERSION}"

# ---------------------------------------------------------------------------
# Stage: nodetools
# Pinned supergateway + context7 MCP, installed at build time so wrapped
# services need no runtime network access to fetch themselves. supergateway
# 3.x minimum: --outputTransport streamableHttp (what mcp-context7 runs
# under in docker-compose.yml, same as services/engram-router's own
# separate Dockerfile) doesn't exist before 3.x — 2.8.1's --help only
# lists stdio/sse/ws. Avoid 3.0.0 specifically,
# it's missing a dist file (ERR_MODULE_NOT_FOUND on its own entrypoint).
# ---------------------------------------------------------------------------
FROM base AS nodetools

ARG SUPERGATEWAY_VERSION=3.4.3
ARG CONTEXT7_MCP_VERSION=1.0.17

RUN mkdir -p /opt/node-tools \
    && npm install --global --prefix /opt/node-tools \
        "supergateway@${SUPERGATEWAY_VERSION}" \
        "@upstash/context7-mcp@${CONTEXT7_MCP_VERSION}"

# ---------------------------------------------------------------------------
# Stage: runtime
# Assembles the artifact trees from the stages above onto the shared base.
# Runs as the non-root `app` user via tini.
# ---------------------------------------------------------------------------
FROM base AS runtime

COPY --from=artifacts /out/engram /usr/local/bin/engram
COPY --from=pytools /opt/uv-tools /opt/uv-tools
COPY --from=nodetools /opt/node-tools /opt/node-tools

ENV PATH="/opt/uv-tools/bin:/opt/node-tools/bin:${PATH}"

USER app
WORKDIR /home/app

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["engram", "--help"]
