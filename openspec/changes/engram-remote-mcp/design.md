# Design: Engram Remote MCP

## Technical Approach

A new Node service, `services/engram-router/`, sits behind Caddy's existing
`/mcp/engram*` `forward_auth` gate (unchanged auth model — this service adds
no authentication of its own, it only *trusts* the identity Caddy already
verified). On each request it resolves an identity → project → child-process
mapping, spawning a `supergateway`-wrapped `engram mcp` child on first sight
of an identity and reverse-proxying to it (spawned or reused) on every
request after. The service speaks no MCP protocol itself — it is a dumb
byte-level HTTP proxy in front of per-identity `supergateway` instances,
which already implement Streamable HTTP correctly.

## Architecture Decisions

### Decision: own Dockerfile, not the shared `x-mcp-image` anchor

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) `services/engram-router/Dockerfile`, own multi-stage build (mirrors `services/auth-gateway/` and `services/engram-monitor/` precedent) | Duplicates the engram-binary-fetch + supergateway-install stages already in the root `Dockerfile` | **Chosen** |
| (b) Reuse `x-mcp-image` anchor, override `command:` to run the router's own Node entrypoint instead of a supergateway-wrapper command | No duplication; but `x-mcp-image`'s build context is the repo root with no app-code `COPY`, and every other service under that anchor is "one fixed command," not an app with its own source tree — bending it to also host real application logic blurs a boundary the other three services rely on staying simple | Rejected |

**Rationale**: this service has real application logic (process lifecycle, a
port allocator, a reverse proxy) — categorically different from the other
three `mcp-*` services, which are each one fixed CLI invocation. Every other
service in this repo with actual source code (`auth-gateway`, engram-monitor
build tooling) already gets its own Dockerfile; this follows that precedent
rather than overloading `x-mcp-image`. The duplicated stages (engram binary
fetch + checksum verify, `supergateway@3.4.3` install) are copy-pasted from
the root `Dockerfile`'s `artifacts`/`nodetools` stages verbatim at apply
time — if this drifts twice, a shared base image is a good follow-up change,
not a blocker here.

### Decision: dependency-free reverse proxy, not `http-proxy`

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) Hand-rolled proxy: `http.request` to the child's local port, pipe request/response streams | Zero new runtime dependency (matches this repo's stated auth-gateway precedent); must get streaming right by hand | **Chosen** |
| (b) `node-http-proxy` or similar npm package | Handles edge cases for free, but is a new runtime dependency this repo has deliberately avoided everywhere else | Rejected |

**Rationale**: the router never needs to understand MCP/JSON-RPC/SSE
framing — it only needs to move bytes between two HTTP connections without
buffering the whole body, so `req.pipe(proxyReq)` / `proxyRes.pipe(res)`
with headers copied through is sufficient and well within `node --test`'s
existing testing approach (ephemeral `listen(0)` + `fetch`, same as
auth-gateway).

### Decision: identity → child mapping is in-memory, not persisted

A `Map<identity, { child, port, lastRequestAt }>` inside the single router
process is sufficient. This service is not designed to run more than one
replica; if that changes later, the mapping would need to move to a shared
store — out of scope here, and not implied by anything in this change.

### Decision: port allocation via a small internal pool, not "ask the OS"

`supergateway --port <N>` requires an explicit port; the router owns a
fixed internal range (default `19100`–`19100 + MAX_CHILDREN`, both
configurable) and assigns the next free slot per new child, freeing it when
that child is torn down. Avoids the bind-to-0-then-read-then-close race of
asking the OS for a free port and hoping nothing else claims it in between.

## Data Flow

    client ──Authorization: Bearer <gw-token>──▶ Caddy :443  /mcp/engram*
                                                  │ strip_gateway_headers (inbound X-Gateway-* stripped)
                                                  ├─GET /verify (+X-Forwarded-Uri)─▶ auth-gateway
                                                  ◀──204 + X-Gateway-User + X-Gateway-User-Id
                                                  │ copy_headers X-Gateway-User X-Gateway-User-Id
                                                  └──────────────────────────────▶ engram-router:9000

    engram-router:
      1. read X-Gateway-User (already gateway-verified; never re-derive from anything else)
      2. lookup/create child for that identity
         - not found → allocate port, spawn:
           supergateway --stdio "engram mcp" --outputTransport streamableHttp
             --port <allocated> --host 127.0.0.1
           with child env: ENGRAM_PROJECT=<identity>, ENGRAM_CLOUD_AUTOSYNC=1,
             ENGRAM_CLOUD_TOKEN=<legacy wildcard token>,
             ENGRAM_CLOUD_SERVER=http://engram-cloud:18080
         - found + healthy → reuse
         - found + dead → respawn, replacing the map entry
      3. reverse-proxy the request/response to 127.0.0.1:<that child's port>

    engram-router ──ENGRAM_CLOUD_TOKEN (legacy wildcard)──▶ engram-cloud:18080 (internal, this repo's own compose service)

## Interfaces / Contracts

`engram-router` internal HTTP surface: exactly one route, all methods,
matching whatever path `supergateway --streamableHttpPath` is configured
with downstream (mirrors the existing `mcp-context7`/`mcp-atlassian`
convention of the backend serving the *full* incoming path, since Caddy's
`handle /mcp/engram*` forwards without stripping).

| Env var (router process) | Purpose |
|---|---|
| `ENGRAM_CLOUD_TOKEN` | Legacy wildcard token, passed through to every spawned child |
| `ENGRAM_CLOUD_SERVER` | `http://engram-cloud:18080` (this repo's own service) |
| `MAX_ENGRAM_CHILDREN` | Stopgap ceiling (default TBD at apply, e.g. 20) |
| `ENGRAM_ROUTER_PORT_BASE` | Start of the internal port-allocation range |

| Env var (per spawned child, set by the router) | Purpose |
|---|---|
| `ENGRAM_PROJECT` | The requesting identity's derived project name |
| `ENGRAM_CLOUD_AUTOSYNC` | `1`, always |
| `ENGRAM_CLOUD_TOKEN` / `ENGRAM_CLOUD_SERVER` | Forwarded from the router's own env |

## File Changes

| File | Action | Description |
|---|---|---|
| `services/engram-router/Dockerfile` | Create | Own multi-stage build: engram binary (checksum-verified) + `supergateway` + Node app |
| `services/engram-router/src/*.js` | Create | Identity extraction, child-process manager, port allocator, reverse proxy |
| `services/engram-router/test/*.test.js` | Create | `node --test`, written first |
| `docker-compose.yml` | Modify | Remove `mcp-engram-tool`; add `engram-router`; wire `ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_ALLOWED_PROJECTS=*` for `engram-cloud` |
| `Caddyfile` | Modify | `/mcp/engram*` → `engram-router:9000` (same `forward_auth` + `copy_headers` shape as today) |
| `services/auth-gateway/src/mcp-registry.js` | Modify | Correct the dead `ENGRAM_API_KEY` claim on the `engram` entry |
| `.env.example` | Modify | Document the new/renamed cloud-sync env vars |

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | identity → project derivation (rejects missing/malformed header, ignores client-supplied project hints), port allocator (no double-assignment, frees on teardown) | `node --test` |
| Integration | spawn-on-first-request, reuse-on-second-request, respawn-on-dead-child, ceiling rejection at `MAX_ENGRAM_CHILDREN` | `node --test`, a fake/stub child process instead of a real `engram mcp` binary in CI |
| E2E (manual, apply gate) | two distinct gateway identities, real `engram mcp`, confirm cross-identity isolation and that a `mem_save` reaches `engram-cloud` | `docker compose up`, curl/MCP client smoke script against both identities |

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| **Identity header spoofing** | Applicable | Same `strip_gateway_headers` Caddy snippet already used by every other `/mcp/*` route strips any inbound client-supplied `X-Gateway-User` before `forward_auth`; router additionally rejects a missing/malformed value rather than assuming Caddy is correctly configured | Router unit test: missing `X-Gateway-User` → rejected, no child touched |
| **Project name injection via identity value** | Applicable | Identity value is validated/sanitized before use as `ENGRAM_PROJECT` or in any path/env context (defense in depth even though auth-gateway's own username constraints already limit the character set) | Unit test: an identity value with shell/path-metacharacter-like content is rejected or safely escaped, never passed through unchecked |
| **Cloud sync token over-exposure** | Applicable | The legacy wildcard token lives only in the router's and spawned children's environment, never returned in any HTTP response or log line | Unit test asserts the token never appears in a response body or router log output |
| **Resource exhaustion via unbounded process spawn** | Applicable | Hard `MAX_ENGRAM_CHILDREN` ceiling, explicit rejection above it | Integration test: N+1th distinct identity gets an explicit capacity error, no (N+1)th process exists |

## Migration / Rollout

Order: (1) `engram-router` service + its own tests, merged and buildable
standalone; (2) `docker-compose.yml` + `Caddyfile` cutover — `mcp-engram-tool`
removed and `engram-router` wired in the same change (not left running side
by side, per proposal.md); (3) `mcp-registry.js` correction. Rollback per
proposal.md: revert the compose/Caddyfile diff to restore the old static
bridge immediately.

## Open Questions

- [ ] Exact `MAX_ENGRAM_CHILDREN` default — apply phase picks a starting
      number (e.g. 20) understanding it is a stopgap, not a tuned value.
- [ ] Exact respawn/backoff behavior on a repeatedly-crashing child (e.g. a
      malformed `ENGRAM_PROJECT` value that makes `engram mcp` itself exit)
      — apply MUST NOT let a crash-looping child spin unboundedly; a simple
      fixed retry cap per identity is enough for this change.
- [ ] `services/auth-gateway/src/mcp-registry.js`'s `engram` entry: whether
      to mark it `perUserCredentials: true`-shaped or introduce a third
      registry state ("no credential, but per-identity isolated") — apply
      phase decides the smallest change that keeps the existing panel
      honest without over-engineering a registry shape for one entry.
