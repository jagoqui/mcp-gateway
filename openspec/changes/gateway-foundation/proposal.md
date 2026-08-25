# Proposal: Gateway Foundation

## Intent

Each teammate installs and configures ~20 MCP binaries locally today. Self-host them on the jagoqui.tech VPS behind one URL and one Bearer token. This change proves the pattern with 3 pilot MCPs, one per packaging style.

## Scope

### In Scope

- Shared multi-stage `Dockerfile`: Node 22, uv/Python, checksum-verified GitHub-release binaries
- Pilots over streamable HTTP: `context7` (supergateway-wrapped stdio), `mcp-atlassian` (native `--transport streamable-http`), `engram` (supergateway-wrapped)
- `docker-compose.yml`; `Caddyfile` with TLS, routing, `forward_auth`
- `services/auth-gateway/`: Express token issuance and validation — the only strict-TDD unit
- `engram-cloud` + postgres; `engram-monitor` Dockerfile (nginx serving Vite `dist/`)
- `.env.example`, operator README

### Out of Scope

- Remaining ~19 MCPs — later changes reuse this pattern
- Angular/shadcn/DeepWiki MCPs: vendor-hosted, permanently out
- `git init`, RDD enablement, GitHub repo creation
- VPS/SSH deployment; vendoring engram-monitor source (human-gated)

## Capabilities

### New Capabilities

- `gateway-auth`: issuance, validation, forward_auth contract
- `reverse-proxy-routing`: routes, TLS, public vs gated
- `mcp-transport-exposure`: streamable-HTTP exposure per packaging style
- `container-runtime-image`: base image, release resolution, checksums
- `service-composition`: compose topology, networks, volumes, env

### Modified Capabilities

- None (`openspec/specs/` is empty)

## Approach

Use a server's native HTTP transport when it has one; wrap stdio with `supergateway` otherwise. Uniform wrapping is rejected as a hop `mcp-atlassian` does not need.

**Decision: `forward_auth` also gates `engram.{$DOMAIN}`.** One perimeter, one revocation point; engram-cloud's own auth becomes defense in depth, not access control. Cost: two credentials for dashboard users. Mitigation: auth-gateway accepts Bearer *or* HttpOnly cookie and 302s browser routes to `auth.{$DOMAIN}`, which stays ungated.

**Decision: auth-gateway toolchain** (pins `config.yaml` TBDs): `node --test` — built into Node 22, in the image already, zero runtime deps, native coverage; integration via ephemeral `listen(0)` and `fetch`. Plain JS ESM with JSDoc checked by `tsc --noEmit`; eslint and prettier, dev-only.

Dockerfile, compose, Caddyfile, and nginx.conf are infra desired-state, not unit-tested.

**Confirmed by the user (product/scope round, supersedes prior assumptions):**
- Identity: one gateway credential per person, not a shared team token — auth-gateway's multi-user store (already designed this way) is correct as-is.
- Token lifecycle: long-lived until manually revoked by an admin (PAT-style), no automatic expiry for this first slice.
- Atlassian: **per-user credentials, not a shared service account** — this changes the proposal's earlier assumption. `mcp-atlassian`'s streamable-HTTP mode supports per-request auth via forwarded headers; the exact mechanism (auth-gateway stores each user's Atlassian PAT and injects it via `forward_auth`'s `copy_headers` on the `/mcp/atlassian*` route, vs. the MCP client supplying it directly) is an open decision for `sdd-design` to resolve, not settled here.
- Engram Cloud: shared team memory, one project/namespace visible to every token holder — matches the original ask, no per-user isolation needed.

## Affected Areas

| Area | Impact |
|---|---|
| `Dockerfile`, `docker-compose.yml`, `Caddyfile` | New (infra) |
| `services/auth-gateway/**` | New (strict TDD) |
| `services/engram-monitor/{Dockerfile,nginx.conf}` | New (infra) |
| `.env.example`, `README.md` | New |
| `openspec/config.yaml` | Modified — pin toolchain |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| mcp-atlassian #507 transport quirk | Med | Smoke-test at apply; `mcp-proxy` stdio fallback |
| engram asset-name drift, API rate limit | Med | Resolve `latest` at build, verify `checksums.txt`, pinned-tag arg |
| engram-monitor backend env var unknown | High | Read cloned source at task phase; never guess |
| Secrets in layers or committed `.env` | Med | Runtime env only; `.env` gitignored |
| Over 400 changed lines | High | Chain PRs: image+compose+Caddy, auth-gateway, engram stack |
| Per-user Atlassian credentials add a real design surface (storage + injection mechanism) not present in the original shared-account assumption | Med | `sdd-design` resolves the exact mechanism (header-forwarding via `forward_auth copy_headers` vs. client-supplied header) before `sdd-tasks` breaks it down |

## Rollback Plan

Nothing is deployed. `docker compose down -v` plus reverting files restores the empty state. Per-service rollback deletes its compose service and Caddy route block. No VPS or DNS state is touched.

## Dependencies

- Human `git clone` of engram-monitor into `services/engram-monitor/src/`
- DNS A records for `jagoqui.tech` and subdomains (TLS only)
- GHCR pull access; Atlassian and Context7 credentials in `.env`

## Success Criteria

- [ ] `docker compose build` cold-cache succeeds; `up -d` reaches healthy
- [ ] auth-gateway suite green under `node --test`, written test-first
- [ ] Unauthenticated `/mcp/*` rejected; authenticated `initialize` succeeds on all 3 pilots
- [ ] A real MCP client connects with only a URL and token
