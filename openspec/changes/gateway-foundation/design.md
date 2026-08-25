# Design: Gateway Foundation

## Technical Approach

One image, many roles. A single multi-stage `Dockerfile` produces one runtime containing Node 22, `uv`, `supergateway`, and the `engram` binary; compose runs it under different commands per MCP. Caddy terminates TLS and is the only published surface; every route except `auth.{$DOMAIN}/login` and `/verify` passes `forward_auth` against `auth-gateway`. auth-gateway is the sole strict-TDD unit (`node --test`, JSDoc + `tsc --noEmit`).

## Architecture Decisions

### Decision: per-user Atlassian credentials are brokered by auth-gateway (shape a)

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) auth-gateway stores each PAT encrypted, `/verify` emits it, Caddy injects it upstream | New secret store + key management; keeps client config to URL+token | **Chosen** |
| (b) client sends its own PAT in `X-Atlassian-Token`, passed through | No new storage, but reintroduces a plaintext local secret on ~20 machines and collides with the gateway `Authorization` header | Rejected |
| (c) shared service account | Contradicts the confirmed per-user requirement | Rejected |

**Rationale**: the proposal's success criterion is *"a real MCP client connects with only a URL and token."* (b) breaks it for one of three pilots and pushes a long-lived Atlassian credential into every teammate's `.mcp.json`, un-revocable from the gateway. (a) keeps one credential per person, one revocation point, and enrollment happens once over HTTPS. Cost accepted: AES-256-GCM at rest keyed by `ATLASSIAN_ENC_KEY` (32 random bytes, base64, runtime env only) via `node:crypto` — no new dependency. This defends against DB-file/volume-snapshot exfiltration, not host compromise; that limit is documented in the README, not papered over. (b) stays additive later: if a request already carries `X-Atlassian-Token`, a future slice can prefer it without breaking this contract.

### Decision: tokens hashed with SHA-256, passwords with bcrypt

`/verify` runs on **every** MCP request; bcrypt cost-12 per hop is 100–300 ms of CPU. Gateway tokens are 256-bit `randomBytes(32)` base64url — no guessable entropy, so a keyed-lookup digest is sufficient. Passwords are human-chosen and stay bcrypt. `UNIQUE` index on `token_hash` gives indexed lookup; comparison after fetch uses `timingSafeEqual`. No `/verify` caching — revocation of a long-lived token must be instant.

### Decision: the PAT is scoped to its route by `X-Forwarded-Uri`

`forward_auth` rewrites to `GET /verify` and preserves the original path in `X-Forwarded-Uri`. auth-gateway emits `X-Atlassian-Authorization` **only** when that path is under `/mcp/atlassian`, so the secret never reaches the Context7 or engram routes. Rejected: always emitting it (broadest blast radius) and a per-route `/verify/atlassian` endpoint (duplicated auth logic).

## Data Flow

    client ──Authorization: Bearer <gw-token>──▶ Caddy :443  /mcp/atlassian*
                                                  │ strips inbound X-Gateway-*, X-Atlassian-*
                                                  ├─GET /verify (+X-Forwarded-Uri)─▶ auth-gateway
                                                  │      sha256 → tokens → users → decrypt PAT
                                                  ◀──204 + X-Gateway-User + X-Atlassian-Authorization
                                                  │ header_up Authorization {header.X-Atlassian-Authorization}
                                                  │ header_up -X-Atlassian-Authorization
                                                  └──────────────────────────────▶ mcp-atlassian:9000/mcp

Enrollment: `POST /login` (password) → HttpOnly session cookie → `POST /me/atlassian {token, scheme, cloudId}` → encrypted row. `bin/admin.js` creates users, issues tokens (shown once), revokes.

## Interfaces / Contracts

`GET /verify` — Caddy `forward_auth auth-gateway:3000 { uri /verify; copy_headers X-Gateway-User X-Gateway-User-Id X-Atlassian-Authorization }`

| Status | When | Response headers |
|---|---|---|
| 204 | valid Bearer or session cookie, user enabled | `X-Gateway-User`, `X-Gateway-User-Id`; `X-Atlassian-Authorization` iff Atlassian route + enrolled |
| 302 | invalid/absent **and** `Accept: text/html` | `Location: https://auth.{$DOMAIN}/login?next=…` |
| 401 | invalid, absent, revoked, or disabled user | `WWW-Authenticate: Bearer realm="mcp-gateway"` |
| 403 | authenticated but Atlassian route and no enrolled credential | JSON body naming the enrollment URL |

```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')), disabled_at TEXT);
CREATE TABLE tokens (id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE, label TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')), last_used_at TEXT, revoked_at TEXT);
CREATE INDEX idx_tokens_user ON tokens(user_id);
CREATE TABLE atlassian_credentials (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  scheme TEXT NOT NULL, ciphertext TEXT NOT NULL,  -- base64(iv|tag|ct), AES-256-GCM
  cloud_id TEXT, updated_at TEXT NOT NULL);
```

**Unverified external fact**: mcp-atlassian's per-request header is expected to be `Authorization: Token <PAT>` (Server/DC) or `Authorization: Bearer <token>` (Cloud OAuth), with optional `X-Atlassian-Cloud-Id`, and multi-user mode likely gated by `ATLASSIAN_OAUTH_ENABLE=true`. No doc tool was available in this phase. The whole uncertainty is confined to one function, `atlassianAuthHeader(cred) → {name, value}`, plus one compose env var; apply MUST verify against the upstream README and adjust that function only.

## Dockerfile Stage Layout

| Stage | Base | Produces |
|---|---|---|
| `base` | `node:22-bookworm-slim` | ca-certificates, curl, tini, non-root `app` |
| `artifacts` | `base` | `engram` binary: resolve `latest` via GitHub API (`ENGRAM_VERSION` ARG overrides), download asset + `checksums.txt`, `sha256sum -c` → `/out/` |
| `pytools` | `base` + `COPY --from=ghcr.io/astral-sh/uv:<pin> /uv` | `uv tool install mcp-atlassian==<pin>` → `/opt/uv-tools` |
| `nodetools` | `base` | pinned `supergateway` → `/opt/node-tools` (no runtime network) |
| `runtime` | `base` | copies the three artifact trees, `tini` entrypoint, runs as `app` |

## File Changes

| File | Action | Description |
|---|---|---|
| `Dockerfile` | Create | Five stages above |
| `docker-compose.yml` | Create | caddy, auth-gateway, mcp-context7, mcp-atlassian, mcp-engram-tool, engram-cloud(+db), engram-monitor; one bridge net, only caddy publishes |
| `Caddyfile` | Create | `{$DOMAIN}` path routes, `auth.`/`engram.` hosts, inbound header stripping, `forward_auth` |
| `services/auth-gateway/src/{app,db,tokens,crypto,verify}.js` | Create | Express app + modules (JSDoc-typed ESM) |
| `services/auth-gateway/test/*.test.js` | Create | `node --test`, written first |
| `services/auth-gateway/bin/admin.js` | Create | user/token CLI |
| `services/engram-monitor/{Dockerfile,nginx.conf}` | Create | build `src/` with Node 22, serve `dist/` on nginx, SPA fallback |
| `.env.example`, `README.md` | Create | Env contract + operator runbook |
| `openspec/config.yaml` | Modify | Pin runner/linter/type-checker TBDs |

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | token hash/compare, AES-GCM round-trip, route-scoping of `X-Forwarded-Uri`, bcrypt verify | `node --test` |
| Integration | `/verify` status/header matrix incl. spoofed `X-Gateway-User` and revoked token; `/login`; enrollment | `listen(0)` + `fetch`, temp SQLite |
| E2E (manual, apply gate) | `docker compose up`, unauthenticated `/mcp/*` → 401, authenticated `initialize` on all 3 pilots | curl/MCP client smoke script |

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Documentation-like paths | N/A — no file classification or execution of repo content |  |  |
| Git repository selection | N/A — no VCS automation in this change |  |  |
| Commit state | N/A |  |  |
| Push state | N/A |  |  |
| PR commands | N/A |  |  |
| **Routing: inbound header spoofing** | Applicable | Caddy strips `X-Gateway-*` / `X-Atlassian-*` from client requests before `forward_auth`; auth-gateway derives identity only from Bearer/cookie | `/verify` ignores a client-supplied `X-Gateway-User`; compose smoke asserts spoofed header → 401 |
| **Routing: secret over-forwarding** | Applicable | PAT header emitted only for normalized paths under `/mcp/atlassian` | `/verify` on `/mcp/context7` and on `/mcp/atlassian/../context7` omits `X-Atlassian-Authorization` |
| **Process integration: subprocess args** | Applicable | `supergateway --stdio` command strings are fixed in compose, never built from request data | N/A (config, asserted by smoke test) |

## Migration / Rollout

No migration — greenfield. Order: (1) image + compose + Caddy, (2) auth-gateway TDD, (3) engram stack. Rollback per proposal.

## Open Questions

- [ ] engram-monitor backend base-URL env var — apply MUST read `services/engram-monitor/src/` after the human clone; block if absent, never guess.
- [ ] Confirm mcp-atlassian per-request header name/scheme and multi-user enable flag against upstream docs at apply time.
- [ ] Confirm Caddy `forward_auth` `copy_headers` + `header_up` ordering behaves as designed (fallback: `copy_headers X-Atlassian-Authorization>Authorization`).
