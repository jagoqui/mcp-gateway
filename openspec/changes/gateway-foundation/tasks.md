# Tasks: Gateway Foundation

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1,300-1,700 total (4 slices; largest ~450) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2a → PR2b → PR3 (refines proposal's 3-slice guess) |
| Delivery strategy | ask-on-risk |
| Chain strategy | feature-branch-chain (resolved) |

Decision needed before apply: No — resolved: feature-branch-chain, 4 PRs
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

Rationale: 19 requirements / 35 scenarios, 5 specs. auth-gateway alone (11
scenarios + 2 threat-matrix RED tests, test-first) est. ~700-800 lines, so
"auth-gateway" splits into 2a (data/crypto) and 2b (verify/login/admin) to
stay near budget. PR1 (image+compose+Caddy) est. ~380 lines alone.

### Suggested Work Units

| Unit | Goal | PR | Focused test cmd | Runtime harness | Rollback boundary |
|------|------|-----|-------------------|-----------------|-------------------|
| 1 | Dockerfile + 5-svc compose + Caddyfile + env/gitignore | PR1 | `docker compose config -q` | `docker compose build` cold-cache | Revert 5 files; `compose down -v` |
| 2a | auth-gateway db/crypto/token-hash | PR2a | `node --test test/{crypto,tokens}.test.js` | N/A — pure unit logic | Delete `src/{db,crypto,tokens}.js`+tests |
| 2b | auth-gateway verify/login/enrollment/admin | PR2b | `node --test test/{verify,login,enrollment}.test.js` | `listen(0)`+`fetch`, temp SQLite | Delete `src/{app,verify}.js`,`bin/admin.js`+tests |
| 3 | engram-monitor image + compose/Caddy ext + docs | PR3 | N/A — infra, not unit-testable | `compose up -d engram-* caddy` + curl | Delete engram-monitor files; revert compose/Caddyfile diffs |

## Phase 1: Container & Compose Foundation (PR1)

- [x] 1.1 `Dockerfile` stage `base`: node:22-bookworm-slim, tini, non-root `app`
- [x] 1.2 `Dockerfile` stage `artifacts`: GitHub `latest` API resolve (`ENGRAM_VERSION` ARG override), download binary + `checksums.txt`, `sha256sum -c`
- [x] 1.3 `Dockerfile` stage `pytools`: pinned `uv`, `uv tool install mcp-atlassian==<pin>`
- [x] 1.4 `Dockerfile` stage `nodetools`: pinned `supergateway`, no runtime network
- [x] 1.5 `Dockerfile` stage `runtime`: copy artifact trees, `tini` entrypoint, run as `app`
- [x] 1.6 `docker-compose.yml`: `caddy`, `auth-gateway`, `mcp-context7`, `mcp-atlassian` (`--transport streamable-http`), `mcp-engram-tool`; one bridge net; fixed `supergateway --stdio` strings; only `caddy` publishes
- [x] 1.7 `Caddyfile`: subdomain routes, `/login`+`/verify` excluded from `forward_auth`, strip inbound `X-Gateway-*`/`X-Atlassian-*`, `copy_headers` scoped to `/mcp/atlassian*`
- [x] 1.8 `.env.example`: DOMAIN, ATLASSIAN_ENC_KEY, mcp credentials — unblocked by the user (sandbox denied `.env*` writes to the apply sub-agent and, initially, the orchestrator); file renamed from `env.example.tmp` and committed.
- [x] 1.9 `.gitignore`: `.env`, `*.sqlite`, `node_modules`, `dist` (already present from the SDD scaffolding bootstrap commit; verified content covers all required patterns, no change needed)
- [x] 1.10 Verify: `docker compose config -q` passed (exit 0, brew-installed `docker`+`docker-compose` CLI, no daemon required for `config`). `docker compose build` NOT run — no Docker daemon available in this sandbox (`docker info` fails to reach `/var/run/docker.sock`). Additionally validated `Caddyfile` syntax with a real `caddy validate` (brew-installed caddy 2.11.4) — not required by this task but the only available substitute for a live Caddy config check.

## Phase 2a: Auth-Gateway Data/Crypto Layer (PR2a, strict TDD)

- [x] 2.1 RED `test/crypto.test.js`: AES-256-GCM round-trip via `ATLASSIAN_ENC_KEY`
- [x] 2.2 GREEN `src/crypto.js`
- [x] 2.3 RED `test/tokens.test.js`: SHA-256 hash + `timingSafeEqual`, bcrypt password verify
- [x] 2.4 GREEN `src/tokens.js`
- [x] 2.5 `src/db.js`: better-sqlite3 schema `users`, `tokens` (`UNIQUE token_hash`), `atlassian_credentials` (RED `test/db.test.js` + GREEN, schema taken verbatim from design.md's exact DDL — see Deviations note in apply-progress)
- [x] 2.6 REFACTOR: shared db helpers (`applySchema` extracted from `openDb`); `tsc --noEmit` clean; eslint/prettier clean

## Phase 2b: Verify/Login/Enrollment/Admin (PR2b, strict TDD)

- [x] 3.1 RED `test/verify.test.js`: 204 valid Bearer / valid cookie; 401 absent/invalid/revoked/disabled
- [x] 3.2 RED `test/verify.test.js`: 302 to `auth.{$DOMAIN}/login?next=` when `Accept: text/html`
- [x] 3.3 RED `test/verify.test.js`: 403 Atlassian route, no enrolled credential
- [x] 3.4 RED (threat: header spoofing): `/verify` ignores client-supplied `X-Gateway-User`
- [x] 3.5 RED (threat: secret over-forward): `X-Atlassian-Authorization` omitted on `/mcp/context7` and `/mcp/atlassian/../context7`
- [x] 3.6 GREEN `src/verify.js`: route-scoping via `X-Forwarded-Uri`
- [x] 3.7 RED `test/login.test.js`: `POST /login` issues HttpOnly session cookie
- [x] 3.8 GREEN `POST /login` in `src/app.js`
- [x] 3.9 RED `test/enrollment.test.js`: `POST /me/atlassian` stores encrypted credential
- [x] 3.10 GREEN enrollment route
- [x] 3.11 `bin/admin.js`: create user, issue token (shown once), revoke token (RED `test/admin.test.js` + GREEN, added beyond the literal task list per strict TDD hard gate)
- [x] 3.12 REFACTOR: mount all routes in `src/app.js`; `tsc --noEmit`; eslint/prettier — plus two PR2a advisory fixes done as their own RED/GREEN pair first (crypto.js decrypt() truncated-payload check, db.js WAL+busy_timeout)

## Phase 3: Engram Stack & Docs (PR3)

- [x] 4.1 Human-gated: clone engram-monitor source into `services/engram-monitor/src/` (blocking) — done by the orchestrator before this apply batch; gitignored per `.gitignore`, not committed.
- [x] 4.2 Read cloned source for real backend base-URL env var name; block if absent, never guess — resolved to `VITE_ENGRAM_URL` (`src/config/engram.ts`, Vite build-time env, default `http://127.0.0.1:7437`). Done by the orchestrator; used as-is in the Dockerfile ARG/ENV and compose `build.args`.
- [x] 4.3 `services/engram-monitor/Dockerfile`: multi-stage — `node:22-bookworm-slim` build stage (pnpm, `ARG VITE_ENGRAM_URL` → `ENV` before `pnpm install && pnpm run build`), `nginx:alpine` final stage serving `dist/`.
- [x] 4.4 `services/engram-monitor/nginx.conf`: SPA fallback (`try_files $uri $uri/ /index.html;`) on port 80.
- [x] 4.5 Extend `docker-compose.yml`: added `engram-cloud-db` (postgres:16-alpine, `pg_isready` healthcheck), `engram-cloud` (`engram cloud serve` mode, port 18080, `depends_on: service_healthy`, no `ENGRAM_CLOUD_INSECURE_NO_AUTH`), `engram-monitor` (build with `VITE_ENGRAM_URL` arg). Also added `AUTH_GATEWAY_SESSION_SECRET` to the existing `auth-gateway` service (PR2b gap, `src/session.js` reads it but PR1's compose never declared it).
- [x] 4.6 Extend `Caddyfile`: added `engram.{$DOMAIN}` (→ `engram-cloud:18080`) and `monitor.{$DOMAIN}` (→ `engram-monitor:80`) site blocks, both gated by the same `forward_auth` pattern as `/mcp/*` routes.
- [x] 4.7 Verify mcp-atlassian per-request header name/scheme + multi-user flag against upstream source — CONFIRMED CORRECT via deepwiki against sooperset/mcp-atlassian's `UserTokenMiddleware`: `Authorization: Bearer <oauth>` / `Token <PAT>` / `Basic <base64>` per `scheme`, exactly matching the existing `atlassianAuthHeader()` in `services/auth-gateway/src/verify.js` (PR2b, unchanged). `ATLASSIAN_OAUTH_ENABLE=true` (PR1 compose) confirmed correct. No code change made — PR2b's reviewed `verify.js` was not touched. Follow-up flagged, not implemented here: `X-Atlassian-Cloud-Id` header for multi-cloud accounts, using the already-stored `atlassian_credentials.cloud_id` column.
- [x] 4.8 Finalize `.env.example`: added `AUTH_GATEWAY_SESSION_SECRET`, `ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_ADMIN`/`ENGRAM_JWT_SECRET`/`ENGRAM_CLOUD_ALLOWED_PROJECTS`, `ENGRAM_CLOUD_DB_USER`/`ENGRAM_CLOUD_DB_PASSWORD`/`ENGRAM_CLOUD_DB_NAME`, `VITE_ENGRAM_URL` (with the compatibility caveat inline).
- [x] 4.9 `README.md`: setup (env, manual clone, `config -q`, `up -d --build`), login/token flow via `bin/admin.js`, env var contract, "adding a new MCP" repeatable pattern, and the `VITE_ENGRAM_URL` compatibility caveat documented prominently.
- [x] 4.10 Pin `openspec/config.yaml` TBDs: `runner: "node --test"`, `linter: "eslint"`, `type_checker: "plain JS + JSDoc, checked via tsc --noEmit"`, `formatter: "prettier"`; `testing.layers` updated to reflect unit/integration done, e2e not planned; also pinned the still-TBD `apply.test_command`/`verify.test_command` and refreshed stale `notes` (git init done, auth-gateway fully built).
- [x] 4.11 (gap-fill, not in original task list) `services/auth-gateway/Dockerfile` + `.dockerignore`: `docker-compose.yml`'s `auth-gateway` service has referenced `build: context: ./services/auth-gateway` since PR1, but no Dockerfile existed until now — the service could never actually build. `node:22-bookworm-slim`, non-root `app` user (same pattern as the root `Dockerfile`), `npm ci --omit=dev` using the PR2a-committed `package-lock.json`, `/data` pre-created and chowned to `app` for the SQLite volume mount.

## Phase 4: Integration Verification (manual, apply gate)

- [ ] 5.1 `docker compose up -d`; all services reach healthy
- [ ] 5.2 curl unauthenticated `/mcp/*` → 401 on all 3 pilots
- [ ] 5.3 curl spoofed `X-Gateway-User` → still 401 (threat-matrix smoke)
- [ ] 5.4 Authenticated `initialize` succeeds: context7, mcp-atlassian, engram MCP
- [ ] 5.5 Real MCP client connects with only URL + token
