# mcp-gateway

Self-hosted, single-perimeter access to MCP servers for the team. One URL,
one Bearer token per person, instead of ~20 locally-installed binaries per
teammate. `Caddy` terminates TLS and gates every route through
`auth-gateway`'s `forward_auth` check; `docker-compose.yml` runs one shared
runtime image under a different command per MCP.

## Quick path

1. Copy the env template and fill in real values:

   ```bash
   cp .env.example .env
   ```

   See [Environment variables](#environment-variables) below for what each
   key means and how to generate secrets.

2. Clone the engram-monitor dashboard source (not vendored — gitignored,
   see [`services/engram-monitor/src/`](#engram-monitor-source-manual-clone)):

   ```bash
   git clone https://github.com/egdev6/engram-monitor.git services/engram-monitor/src
   ```

3. Validate the compose file (no Docker daemon needed):

   ```bash
   docker compose config -q
   ```

4. Build and start everything:

   ```bash
   docker compose up -d --build
   ```

5. Create your first admin user and log in — see
   [Logging in](#logging-in--getting-a-token) below.

## Architecture

```
client ──Authorization: Bearer <token>──▶ Caddy :443
                                           │ forward_auth → auth-gateway:3000 /verify
                                           ▼
                          mcp-context7 / mcp-atlassian / engram-router
```

- **`Dockerfile`** — one multi-stage image (Node 22 + `uv` + `supergateway`
  + the `engram` binary). `docker-compose.yml` runs it under a different
  `command:` per pilot MCP (`mcp-context7`, `mcp-atlassian`).
  `engram-router` (below) has its own separate Dockerfile — it ships real
  application source, not just a fixed CLI invocation.
- **`Caddyfile`** — the only published surface. Every route except
  `auth.{$DOMAIN}/login` and `/verify` requires a passing `forward_auth`
  call to `auth-gateway`.
- **`services/auth-gateway/`** — Express app: issues/validates Bearer
  tokens and session cookies, brokers per-user Atlassian credentials. The
  only strict-TDD unit in this repo (`node --test`).
- **`services/engram-router/`** — per-identity Streamable HTTP MCP bridge:
  spawns one `supergateway`-wrapped `engram mcp` child per authenticated
  gateway user (identity from `X-Gateway-User`, never client-supplied),
  each autosyncing to `engram-cloud`. See
  `openspec/changes/engram-remote-mcp/design.md`.
- **`services/engram-monitor/`** — static dashboard (Vite/React), built
  from a manually-cloned upstream source and served via nginx. Local-only,
  reached through an SSH tunnel — see [engram-monitor
  backend](#engram-monitor-backend) below for why.

## Logging in / getting a token

Admin users and tokens are managed with `bin/admin.js` inside the
`auth-gateway` container:

```bash
# create a user (prompts for username/password if flags omitted)
docker compose exec auth-gateway node bin/admin.js create-user --username alice

# provision the single admin account (--admin true) — see "Admin users
# panel" below; there is no separate promote-to-admin command
docker compose exec auth-gateway node bin/admin.js create-user --username root --admin true

# rotate a password (admin or regular user) — never via the browser panel
docker compose exec auth-gateway node bin/admin.js set-password --username alice

# issue a Bearer token for that user — shown ONCE, copy it immediately
docker compose exec auth-gateway node bin/admin.js issue-token --username alice

# revoke a token
docker compose exec auth-gateway node bin/admin.js revoke-token --token <token>
```

Browsers authenticate at `https://auth.{$DOMAIN}/login` (HttpOnly session
cookie); MCP clients authenticate with `Authorization: Bearer <token>`
issued above. Point any MCP client at, e.g., `https://{$DOMAIN}/mcp/context7`
with only that URL and token — no other client-side configuration needed.

After logging in, each user manages their own credentials at
`https://auth.{$DOMAIN}/credentials` — a server-rendered, zero-JavaScript
page (plain `<form method="post">`, no build step, no client-side script)
listing every MCP the gateway proxies to:

- **Atlassian (Jira / Confluence)** is the only MCP with a per-user
  credential form — it is the only one that reads a per-request
  `Authorization` header. Enter your Atlassian API token there (and a
  `cloudId` if needed) to enroll; a "Remove credential" form clears it.
- **Context7** shows as a read-only, shared-credential row: no form, because
  it runs as a `supergateway --stdio` wrapper reading a boot-time env
  secret (`CONTEXT7_API_KEY` in `.env`) with no incoming-header injection
  path — configured once by an admin, not per-user.
- **Engram** also shows as a read-only row, but for the opposite reason:
  there is no credential to configure at all. Every gateway user gets
  their own isolated Engram Cloud project automatically, derived from
  their gateway identity (`X-Gateway-User`) by `engram-router` — see
  `services/engram-router/`.

Hitting an Atlassian route (`/mcp/atlassian/*`) with no enrolled credential
returns `403 {"error":"no_atlassian_credential","enrollUrl":"https://auth.{$DOMAIN}/credentials"}`
pointing straight at this page. Visiting `/credentials` while logged out
redirects to `/login?next=%2Fcredentials`, so signing in returns you to the
panel automatically. Cookie-authenticated writes on this page carry a
stateless, per-session CSRF token; `Authorization: Bearer` clients (CLI/MCP)
are unaffected — CSRF only applies to the cookie-authenticated browser path.

## Admin users panel

`https://engram-cloud.{$DOMAIN}/admin/users` is a second, fully independent
zero-JavaScript panel for the single CLI-provisioned admin account (`bin/admin.js
create-user --admin true`, above) to manage regular users and their tokens without
VPS shell access. It shares no session with `/credentials`: sign in at
`/admin/login` with a `__Host-admin_session` cookie, distinct from the regular
`session` cookie and CSRF-scoped separately from it.

From this panel you can list every regular user (with active/revoked token
counts), create one, disable/enable one (leaving their tokens untouched), and per
user, view/issue/revoke/regenerate their tokens — a newly issued or regenerated
token is shown exactly once, on that same response, never again afterward. The
admin account itself is out of scope by design: there is no create-admin,
list-admin, or self-disable action anywhere in this panel, and no `Authorization:
Bearer` credential is ever accepted here, even one belonging to the admin — only
the admin session cookie authenticates it. Every write here also appends one row
to `admin_audit_log` (actor, action, target, timestamp) — there is no UI for it
yet; query it directly against the `auth-gateway` SQLite database if you need the
trail.

Login attempts throttle after 5 failures for one username within a 15-minute
window (429 on the 6th, even with the correct password) — the escape hatch for a
locked-out admin is `bin/admin.js set-password` (bypasses HTTP entirely) or
restarting the `auth-gateway` container (clears the in-memory throttle map).

## Environment variables

Every variable is documented inline in [`.env.example`](.env.example),
grouped by service. Copy it to `.env` (gitignored) and fill in real values;
`docker compose` reads `.env` automatically. Highlights:

| Variable | Purpose |
|---|---|
| `DOMAIN` | Base domain; the `auth.` subdomain and `/mcp/*` path prefixes route under it. `engram-monitor` is intentionally not published — see [engram-monitor backend](#engram-monitor-backend) |
| `ATLASSIAN_ENC_KEY` | AES-256-GCM key encrypting stored per-user Atlassian credentials |
| `AUTH_GATEWAY_SESSION_SECRET` | Signs the HttpOnly session cookie issued by `POST /login` |
| `AUTH_GATEWAY_ADMIN_SESSION_SECRET` | Signs the `__Host-admin_session` cookie for the [admin users panel](#admin-users-panel) — a distinct secret from `AUTH_GATEWAY_SESSION_SECRET`, never shared |
| `ENGRAM_CLOUD_*`, `ENGRAM_JWT_SECRET` | `engram-cloud`'s (`engram cloud serve`) own config — team-shared memory instance |
| `ENGRAM_CLOUD_DB_*` | Postgres credentials for `engram-cloud-db` |
| `VITE_ENGRAM_URL` | **Build-time only.** engram-monitor's backend base URL, baked into its JS bundle by `vite build` — see [engram-monitor backend](#engram-monitor-backend) below |

## Engram-monitor source (manual clone)

`services/engram-monitor/src/` is a manual `git clone` of
[`egdev6/engram-monitor`](https://github.com/egdev6/engram-monitor),
deliberately **not vendored/committed** (see the `.gitignore` entry). Run
the clone command in step 2 above before `docker compose up --build`; the
`engram-monitor` service's build will fail without it.

## engram-monitor backend

engram-monitor's own README and source (`src/config/engram.ts`) describe
it as a dashboard for a plain `engram serve` local HTTP API (observation
search/browse endpoints), defaulting to `http://127.0.0.1:7437` — **not**
the same API surface as `engram-cloud`'s `engram cloud serve` mode (port
`18080`, which only exposes `/health`, `/sync/pull`, `/sync/push`, and its
own `/dashboard/*`).

**engram-monitor is deliberately not published through Caddy or DNS.**
Its client (`src/services/engram.ts`, a bare `axios.create()`) sends no
Authorization header, no cookies, and no interceptors of any kind — it
was built to talk to `engram serve` on `localhost`, where the OS itself is
the trust boundary. That client also calls destructive/data-moving
endpoints (`DELETE /observations/:id`, `POST /import`,
`POST /projects/migrate`), and `engram serve` has no auth of its own to
gate them with. Putting it behind `forward_auth` like every other route
would 401 every single request (the dashboard would load and show
nothing); putting it in front of `forward_auth` would expose the team's
entire memory store — reads and deletes both — on the public internet
with no authentication at all. Neither is acceptable, so this repo ships
neither: the route stays off, and access is local-only.

To use it, SSH-tunnel `engram-monitor`'s published `127.0.0.1:7438`, then
open the dashboard locally:

```bash
ssh -L 7438:localhost:7438 <you>@jagoqui.tech
# then, on your machine:
open http://localhost:7438
```

Only one port to tunnel: the bundled JS calls `/api` (same origin as the
page itself, not a separate `127.0.0.1:7437`), and `nginx.conf` proxies
that internally straight to `127.0.0.1:7437` — this container runs with
`network_mode: host` (see `docker-compose.yml`) specifically because the
host's `engram serve` binds `127.0.0.1` only, so no bridge-networked
container (not even via `host.docker.internal`) can reach it; sharing the
host's own network namespace is the only way in. This proxy isn't just
convenience — `engram serve` sends no `Access-Control-Allow-Origin`
header, so a cross-origin `baseURL` (even over a working two-port tunnel)
gets its responses blocked by the browser's CORS policy regardless of
whether the TCP connection itself works.

`engram-cloud` (Postgres-backed team sync + its own `/dashboard/*`) is
unrelated to engram-monitor — see the next section.

## engram-cloud (team-shared memory sync)

Unlike plain `engram serve`, `engram cloud serve` has its own real
Bearer-token auth (`ENGRAM_CLOUD_TOKEN`), so it's published directly at
`https://engram-cloud.{$DOMAIN}` — deliberately **not** wrapped in this
repo's `forward_auth`, since the `engram` CLI's own sync client sends a
single `Authorization` header carrying `ENGRAM_CLOUD_TOKEN`, which
`forward_auth` would reject as an invalid gateway token. This token is
team-wide (one shared secret, not per-user like `/mcp/atlassian`).

Each team member points their own local `engram` install at it once.
Source the shared token from a git-ignored file (e.g.
`~/.config/engram/env`, `chmod 600`) rather than typing it directly into
an interactive shell, where it can land in shell history or `ps` output:

```bash
source ~/.config/engram/env   # exports ENGRAM_CLOUD_TOKEN
engram cloud config --server https://engram-cloud.jagoqui.tech
engram cloud enroll <name>
engram sync --cloud --project <name>
```

Or enable background autosync instead of running `sync` by hand — same
sourced file, plus:

```bash
export ENGRAM_CLOUD_AUTOSYNC=1
export ENGRAM_CLOUD_SERVER=https://engram-cloud.jagoqui.tech
```

Teammates pull what others pushed with `engram sync --cloud --import
--project <name>`.

## Adding a new MCP later

This repo only pilots 3 of ~20 MCPs (one per packaging style). To add
another later, follow the pattern already used by `mcp-context7` /
`mcp-atlassian` in `docker-compose.yml`:

1. **Pick a transport.** If the server has native streamable-HTTP support
   (like `mcp-atlassian`), run it directly. Otherwise wrap its stdio
   command with `supergateway --stdio "<cmd>" --outputTransport
   streamableHttp --port 9000 --host 0.0.0.0` (like `mcp-context7`). If the
   bridge itself needs real application logic (per-identity routing,
   process lifecycle, anything beyond one fixed CLI invocation), it
   probably needs its own Dockerfile instead of the shared `x-mcp-image`
   anchor — see `services/engram-router/` for that shape.
2. **Add a compose service.** Reuse the shared `x-mcp-image` anchor at the
   top of `docker-compose.yml` if the tool can be installed into the
   existing shared image (`uv tool install` / `npm install --global` in
   the `Dockerfile`); otherwise give it its own `build:` context like
   `auth-gateway` or `engram-monitor`. Only expose the service on the
   internal `gateway` network (`expose:`, never `ports:` — `caddy` is the
   sole publisher).
3. **Add a Caddy route block.** Copy an existing `handle /mcp/<name>*`
   block: `forward_auth auth-gateway:3000 { uri /verify; import
   strip_gateway_headers; copy_headers X-Gateway-User X-Gateway-User-Id }`
   then `reverse_proxy <service>:9000`. Only add extra `copy_headers` /
   `header_up` promotion (like the Atlassian PAT injection) if the new
   MCP needs a brokered per-user secret.
4. **Add any new secrets to `.env.example`**, documented inline.
5. **Verify:** `docker compose config -q`, then `docker compose up -d
   --build <service>`, then an unauthenticated request against the new
   route (expect `401`) and an authenticated one (expect success).

## Development / testing

- `services/auth-gateway`: `npm test` (`node --test`), `npm run typecheck`
  (`tsc --noEmit` over JSDoc-typed ESM), `npm run lint` (eslint), `npm run
  format` (prettier check). See `openspec/config.yaml` for the pinned
  toolchain.
- Everything else (`Dockerfile`, `docker-compose.yml`, `Caddyfile`,
  `services/engram-monitor/{Dockerfile,nginx.conf}`) is infra/config,
  validated statically (`docker compose config -q`, `caddy validate
  --config Caddyfile`) rather than unit-tested.

## Rollback

Nothing is deployed by default. `docker compose down -v` plus reverting
the changed files restores the empty state. Per-service rollback deletes
its compose service block and matching Caddy route — no shared state is
touched.
