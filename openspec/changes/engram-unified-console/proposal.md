# Proposal: Engram Unified Console

## Intent

Engram now has three surfaces a human has to juggle separately: Engram
Cloud's own dashboard (managed-token login), engram-monitor (SSH-tunnel
only, zero auth, read-only), and raw `curl`/`psql` for anything
administrative. Give one login (email + password, admin-provisioned) that
gates both engram-monitor (with memory edit for admins) and a new
Engram-Cloud user/project/token admin screen, built inside engram-monitor's
own UI — so there is one system, one credential, not three.

## Scope

### In Scope

- `GET`/`POST /admin/login` — the still-missing admin login PAGE for
  auth-gateway's already-built admin-session machinery
  (`admin-session.js`/`admin-auth.js`/`GET /admin/verify` — implemented on
  this branch, but nothing renders a login form or issues the cookie yet).
  Reused as-is, not rebuilt: this is the single login for everything below.
- A shared `engram serve` instance (new compose service) with
  `ENGRAM_CLOUD_AUTOSYNC=1` against this repo's own `engram-cloud` — the
  bridge that lets engram-monitor's existing REST calls (`GET/POST/PATCH/DELETE
  /observations`, `/sessions`, etc. — already implemented server-side,
  verified against source) operate on the same data now flowing through
  `engram-router`, bidirectionally.
- Routing engram-monitor through Caddy (leaving `network_mode: host`) at a
  real subdomain, gated by the admin session — replacing the current
  SSH-tunnel-only, zero-auth exposure.
- New auth-gateway routes proxying Engram Cloud's `/admin/*` API
  (users/grants/tokens) — a backend-for-frontend so the browser never holds
  a raw Engram Cloud managed token. Engram-monitor's own nginx gets a second
  `proxy_pass` for these, alongside its existing one for `/api/*`.
- New pages inside engram-monitor's own React source (same design
  system/components already there) for: listing/creating Engram Cloud
  users, granting/revoking projects, issuing/revoking tokens.
- Exposing memory edit/delete in engram-monitor's UI, gated on the logged-in
  admin's role (the underlying `PATCH`/`DELETE /observations/{id}` already
  exists server-side).

### Out of Scope

- Rebuilding or replacing auth-gateway's existing admin-session/CSRF/audit
  primitives — reused verbatim.
- A non-admin "viewer" role for engram-monitor — this change gates the
  whole surface behind admin login, single tier. A read-only member role is
  a plausible follow-up, not required now.
- Migrating data between the host-level `~/.engram/` deployment and this
  repo's own `engram-cloud` — unrelated, untouched.
- Changing anything about `engram-router`'s per-identity model — this
  change is purely about the human-facing admin console, not the MCP
  client-facing bridge.

## Capabilities

### New Capabilities

- `engram-console-auth`: the missing admin login page/flow, wiring
  engram-monitor and the new admin routes behind the existing admin-session
  cookie.
- `engram-serve-bridge`: a shared, autosyncing `engram serve` instance
  engram-monitor talks to instead of a bare unsynced local store.
- `engram-cloud-admin-ui`: new engram-monitor pages + auth-gateway proxy
  routes for Engram Cloud user/project/token management.
- `monitor-access-gate`: engram-monitor routed through Caddy, admin-gated,
  replacing SSH-tunnel-only access.

### Modified Capabilities

- None (`openspec/specs/` remains empty; no prior change archived a
  conflicting baseline for any of these areas).

## Approach

**Reuse the existing admin-session primitive; add only the missing login
page.** `authenticateAdmin`/`__Host-admin_session`/`GET /admin/verify` are
already implemented and tested on this branch — this change's only
addition to that surface is `GET`/`POST /admin/login`, mirroring the
already-built regular-user login page (`login-page.js`/`handleGetLogin`)
pattern exactly, just against the admin session instead of the user
session. `bin/admin.js create-user --admin` already creates a bcrypt-hashed
`is_admin=1` row — the "admin already has email/password by default"
requirement is satisfied by running that command once for the operator's
own email as username, not by building anything new.

**The shared `engram serve` instance is the bridge, not a rewrite of
engram-monitor.** Confirmed against source: engram-monitor's frontend
already calls a REST API (`/observations`, `/sessions`, `PATCH`/`DELETE
/observations/{id}`, etc.) that is structurally unrelated to Engram Cloud's
own HTTP surface (`/dashboard/*`, `/admin/*`). Rather than rewriting
engram-monitor's data layer to speak Engram Cloud's API, run one `engram
serve` process with autosync enabled against this repo's `engram-cloud`.
engram-monitor keeps every existing call as-is (including edit/delete,
already implemented server-side); autosync keeps that instance's local
SQLite synchronized with the cloud Postgres in both directions.

**Engram Cloud admin actions are proxied through auth-gateway, never
called directly from the browser.** The new user/project/token management
screens need Engram Cloud's managed-admin token to call `/admin/*` — that
token must never reach client-side JS. auth-gateway (already the trusted
backend behind the admin session) gets new routes
(`/admin/engram-cloud/users`, `/admin/engram-cloud/users/:id/grants`,
`/admin/engram-cloud/users/:id/tokens`) that hold the real token server-side
and forward requests. engram-monitor's own nginx (which already
`proxy_pass`es `/api/*` to local `engram serve`) gets a second `proxy_pass`
for `/admin/*` to `auth-gateway:3000`, keeping the browser same-origin
(same reasoning nginx.conf already documents for the existing proxy — no
CORS surface introduced).

**Monitor moves off `network_mode: host` onto the shared `gateway`
network.** Its current isolation (loopback-only, SSH-tunnel-gated,
`network_mode: host`) exists specifically because it has no auth of its own
and its local API has none either — both conditions this change removes
(auth-gateway now gates it; the local API it talks to is the new shared,
authenticated-by-network-topology `engram serve`, not the bare host
process). Caddy gets a real `monitor.{$DOMAIN}` block, `forward_auth`
against `GET /admin/verify`.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `services/auth-gateway/src/{admin-app,login-page or new admin-login-page}.js` | New/Modified | `GET`/`POST /admin/login`, new Engram Cloud admin-proxy routes |
| `services/auth-gateway/src/engram-cloud-client.js` (new) | New | Server-held Engram Cloud token, thin client for the `/admin/*` proxy routes |
| `docker-compose.yml` | Modified | New `engram-serve` service (shared, autosyncing); `engram-monitor` off `network_mode: host`, onto `gateway`; new volume for `engram-serve`'s local store |
| `Caddyfile` | Modified | New `monitor.{$DOMAIN}` block, admin-gated |
| `services/engram-monitor/src/` (vendored, human-cloned) | Modified | New admin pages (users/grants/tokens); edit/delete UI on observations, gated by admin role; `nginx.conf` gets the `/admin/*` proxy |
| `services/engram-monitor/nginx.conf` | Modified | Add `/admin/*` → `auth-gateway:3000` proxy alongside the existing `/api/*` one |
| `.env.example` | Modified | New `ENGRAM_CLOUD_ADMIN_TOKEN` (server-held, for the proxy routes) documented |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| engram-monitor's vendored source is human-cloned and gitignored (`services/engram-monitor/src/` excluded from this repo's own git) — changes made to it live only on this checkout unless the human pushes them to `github.com/egdev6/engram-monitor` separately | High (by design, not a bug) | Document clearly in tasks.md; this change's own repo commit cannot carry the vendored-source diff, only the wrapper (`Dockerfile`/`nginx.conf`/compose) changes |
| `engram serve`'s local REST API write/edit routes' exact auth story (`ENGRAM_HTTP_TOKEN`) needs to actually gate them in this deployment, or engram-monitor's own network-topology exposure becomes the only guard | Med | `ENGRAM_HTTP_TOKEN` set on the shared `engram-serve` service; engram-monitor's nginx never exposes `/api/*` publicly either way (same-origin proxy only) |
| Whether engram-monitor's REST calls already support passing an explicit `project` (needed since this shared instance is multi-project, unlike engram-router's per-identity single-project children) is unverified — inferred from its existing project-switcher UI, not confirmed against its actual request payloads | Med | Apply phase MUST read the actual vendored source's API client before assuming; this is exactly the kind of "unverified external fact" gateway-foundation's own design.md flagged rather than guessed at |
| Over 400 changed lines across auth-gateway + compose/Caddy + engram-monitor wrapper files | High | Likely slices: (1) admin login page, (2) engram-serve bridge + compose/Caddy wiring, (3) Engram Cloud admin-proxy routes in auth-gateway, (4) engram-monitor UI changes (separate PR scope given the vendored-source caveat above) |

## Rollback Plan

Every piece is additive or a routing change, not a data migration.
Reverting the Caddyfile/compose diff restores engram-monitor's
SSH-tunnel-only isolation immediately. The admin login page is new routes
only — removing them leaves `GET /admin/verify` exactly as it is today.
The Engram Cloud admin-proxy routes touch no existing route. No schema
migration is introduced (no new SQLite tables — `users.is_admin` already
exists).

## Dependencies

- `AUTH_GATEWAY_ADMIN_SESSION_SECRET` already provisioned (admin-session.js
  already requires it today).
- A working Engram Cloud managed-admin token for this repo's own
  `engram-cloud` (already have one — `jagoqui`, bootstrapped this session).
- Human-maintained clone of `services/engram-monitor/src/` stays up to date
  independent of this repo's own git history (pre-existing constraint, not
  introduced by this change).

## Success Criteria

- [ ] Visiting `monitor.{$DOMAIN}` without a valid admin session redirects
      to `admin.{$DOMAIN}/login`, not a bare 401 or the SSH-tunnel-only
      previous behavior
- [ ] Logging in with the default admin's email/password reaches
      engram-monitor's dashboard, seeing memories that are also visible via
      Engram Cloud's own dashboard for the same project (proving the
      autosync bridge, not two disconnected copies)
- [ ] An admin can edit and delete an observation from engram-monitor's UI
      and see the change reflected in Engram Cloud's dashboard
- [ ] An admin can create a new Engram Cloud managed user, grant it a
      project, and issue it a token — all from engram-monitor's UI, without
      ever touching `curl`
- [ ] The Engram Cloud managed-admin token never appears in any browser
      network request, cookie, or client-side script
