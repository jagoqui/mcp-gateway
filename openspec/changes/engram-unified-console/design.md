# Design: Engram Unified Console

## Technical Approach

One login (auth-gateway's admin session, already implemented, missing only
its login page) gates two things: engram-monitor (now Caddy-routed instead
of SSH-tunnel-only) and a new set of auth-gateway routes that proxy Engram
Cloud's admin API. engram-monitor's existing REST calls keep working
unchanged against a new shared, autosyncing `engram serve` instance instead
of the bare unsynced host process. New Engram-Cloud-management pages live
inside engram-monitor's own React source, calling the new proxy routes
through its own nginx (same same-origin-proxy pattern it already uses for
`/api/*`).

## Architecture Decisions

### Decision: reuse the existing admin-session cookie, add only the login page

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) Add `GET`/`POST /admin/login` to the already-implemented admin-session/CSRF/audit machinery | Small, additive; reuses tested primitives (`authenticateAdmin`, `serializeAdminSessionCookie`) | **Chosen** |
| (b) Build a new, separate login system specifically for this console | Duplicates bcrypt/session/cookie logic already correct and tested; a third identity model in one repo | Rejected |

**Rationale**: `admin-session.js`/`admin-auth.js`/`GET /admin/verify` are
already implemented on this branch — they simply have no login page
pointing at them yet. Building a parallel system would duplicate exactly
the mechanism the user asked to reuse ("el mismo sistema").

### Decision: the shared `engram serve` needs its own tiny reverse-proxy wrapper

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) A small Node wrapper (spawns `engram serve`, proxies `0.0.0.0:<port>` → its forced `127.0.0.1:7437`) — same shape as `engram-router`'s proxy, minus per-identity spawning | One more small service to build/test, but reuses already-tested proxy code | **Chosen** |
| (b) The bare official image as a compose service, no wrapper | `engram serve` binds ONLY `127.0.0.1` with no override env var (verified against source — unlike `engram cloud serve`'s `ENGRAM_CLOUD_HOST`) — unreachable from any other container on the same bridge network | Rejected, does not work |
| (c) `network_mode: host` for this service too, same as Monitor's current constraint | Reintroduces the exact isolation problem this whole change exists to remove, and does not actually solve reachability from a bridge-networked Monitor either | Rejected |

**Rationale**: this is not a preference, it is a hard constraint discovered
by checking the actual bind behavior against source rather than assuming
the official image behaves like `engram cloud serve`'s. No enrollment
logic is needed in this wrapper: Monitor's REST API has no
create-observation call at all (confirmed in Phase 0) — every project it
ever touches was already synced in (and therefore already enrolled) via
`engram-router`.

### Decision: a shared `engram serve` + autosync bridge, not a Monitor rewrite

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) New `engram-serve` compose service, autosync enabled, Monitor's existing REST calls unchanged | Reuses Monitor's already-implemented read/edit/delete UI entirely; one more small service to run | **Chosen** |
| (b) Rewrite Monitor's data-fetching hooks/services to call Engram Cloud's `/admin`/`/dashboard` API directly | Engram Cloud's HTTP surface has no confirmed observation-level CRUD API (only the dashboard's server-rendered pages) — likely a much larger, riskier frontend rewrite | Rejected |

**Rationale**: confirmed via source that `internal/server`'s local REST API
already has `PATCH`/`DELETE /observations/{id}` — exactly the edit/delete
capability requested — and Monitor's frontend already calls that API
family. The bridge reuses all of that; option (b) would mean redesigning
Monitor's entire data layer against a different, less-suited API shape.

### Decision: Engram Cloud admin actions proxied through auth-gateway (BFF), never called from the browser

| Option | Tradeoff | Verdict |
|---|---|---|
| (a) auth-gateway holds `ENGRAM_CLOUD_ADMIN_TOKEN` server-side, exposes narrow proxy routes | One more credential to provision; browser never sees the real token | **Chosen** |
| (b) Hand the browser a scoped Engram Cloud token directly | No proxy layer needed, but a managed-admin-capable token would sit in browser JS/localStorage — unacceptable given everything this session already learned about token leakage | Rejected |

**Rationale**: this repo's own credential-admin-panel precedent already
treats "never let a powerful token reach the browser" as a hard rule (per-
user Atlassian PATs are decrypted server-side and injected via headers,
never handed to the client). This follows the same shape.

### Decision: engram-monitor leaves `network_mode: host`

The only reason engram-monitor was pinned to `network_mode: host` was to
reach the bare host's loopback-only `engram serve` (7437) — a constraint
this change removes by replacing that backend with a Docker-network-native
`engram-serve` service. Once it is no longer talking to the host's loopback,
there is no remaining reason to keep it off the `gateway` network, and
every reason to put it on (Caddy routing, admin gating).

## Data Flow

    admin browser ──cookie──▶ Caddy :443  monitor.{$DOMAIN}
                               │ forward_auth → auth-gateway:3000 /admin/verify
                               ▼
                          engram-monitor:80 (nginx)
                               │ same-origin proxy_pass
                    ┌──────────┴──────────┐
                    ▼                     ▼
              /api/*  ──▶ engram-serve:7437       /admin/*  ──▶ auth-gateway:3000
                          (local REST API,                      (new Engram-Cloud
                           autosync ↕)                            admin proxy routes)
                               │                                       │
                               │ ENGRAM_CLOUD_AUTOSYNC                 │ ENGRAM_CLOUD_ADMIN_TOKEN
                               ▼                                       ▼
                          engram-cloud:18080 (this repo's own, Postgres-backed)

Admin login: `GET /admin/login` (unauthenticated) → `POST /admin/login`
(username/password against `users` table, `is_admin=1` required) →
`Set-Cookie: __Host-admin_session` → redirect to `next` (e.g.
`monitor.{$DOMAIN}` or back into an Engram-Cloud-admin page).

## Interfaces / Contracts

New auth-gateway routes (all under the existing `/admin/*` dispatcher,
`authenticateAdmin`-gated except login itself):

| Route | Method | Purpose |
|---|---|---|
| `/admin/login` | GET | Unauthenticated login form |
| `/admin/login` | POST | Verify credentials, require `is_admin=1`, set cookie |
| `/admin/engram-cloud/users` | GET | List Engram Cloud managed users (proxies `GET /admin/users`) |
| `/admin/engram-cloud/users` | POST | Create a managed user (proxies `POST /admin/users`) |
| `/admin/engram-cloud/users/:id/grants` | POST | Grant a project (proxies `POST /admin/users/{id}/grants`) |
| `/admin/engram-cloud/users/:id/tokens` | POST | Issue a token (proxies `POST /admin/users/{id}/tokens` — **exact request/response shape not yet confirmed against source; apply MUST verify before implementing, not guess**) |

New env vars: `ENGRAM_CLOUD_ADMIN_TOKEN` (auth-gateway, server-held managed
token for the proxy routes — distinct from `engram-router`/`engram-serve`'s
legacy wildcard `ENGRAM_CLOUD_TOKEN`, since this one needs real admin
privileges, not just sync-anything).

## File Changes

| File | Action | Description |
|---|---|---|
| `services/auth-gateway/src/admin-login-page.js` | New | Mirrors `login-page.js` for the admin session |
| `services/auth-gateway/src/admin-app.js` | Modify | Wire `GET`/`POST /admin/login` and the new `/admin/engram-cloud/*` routes into the dispatcher |
| `services/auth-gateway/src/engram-cloud-client.js` | New | Thin fetch wrapper using `ENGRAM_CLOUD_ADMIN_TOKEN`, one function per proxied endpoint |
| `services/engram-serve-bridge/` | New | Small Node wrapper: spawns `engram serve` (forced `127.0.0.1:7437`), reverse-proxies `0.0.0.0:<port>` to it — same shape as `engram-router`'s proxy, no per-identity spawning |
| `docker-compose.yml` | Modify | New `engram-serve-bridge` service + volume; `engram-monitor` off `network_mode: host` onto `gateway`, no longer loopback-published |
| `Caddyfile` | Modify | New `monitor.{$DOMAIN}` block |
| `services/engram-monitor/nginx.conf` | Modify | Add `/admin/*` → `auth-gateway:3000` proxy; `/api/*` target becomes `engram-serve:7437` instead of `127.0.0.1:7437` |
| `services/engram-monitor/src/` (vendored) | Modify | New admin pages; edit/delete UI gated by role — **lives only in this checkout**, see Risks |
| `.env.example` | Modify | Document `ENGRAM_CLOUD_ADMIN_TOKEN`, `AUTH_GATEWAY_ADMIN_SESSION_SECRET` (already required, now load-bearing for two surfaces instead of one) |

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | Admin login: correct creds + `is_admin=1` → cookie; correct creds + `is_admin=0` → generic failure; wrong password → same generic failure | `node --test`, mirrors existing `login.test.js` |
| Unit | Engram-Cloud proxy routes: unauthenticated → same rejection as other `/admin/*`; authenticated → correct outbound call shape (mocked) | `node --test` |
| Integration | `engram-serve` bridge: a `PATCH /observations/{id}` through it becomes visible via a direct `engram-cloud` Postgres query | Manual/E2E, same class of check `engram-remote-mcp` used |
| E2E (manual, apply gate) | Full flow: login → Monitor loads → edit an observation → visible in Engram Cloud dashboard → create a new Engram Cloud user from Monitor's UI | `docker compose up`, browser walkthrough |

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| **Engram Cloud admin token exposure** | Applicable | Held only in auth-gateway's process env, used only in outbound server-side requests | Unit test asserts the token never appears in any proxy route's response body |
| **Monitor's edit/delete reachable by a non-admin** | Applicable | Gated at the Caddy layer (`forward_auth` on the whole `monitor.{$DOMAIN}` vhost) — never relies on Monitor's own frontend to hide the button | Manual E2E: an unauthenticated request to `monitor.{$DOMAIN}` never reaches the container |
| **engram-serve's local API reachable directly, bypassing Monitor's admin gate** | Applicable | `engram-serve` gets no Caddy route of its own — reachable only from other containers on the `gateway` network, same isolation model as `engram-cloud` itself | N/A (network topology, asserted by compose review) |

## Migration / Rollout

Order: (1) admin login page (standalone, testable in isolation, unblocks
everything else), (2) `engram-serve` bridge + compose/Caddy wiring for
Monitor's access gate, (3) Engram Cloud admin-proxy routes in auth-gateway,
(4) engram-monitor's own UI changes (separate concern given the
vendored-source caveat — may land as a follow-up PR the human applies to
their own clone). Rollback per proposal.md: every piece is additive or a
routing change.

## Open Questions — resolved during Phase 0 (see tasks.md)

All three were resolved against real source before any code was written:

- `POST /admin/users/{principalID}/tokens`: request `{"name": "<optional>"}`,
  response `{"raw_token": "<once>", "token": {...adminTokenMetadata}}`.
- Neither `updateObservation` nor `deleteObservation` takes or needs a
  `project` param — both operate on an existing observation's `id`. The
  shared bridge needs no special multi-project write handling.
- Editing observations is already fully wired in Monitor's UI
  (`useUpdateObservation` / `MarkdownPanel.tsx`) — this change's admin gate
  makes it "admin-only" for free, no Monitor source change required for
  edit itself. Only a single-observation delete button is genuinely new UI
  work (bulk delete-everything already exists via `resetAll`).

## Post-Implementation Correction (Phase 3, see tasks.md)

Every `ENGRAM_CLOUD_ADMIN_TOKEN` reference above (lines ~62, ~92, ~115,
~126, ~132) is WRONG — do not provision a new secret by that name.
`.env.example`/`docker-compose.yml`'s `engram-cloud` service already
provision `ENGRAM_CLOUD_ADMIN`, confirmed via deepwiki as exactly the
legacy admin fallback Bearer token `engram cloud serve` itself accepts for
its own `/admin/*` API. `engram-cloud-client.js` reuses that existing,
already-live value; `ENGRAM_CLOUD_SERVER` is likewise reused verbatim from
`engram-router`/`engram-serve-bridge`, not a new name either. See tasks.md
Phase 3 for the full correction and the verified route/payload shapes.
