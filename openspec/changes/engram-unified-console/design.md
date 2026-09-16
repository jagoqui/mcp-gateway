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

The design's original `ENGRAM_CLOUD_ADMIN_TOKEN` naming (lines ~62, ~92,
~115, ~126, ~132) is CORRECT after all — it names a genuine, separate
managed-admin secret, distinct from the legacy `ENGRAM_CLOUD_ADMIN`/
`ENGRAM_CLOUD_TOKEN` env vars `engram cloud serve` itself reads.

A prior revision of this note wrongly concluded the existing
`ENGRAM_CLOUD_ADMIN` value could be reused instead — that was tested live
against the real `engram cloud serve` instance and got a hard 403.
Confirmed via deepwiki against engram's own source: every `/admin/*` route
runs through `requireManagedAdmin`, which explicitly checks
`principal.Source == PrincipalSourceManagedToken` and REJECTS
`PrincipalSourceLegacyEnvAdmin` (the source tag for both
`ENGRAM_CLOUD_ADMIN` and `ENGRAM_CLOUD_TOKEN`) outright — confirmed by this
engram version's own test, `TestAdminHandlersRequireManagedAdminAndLeaveNoStateForMembers`,
which lists a legacy admin principal as `forbiddenPrincipal` for these
exact routes. `ENGRAM_CLOUD_ADMIN_TOKEN` (docker-compose.yml, auth-gateway
service) now holds a genuinely separate, real managed-admin Bearer token,
recovered live on this VPS via `engram cloud bootstrap recover-token`
(the deployment's one existing managed admin had a token row that was
never used/saved by an earlier session — deleted it first so the CLI's
"zero principal tokens" recovery-eligibility check would pass, then
recovered a fresh one). `ENGRAM_CLOUD_SERVER` is still reused verbatim
from `engram-router`/`engram-serve-bridge`, that part of the original
correction held.

Also required, and NOT originally called out anywhere in this design:
`ENGRAM_CLOUD_TOKEN_PEPPER` must be set on the `engram-cloud` service
itself (docker-compose.yml), or managed-token authentication is disabled
server-side entirely, regardless of which Bearer token is sent — this was
already a known gap from `engram-console-workspaces`'s own exploration
phase, hit again independently here. Provisioned live on this VPS,
synced from `~/.engram/.env`'s existing value (the original engram-cloud
deployment this stack's data was consolidated from — a mismatched pepper
would have made the existing managed-admin token's hash unverifiable).

Verified live end-to-end against the real production `engram-cloud`
(2026-09-16): `GET /admin/engram-cloud/users` through the full
Caddy → auth-gateway → engram-cloud chain returned the two real managed
users on this deployment. See tasks.md Phase 3 for the corrected
route/payload shapes (those were already right, deepwiki-verified,
untouched by this correction).

## Phase 5: Console Shell + Per-Admin Engram Cloud SSO (new, 2026-09-16)

Two pieces the original proposal named but never turned into a resolved
design or tasks: (a) a shared header+sidebar+main shell so Monitor and
Engram Cloud's own dashboard render inside one frame instead of two
unrelated full-page products, (b) auto-login into Engram Cloud's own
`/dashboard` using the SAME identity as the admin-panel session, so no
admin ever sees Cloud's separate login screen.

### SSO mechanism — confirmed via deepwiki against engram's own source

`POST /dashboard/login` accepts a managed principal's own issued Bearer
token as a `token` form field (NOT an `Authorization` header) and, on
success, responds `303` with `Set-Cookie: engram_dashboard_token=...;
Path=/dashboard; HttpOnly; SameSite=Lax; Max-Age=28800` (`Secure` follows
`X-Forwarded-Proto`). A token issued to ANY managed principal — not just
the bootstrap admin — works here; there is no admin-only restriction on
dashboard login itself. This means auth-gateway can perform this login
server-side on the admin's behalf and relay the resulting cookie, with
zero client-side JS.

### Identity model — explicit user decision (2026-09-16)

Each admin-panel user gets their OWN Engram Cloud principal + token, not
a shared identity. (Considered and rejected: reusing the single shared
`ENGRAM_CLOUD_ADMIN_TOKEN` bootstrap-admin identity for every admin-panel
user's SSO — simpler, zero new storage, but every admin would appear as
the same Cloud principal, which the user explicitly did not want.)

Storage mirrors this codebase's own existing precedent for exactly this
shape of problem — `atlassian_credentials` (per-user, AES-256-GCM
`ciphertext`, keyed by `user_id`, same `encrypt`/`decrypt` in
`crypto.js`) — rather than inventing a new pattern:

```sql
CREATE TABLE IF NOT EXISTS engram_cloud_credentials (
  user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL,
  ciphertext   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
```

`crypto.js`'s `encrypt`/`decrypt` are reused as-is (generic AES-256-GCM,
not Atlassian-specific despite the `ATLASSIAN_ENC_KEY` env var name) —
introducing a second encryption-key secret for one more per-user
ciphertext column was judged not worth the extra `.env` provisioning
step; the key material has no reason to be scoped per credential type.

### Provisioning — lazy, on first SSO attempt

`GET /admin/engram-cloud/sso` (nav-linked, authenticated admin session
required, no CSRF token needed — a plain navigational GET, no state
mutation of our own):

1. Look up `engram_cloud_credentials` for the current admin session's
   `user_id`. If present, skip to step 3.
2. Not present → provision once, using the existing shared
   `ENGRAM_CLOUD_ADMIN_TOKEN` purely as the PROVISIONING credential
   (never as the identity that logs in): `createUser({username: <admin's
   own username>, role: 'admin'})`, then `issueToken({principalId, name:
   'console-sso'})`. Encrypt the raw token, store
   `{user_id, principal_id, ciphertext, updated_at}`.
3. Decrypt the stored token, `POST /dashboard/login` with it as the
   `token` form field, `redirect: 'manual'` (capture the `Set-Cookie`
   before fetch would otherwise follow the `303`).
4. Re-set the exact same `Set-Cookie` on our own response (same host,
   `engram-cloud.{$DOMAIN}` — the cookie's `Path=/dashboard` scope works
   unmodified since Cloud's dashboard lives on this same origin).
5. `302` to `/dashboard`.

A create-user collision (an existing Cloud principal already has this
admin's username, never linked to them here) surfaces as a clear error,
not a silent failure or an unrelated principal's credential.

### Layout shell

No `X-Frame-Options` or CSP `frame-ancestors` on either Monitor or
Cloud's dashboard (confirmed via deepwiki) — both can be framed. Neither
is our own frontend source (Monitor: separate git-cloned repo; Cloud:
vendored binary), so a true shared header+sidebar+main, not just
matching chrome, needs `<iframe>` — the zero-JS admin panel cannot inject
a common shell into either app's own JS bundle. A new
`GET /admin/console?view=monitor|cloud` renders the shared zero-JS
header+sidebar (real page navigations, not client-side tab state) with
`<main><iframe src="/monitor"|"/admin/engram-cloud/sso"></iframe></main>`
— the `cloud` view's iframe src IS the SSO route above, so opening that
tab performs the login and lands the iframe on `/dashboard` in one step.

Sequenced after SSO (this section) since the shell's `cloud` view depends
on the SSO route existing first.
