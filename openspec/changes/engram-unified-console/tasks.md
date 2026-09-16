# Tasks: Engram Unified Console

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1,600+ in this repo (auth-gateway + compose/Caddy); engram-monitor's own UI changes are separate — vendored, gitignored, not part of this repo's diff |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2 → PR3 (this repo only; engram-monitor UI changes land in its own upstream repo, not chained here) |
| Delivery strategy | auto-chain (reused from this session's cached preflight) |
| Chain strategy | stacked-to-main (reused from this session's cached preflight) |

Units 1-3 (PR1-PR3) are all complete: 21/26 tasks done, 344/344
`services/auth-gateway` tests passing. Remaining: task 2.10 (manual E2E,
deferred to live deploy — this VPS), the `.env.example` documentation task
under Phase 3 (blocked on this session's own file-write permission, handed
to the user), and Phase 4 (engram-monitor UI — external repo, human-applied,
never part of this repo's own apply/verify accounting).

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Rollback boundary |
|------|------|-----------|----------------------|--------------------|
| 1 | Admin login page (`GET`/`POST /admin/login`) | PR 1 | `node --test test/admin-login-page.test.js test/admin-app.test.js` | Revert the new page module and its two dispatcher branches |
| 2 | `engram-serve` bridge service + persistent volume; Monitor off `network_mode: host`, Caddy `monitor.{$DOMAIN}` gate | PR 2 | Manual E2E (compose + curl), needs PR1 | Revert compose/Caddyfile diff — restores tunnel-only Monitor immediately |
| 3 | Engram Cloud admin-proxy routes in auth-gateway | PR 3 | `node --test test/engram-cloud-client.test.js test/admin-app.test.js`, needs PR1 | Revert `engram-cloud-client.js` and its three dispatcher branches |
| 4 | engram-monitor UI: admin pages + edit/delete wiring | Separate, upstream (vendored source, gitignored) | Manual E2E in the human's own clone | N/A — not part of this repo's git history |

## Phase 0: Resolve Design's Open Questions (blocks Units 3 and 4)

- [x] 0.1 `services/engram-monitor/src/src/services/engram.ts` (read-only) — external repo, see Phase 4 note below. Its `updateObservation(id, data)`/`deleteObservation(id)` operate on an existing observation's `id` only — no `project` param exists or is needed on either (the server already knows the observation's project). The design doc's inference that writes need an explicit `project` was wrong; no change needed to the shared bridge on this front.
- [x] 0.2 `POST /admin/users/{principalID}/tokens` — request body `{"name": "<optional label>"}` (`createAdminTokenRequest`); response `{"raw_token": "<shown once>", "token": {id, principal_id, token_prefix, name, created_by_principal_id, created_at, last_used_at, revoked_at, revoked_by_principal_id, revocation_reason}}` (`adminTokenMetadata`, via `sanitizeToken` — hash never included). Confirmed against `handleAdminCreateToken` directly.
- [x] 0.3 **Edit is already wired**: `useUpdateObservation` (React Query mutation, `PATCH /observations/{id}`) is already called from `MarkdownPanel.tsx` — editing observations works in Monitor's UI today, with zero auth gating it currently (anyone who reaches Monitor can edit). Once the Caddy admin gate lands (Phase 2), this becomes "editable by admins" for free — **no Monitor source change needed for edit itself**. What's missing: a per-observation delete button — `deleteObservation` exists at the service layer but is currently only called in bulk via `resetAll` (reset everything), never wired to a single observation's UI. Phase 4 shrinks to: (a) optionally add a single-observation delete button, (b) the genuinely new Engram-Cloud admin screens.

## Phase 1: Admin Login Page (Unit 1, PR 1)

- [x] 1.1/1.2 `renderAdminLoginPage` (`src/admin-login-page.js`) — zero-JS form, `next` via shared `sanitizeNext`, reuses `html.js`'s `escapeHtml`/`renderDocument`/`PAGE_HEADERS`. No separate `admin-login-page.test.js` — this repo's own precedent tests page renderers indirectly through the route-level test file (confirmed: no `login-page.test.js` exists either; `login-page.js` is only tested via `login.test.js`'s HTTP assertions).
- [x] 1.3/1.4 `test/admin-app.test.js` extended (8 new tests) + `src/admin-app.js` wired: `GET /admin/login` → 200 form, `next` escaped; `POST /admin/login` correct creds + `is_admin=1` → 302 + `Set-Cookie: __Host-admin_session`; correct creds + `is_admin=0` → identical generic failure to a wrong password; wrong password → generic failure, no cookie; cross-site Origin → 403 before the DB is even touched (added beyond the original plan, matching the regular login's existing CSRF-origin guard). No new crypto primitives — `verifyPassword`/`createAdminSessionToken`/`serializeAdminSessionCookie` all reused as-is.
- [x] 1.5 REFACTOR: `sanitizeNext` is imported/shared from `login-page.js` as planned. `readBody` is a deliberate LOCAL copy in `admin-app.js`, not imported from `app.js` — `app.js` already imports `handleAdminRequest` FROM `admin-app.js`, so importing back would create a circular module dependency. Matches this file's own pre-existing pattern (`sendJson` is already duplicated locally here too, not shared) — corrects this task's original assumption.

## Phase 2: Engram Serve Bridge + Monitor Access Gate (Unit 2, PR 2, needs PR1)

**Corrected mid-flight** (verified against source before implementing, not
assumed): `engram serve` binds only `127.0.0.1`, no override env var exists
(unlike `engram cloud serve`'s `ENGRAM_CLOUD_HOST`) — a bare official-image
compose service would be unreachable from any other container. Needs a
small wrapper, same proxy shape as `engram-router`'s, single fixed child
instead of per-identity spawning. See design.md's corrected decision.

- [x] 2.1 RED `services/engram-serve-bridge/test/app.test.js`: a request to the wrapper's `0.0.0.0:<port>` listener is proxied to a stubbed backend on `127.0.0.1:<real-port>` (same stub-backend technique as `engram-router`'s `app.test.js`); a chunked backend response streams through unbuffered (same pattern); a backend connection error surfaces as 502.
- [x] 2.2 GREEN: `services/engram-serve-bridge/src/app.js` — `createApp(getBackendPort)`/`createServer`, dependency-free byte-level proxy (reuses the exact shape of `engram-router/src/app.js`'s `proxyTo`, adapted for a single fixed backend instead of per-identity).
- [x] 2.3 RED `services/engram-serve-bridge/test/spawn.test.js`: `startEngramServe` waits for `engram serve` to actually be listening (real `waitUntilReady` against a real socket, duplicated with attribution from `engram-router`'s process-manager.js — separate Docker build contexts, no shared package) before resolving; propagates a readiness timeout.
- [x] 2.4 GREEN: `services/engram-serve-bridge/src/spawn.js` (`waitUntilReady`, `realSpawnChild`, `startEngramServe`) + `bin/engram-serve-bridge.js` — spawns `engram serve` once at startup via `ENGRAM_PORT` (confirmed via deepwiki: CLI arg or `ENGRAM_PORT` env, default 7437) with `ENGRAM_CLOUD_AUTOSYNC=1`/`ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_SERVER` (no `ENGRAM_PROJECT` — multi-project), pipes its stdout/stderr to the wrapper's own, waits ready, then starts the proxy server on `PORT` (default 7437, the public/DNS-facing port; internal backend defaults to 17437 via `ENGRAM_SERVE_PORT`).
- [x] 2.5 `services/engram-serve-bridge/Dockerfile` — same engram-binary-fetch-and-verify stage as `engram-router`'s own Dockerfile, no `nodetools`/supergateway stage (`engram serve` speaks plain HTTP itself).
- [x] 2.6 `docker-compose.yml`: new `engram-serve` service (DNS name matches nginx.conf's target; build context `./services/engram-serve-bridge`), persistent `engram_serve_data` volume for `/home/app/.engram` (read-only) (a container-internal mount path, not a host filesystem edit target — `chown`-before-mount applied from the start in the Dockerfile, not repeated as a bug this time).
- [x] 2.7 `docker-compose.yml`: `engram-monitor` — removed `network_mode: host`, added to `gateway` network, `expose: ["80"]`, `depends_on: [engram-serve]`; `caddy`'s `depends_on` extended with `engram-monitor`.
- [x] 2.8 `services/engram-monitor/nginx.conf`: listens on `80` (was `127.0.0.1:7438`); `/api/*` target becomes `engram-serve:7437` (Docker DNS) instead of `127.0.0.1:7437`; added `/admin/*` → `auth-gateway:3000`.
- [x] 2.9 `Caddyfile`: new `monitor.{$DOMAIN}` block, `forward_auth auth-gateway:3000 { uri /admin/verify }`, same shape as every existing gated block; validated via `caddy validate` in a throwaway container.
- [~] 2.10 Manual E2E, run live on this VPS (2026-09-16) — PARTIAL, one real finding:
  - [x] Unauthenticated `GET /monitor/` → 302 to `/admin/login`. Verified.
  - [x] Authenticated `GET /monitor/` → 200, loads the real Vite-built SPA shell (`/monitor/assets/index-*.js`). Verified.
  - [x] `GET /monitor/api/observations` (bridge → `engram-serve` → real local store) → 200, real observation data returned. Verified.
  - [x] `PATCH /monitor/api/observations/1` through the bridge → 200, `revision_count` incremented, `updated_at` bumped. The write itself works end-to-end through Caddy → nginx → engram-serve-bridge → `engram serve`.
  - [ ] **NOT verified — found broken instead**: that same `PATCH` does NOT become visible in `cloud_mutations` (checked immediately and again after 35s; `ENGRAM_CLOUD_AUTOSYNC's` 500ms debounce should easily cover that). `docker logs` on the `engram-serve` container shows exactly one `[autosync] started` line from container startup (27h+ ago) and nothing since — no push attempt, no error, nothing on this specific write. `ENGRAM_CLOUD_AUTOSYNC=1` and `ENGRAM_CLOUD_TOKEN` are both correctly wired into the spawned `engram serve` child's env (confirmed via `bin/engram-serve-bridge.js`'s own source, not guessed). Root cause not yet diagnosed — could be the no-`ENGRAM_PROJECT` (multi-project) mode not wiring the same `onWrite` → `NotifyDirty` hook autosync depends on in single-project mode, or something else entirely. This is Phase 2's own scope (committed well before this session's Phase 3 work) — a real, separate follow-up, not a Phase 3 regression. Local-first writes are NOT at risk either way (engram serve's own SQLite journal has them regardless of cloud sync).

## Phase 3: Engram Cloud Admin Proxy Routes (Unit 3, PR 3, needs PR1 and Phase 0.2) — COMPLETE, VERIFIED LIVE

**Correction found while implementing, then re-corrected after live testing —
design.md's original naming was right all along.** First pass wrongly
concluded the existing `ENGRAM_CLOUD_ADMIN` env var (already provisioned,
already live) could be reused as the Bearer token for these routes instead
of provisioning a new `ENGRAM_CLOUD_ADMIN_TOKEN` secret. That reuse was
committed, deployed, and got a hard 403 against the real `engram cloud
serve` instance. Root cause, confirmed via deepwiki against engram's own
source: `requireManagedAdmin` (called by every `/admin/*` handler) checks
`principal.Source == PrincipalSourceManagedToken` and explicitly REJECTS
`PrincipalSourceLegacyEnvAdmin` — the source tag for both `ENGRAM_CLOUD_ADMIN`
and `ENGRAM_CLOUD_TOKEN` — confirmed by engram's own test,
`TestAdminHandlersRequireManagedAdminAndLeaveNoStateForMembers`, which lists
a legacy admin principal as `forbiddenPrincipal` for exactly these routes.
A genuinely separate managed-admin token is required. `ENGRAM_CLOUD_SERVER`
(base URL, reused verbatim from `engram-router`/`engram-serve-bridge`) was
never wrong — only the admin-token identity was.

Recovering a real managed token also required fixing a second,
independent live-infra gap: `ENGRAM_CLOUD_TOKEN_PEPPER` was never set on
this deployment's `engram-cloud` service (a gap already known from
`engram-console-workspaces`'s own exploration phase, hit again
independently here) — without it, managed-token auth is disabled
server-side entirely, regardless of which token is sent. Provisioned a
new pepper value, then synced it to match `~/.engram/.env`'s existing
value instead (the original engram-cloud deployment this stack's Postgres
data was consolidated from — a mismatched pepper would make the existing
managed-admin's token hash unverifiable). Then `engram cloud bootstrap
recover-token` refused ("requires zero principal tokens, found 1") because
an earlier session had already bootstrapped the one allowed managed admin
and issued it a token that was shown once, never saved, and never used
(`last_used_at` null, confirmed by a read-only query of `cloud_principal_tokens`
first). Deleted that specific unused, never-used token row (explicit user
confirmation obtained first) so the recovery-eligibility check would pass,
then successfully recovered a fresh managed-admin token.

- [x] 3.1 RED `test/engram-cloud-client.test.js`: each client function (`listUsers`, `createUser`, `grantProject`, `issueToken`) sends the correct method/path/body/`Authorization: Bearer <ENGRAM_CLOUD_ADMIN_TOKEN>` to a stubbed HTTP layer (real `node:http` stub server, matching this repo's established test convention, not a mocked `fetch`); token value never appears in any thrown error message or log call. 8 tests.
- [x] 3.2 GREEN: `src/engram-cloud-client.js` — thin fetch wrapper, one function per proxied endpoint, reading `ENGRAM_CLOUD_ADMIN_TOKEN` lazily (never cached — same rotation property as every other secret-reading function in this codebase). Request/response shapes for `GET`/`POST /admin/users` and `POST /admin/users/{id}/grants` confirmed via deepwiki against engram's own source (`handleAdminListUsers`/`handleAdminCreateUser`/`handleAdminCreateGrant`), not guessed — `POST /admin/users/{id}/tokens`'s shape was already confirmed in Phase 0.2.
- [x] 3.3 RED `test/admin-app.test.js` (extend): each new `/admin/engram-cloud/*` route — unauthenticated → same rejection as other `/admin/*` routes, no outbound call attempted (asserted against the real stub server, never hit); authenticated → relays the client's result; mismatched Origin / missing CSRF → 403, stub never hit; upstream failure → 502, never a raw stack trace or the token. 12 tests. These routes are a pure JSON relay for Monitor's own SPA (Phase 4) — no HTML form — so `GET /admin/engram-cloud/users` hands out a fresh admin CSRF token in its own JSON response (`{csrfToken, users}`) for the SPA to reuse via `X-CSRF-Token` on the three POST routes, the JSON equivalent of every other admin page's hidden csrf field.
- [x] 3.4 GREEN: wired all four routes (`GET`/`POST /admin/engram-cloud/users`, `POST /admin/engram-cloud/users/:id/grants`, `POST /admin/engram-cloud/users/:id/tokens`) into `handleAdminRequest` — the two `:id` routes use a regex match, this dispatcher's first dynamic-segment routes (every prior route was an exact string match).
- [x] 3.5 REFACTOR: confirmed the response relay never re-serializes in a way that could leak the token — `relayEngramCloudCall`'s catch always returns a fixed `{error: 'engram_cloud_unreachable'}` shape, never the caught error's own message/stack. No local `admin_audit_log` entry for these routes (deliberate, not an oversight): they operate on Engram Cloud's own separate principal/token ID space, not auth-gateway's `users`/`tokens` tables — a `target_user_id`/`target_token_id` FK there would reference a nonexistent local row. Engram Cloud's own admin API already audits these actions server-side (confirmed via deepwiki: "All admin actions are audited").
- [x] `docker-compose.yml`: `auth-gateway`'s environment gained `ENGRAM_CLOUD_ADMIN_TOKEN` (a genuine managed-admin secret, see correction above) and `ENGRAM_CLOUD_SERVER: http://engram-cloud:18080`. `engram-cloud`'s own environment gained `ENGRAM_CLOUD_TOKEN_PEPPER`. Validated with `docker compose config`.
- [x] task 2.10's proxy-relevant slice: `GET /admin/engram-cloud/users`, verified live end-to-end (2026-09-16) through the real Caddy → auth-gateway → engram-cloud chain on this VPS — 200, returned the deployment's two real managed users. The rest of task 2.10 (Monitor dashboard load, `PATCH /observations/{id}` visibility) is Phase 2's own scope, not re-verified here.
- [ ] `.env.example`: comment documenting `ENGRAM_CLOUD_ADMIN_TOKEN` (new secret) and `ENGRAM_CLOUD_TOKEN_PEPPER` (new secret, on the `engram-cloud` section) — blocked by this session's own file-write permissions on `.env.example`; both were provisioned directly in the live `.env` instead (handed to the user to apply via `!`, confirmed applied), but the example template documenting them for the next deploy is still outstanding.

Full suite: 344/344 `node --test` passing (up from 314 before this phase — 30 new tests: 8 in `engram-cloud-client.test.js`, 22 in `admin-app.test.js`), lint and format clean.

## Phase 4: engram-monitor UI (Unit 4 — separate, upstream, needs Phase 0.1 and 0.3)

OUT OF SCOPE for sdd-apply/sdd-attempt in THIS change: `services/engram-monitor/src/` (read-only).
It is a real git clone of a separate
GitHub repository (`github.com/egdev6/engram-monitor`), with its own Git
common directory, gitignored from this repo. No task below targets it as an
edit path — every reference is descriptive only. Its diff cannot be
committed here — it is tracked and reviewed in that repository's own
history, by a human, in that repository's own clone. This phase is recorded
here for completeness and sequencing only; per design.md's "split
independent repositories into separately planned changes" guidance, it is
never a candidate for this change's automated apply/verify accounting.

- [ ] 4.1 (external repo, human-applied) Add admin pages (list users, grant project, issue token) calling `/admin/engram-cloud/*`, matching existing component patterns (`organisms/`, `atoms/`), in the human's own clone of `github.com/egdev6/engram-monitor` — not this repository.
- [ ] 4.2 (external repo, human-applied) Add a single-observation delete button (edit already works via the existing `useUpdateObservation`/`MarkdownPanel.tsx` wiring, confirmed in Phase 0.3 — nothing to do there), in that same external clone. No role signal needed from the frontend: the Caddy admin gate (Phase 2) already means anyone who reaches Monitor at all is an authenticated admin — Monitor's own code does not need to know or check a role.
- [ ] 4.3 (external repo, human-applied) Human applies and pushes 4.1/4.2's changes to the vendored repo directly; this repo's own `Dockerfile`/`nginx.conf` changes from Phase 2 are what actually deploy whatever that clone contains.
