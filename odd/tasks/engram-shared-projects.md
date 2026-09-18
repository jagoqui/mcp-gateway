# Feature: Grant-Gated Shared Engram Projects

## Objective

Let multiple gateway identities collaborate on the SAME Engram project
in real time via `/mcp/engram`, instead of every identity always being
isolated into `<identity>.<subproject>`. Access to a shared project is
gated by an actual Engram Cloud grant — not open to anyone who can
guess/type the right project name.

## Problem / Why

User-requested (2026-09-17/18), reconsidered after the identity-prefix
removal was flagged as a real security regression on its own (see
Engram memory "Collaborative shared Engram projects deferred"). The
user's actual goal was never "no prefix" for its own sake — it's real
collaboration, authorized by the same grant system already built for
the admin panel (Phase 3 / mcp-profile-page).

## Mechanism (confirmed against real source, not assumed)

- `engram-router` spawns one DEDICATED `engram mcp` child process per
  exact project string (`process-manager.js`'s `getOrCreateChild`,
  keyed by that string, `ENGRAM_PROJECT` set to it at spawn time) — not
  a naming convention, a real per-tenant process boundary.
- `engram-router` has NO access today to auth-gateway's SQLite
  (`engram_cloud_credentials`) or Engram Cloud's grants at all — it is a
  separate container/service with its own process only.
- Engram Cloud's real grants list endpoint (`GET
  /admin/users/{id}/grants`, confirmed via deepwiki) is already wrapped
  as `listGrants` in `auth-gateway/src/engram-cloud-client.js`
  (mcp-profile-page).

## Decisions (resolved with the user)

- No grant for the requested project → hard reject (403), never a
  silent fallback to the identity-private default.
- `X-Engram-Subproject`'s MEANING changes (header name kept, to match
  what the user already tested/expects): it now names the exact,
  unprefixed shared project requested — no longer joined onto the
  identity.
- Absent `X-Engram-Subproject` → unchanged private default (the bare
  identity itself), no grant check at all — this is what makes
  zero-config personal use still free of any admin setup.
- Grant check happens ONCE, on the cold path only (same lifecycle as
  today's one-time `engram cloud enroll` + spawn) — a live/cached child
  is reused without re-checking on every request, avoiding a network
  round-trip per MCP tool call.

## Scope

In scope:
- New auth-gateway endpoint, internal-only (Docker network, not routed
  through Caddy, shared-secret protected): resolves an identity's own
  Engram Cloud grants and answers whether a specific bare project name
  is granted.
- `engram-router`'s `identity.js`/`process-manager.js`/`app.js`: the
  cold-path grant check before enrolling/spawning a child for a
  requested-but-not-yet-verified shared project; a distinct 403 for "no
  grant", never conflated with the existing 503 capacity error.
- A new shared secret (`ENGRAM_ROUTER_INTERNAL_SECRET` or similar),
  provisioned in `.env`/`.env.example`, docker-compose.yml wiring for
  both services.

Out of scope:
- Any UI change — the mcp-profile-page's config blocks already show the
  right per-grant subproject values; this only changes what happens
  server-side when that config is actually used.
- Removing or changing the identity-private default path at all.
- Cross-identity read of another identity's PRIVATE (non-shared)
  project — untouched, still fully isolated.

## Task Checklist

- [x] 1/2. RED/GREEN `test/admin-app.test.js`: `resolveEngramGrant` (private, `app.js`) + `GET /internal/engram-grant?identity=&project=` — shared-secret gated (`X-Internal-Secret`/`ENGRAM_ROUTER_INTERNAL_SECRET`), returns `{granted}`, fails closed for an unknown identity/no Cloud link/unreachable Cloud. 4 new tests.
- [x] 3. `ENGRAM_ROUTER_INTERNAL_SECRET` wired in `docker-compose.yml` for both `auth-gateway` (verifier) and `engram-router` (caller, plus `AUTH_GATEWAY_INTERNAL_URL: http://auth-gateway:3000`). `.env`/`.env.example` provisioning handed to the user (blocked for direct edits) — pending as of this note.
- [x] 4/5. RED/GREEN across three files:
  - `identity.js`: `deriveProject`'s contract changed — returns `{identity, project, isShared}` instead of a joined string; `X-Engram-Subproject` now names a bare SHARED project directly (no more `identity.subproject` join); absent header still means the private identity-scoped default, `isShared: false`. 6 pre-existing tests updated for the new contract + 1 new test documenting the accepted bare-name-collision consequence.
  - `process-manager.js`: `getOrCreateChild(project, {identity, isShared})` — grant check ONLY on the cold (not-yet-cached) path, via injectable `checkGrant` (default throws loudly if ever reached unconfigured — never a silent allow). New `GrantDeniedError`. 4 new tests + fixed a real latent bug found while renaming (`children.delete(identity)` on the ready-timeout cleanup path used the wrong variable after the rename — would have deleted the wrong map key).
  - `app.js`: passes `{identity, isShared}` through; maps `GrantDeniedError` to a distinct 403, never conflated with the existing capacity 503. 1 pre-existing test updated (bare project, not joined), 1 new test.
  - New `grant-client.js` (`createGrantChecker`) — real HTTP call to the new endpoint, fails closed on any non-2xx or network error. 5 new tests.
  - Wired into `bin/engram-router.js` (`ENGRAM_ROUTER_INTERNAL_SECRET`/`AUTH_GATEWAY_INTERNAL_URL`, both required — no silent default for the shared path).

Full suite: auth-gateway 401/401, engram-router 47/47 (including grant-client.test.js), both lint clean.

- [ ] 6. Manual E2E on the VPS — pending: needs `ENGRAM_ROUTER_INTERNAL_SECRET` provisioned in `.env` first (blocked for direct edits, handed to the user), then both `auth-gateway` and `engram-router` rebuilt/redeployed together (engram-router's own startup now REQUIRES this secret — must not deploy it before the secret exists, or it crash-loops).

## Progress Notes

- Known, deliberately accepted consequence of the new design (documented
  in `identity.js`'s own doc comment and a dedicated test): a shared
  project's bare name can collide with another identity's own private
  default (someone granted a project literally named "yenny-fernanda"
  lands in the exact same project as identity "yenny-fernanda"'s own
  private space). Operators must never name a shared project after a
  real gateway username. Flagged to the user, not fixed with an extra
  reserved-name check (not asked for, and would need its own design —
  e.g. checking every existing identity on every grant creation).
