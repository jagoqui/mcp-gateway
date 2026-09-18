# Feature: Per-Identity Engram Cloud Contributor Attribution

## Objective

Make Engram Cloud's own "Contributors" dashboard tab show each real
gateway identity (Yenny, admin, jagoqui, ...) instead of a generic
`LEGACY_SYNC` entry for everything written through `engram-router`.

## Problem / Why

User-reported (2026-09-18): did a save test as Yenny, but Yenny never
appears in Cloud's Contributors tab — only `LEGACY_SYNC` and
`Jaidiver Gomez Q` (who apparently interacted with Cloud directly via
its own dashboard SSO, not through the router).

## Research (deepwiki, `Gentleman-Programming/engram`, confirmed not guessed)

- Cloud's Contributors tab is built from each chunk's `createdBy` field
  (`internal/cloud/cloudstore/dashboard_queries.go`,
  `DashboardContributorRow`).
- `LEGACY_SYNC` is the documented fallback label for `createdBy` when a
  chunk was synced using a SHARED token rather than a per-user managed
  principal token.
- `createdBy` is a parameter passed into the local `engram mcp`
  process's `Syncer.Export(createdBy, ...)` call at chunk-creation
  time — it is NOT an MCP tool parameter (no `mem_save` field for it),
  and deepwiki could not pin its exact source inside `engram mcp`'s own
  startup code, but every piece of evidence (the LEGACY_SYNC fallback
  condition itself) points to it being resolved once, at process
  startup, from whichever `ENGRAM_CLOUD_TOKEN` that process
  authenticated with (a `whoami`-style resolution against Cloud, most
  likely) — not re-resolved per MCP tool call.

## Root Cause (confirmed against this repo's own source, not guessed)

`engram-router`'s `process-manager.js` `buildEnv(project)` ALWAYS uses
ONE shared `cloudToken` (`ENGRAM_CLOUD_TOKEN`, "the legacy wildcard
token, not a managed principal token" — already commented as such in
this codebase) for every spawned/enrolled child process, regardless of
which real identity is behind the request. Every write, from every
identity, is therefore attributed as `LEGACY_SYNC`.

## Scope

In scope:
- A new auth-gateway internal endpoint,
  `GET /internal/engram-cloud-token?identity=`, mirroring the existing
  `/internal/engram-grant` endpoint EXACTLY (same
  `X-Internal-Secret`/`ENGRAM_ROUTER_INTERNAL_SECRET` gate, never routed
  through Caddy): resolves `identity` → `users.id` → the DECRYPTED
  Cloud token from `engram_cloud_credentials` (reusing `decrypt` from
  `crypto.js`, D11 — no new crypto). Returns `{ token }` or `{ token:
  null }`, never a raw error leaking anything.
- `engram-router`: a new injectable `fetchIdentityToken` option on
  `createProcessManager` (same shape/wiring convention as `checkGrant`),
  with a default that returns `null` (→ always falls back to the shared
  token — safe, no behavior change if ever left unconfigured, UNLIKE
  `checkGrant`'s "throw loudly if unconfigured", because attribution
  accuracy is a nice-to-have, not a security boundary the way grant
  checking is).
- `buildEnv`/`getOrCreateChild`'s cold path: before building env for
  ANY new child (private OR shared), try `fetchIdentityToken({identity})`
  once; use that token for `ENGRAM_CLOUD_TOKEN` if non-null, else fall
  back to the existing shared `cloudToken` exactly as today. Never a
  network round-trip on a cache hit (same "once per spawn" philosophy
  as the grant check).
- New `grant-client.js`-sibling module (or an addition to it) wrapping
  the HTTP call, same fail-closed-to-null-on-any-error shape as
  `createGrantChecker`.
- `bin/engram-router.js`: wires the new fetcher using the SAME already-
  required `ENGRAM_ROUTER_INTERNAL_SECRET` — no new secret needed.

Out of scope (explicit, known limitation — documented, not silently
glossed over):
- TRUE per-write attribution for a SHARED project used by MULTIPLE
  different identities through the same cached process. `createdBy` is
  resolved once at process startup (best evidence available), so a
  shared project's single long-running child can only ever be
  attributed to whichever identity's cold spawn created it — every
  other contributor to that same shared project still shows up as that
  first identity, not themselves. This is a real architectural
  constraint of "one persistent process per project, token resolved
  once," not something this task's scope fixes. Documented here so it
  is never mistaken for "fixed."
- Retroactively fixing already-written `LEGACY_SYNC` chunks in Cloud —
  out of reach from this codebase (Cloud's own data).

## Task Checklist

- [x] 1. RED/GREEN `test/admin-app.test.js` (auth-gateway, same file the
  existing `/internal/engram-grant` tests live in — no separate
  `app.test.js` exists): `GET /internal/engram-cloud-token?identity=` —
  401 missing/wrong secret; 400 missing `identity`; 200 `{token: "..."}`
  for a real linked identity (round-tripped through real `encrypt()`,
  not a placeholder ciphertext); 200 `{token: null}` for an unknown
  identity or one with no Cloud link. New `resolveIdentityToken`/
  `handleInternalEngramCloudToken` in `app.js`, mirroring
  `resolveEngramGrant`/`handleInternalEngramGrant` exactly. 5 new tests.
- [x] 2. RED/GREEN `test/grant-client.test.js` (engram-router): new
  `createIdentityTokenFetcher`, same file/conventions as
  `createGrantChecker`, fails closed to `null` (network error, non-2xx,
  malformed JSON). 6 new tests.
- [x] 3. RED/GREEN `test/process-manager.test.js`: `getOrCreateChild`'s
  cold path calls `fetchIdentityToken` once (only when `meta.identity`
  is present), uses the returned token for `ENGRAM_CLOUD_TOKEN` via
  `buildEnv`'s new `identityTokenOverride` param when non-null, falls
  back to the shared `cloudToken` when null/unconfigured/no-identity;
  never called again on a cache hit; an unconfigured
  `fetchIdentityToken` behaves byte-for-byte like before this feature
  (regression guard). 6 new tests.
- [x] 4. Wired `bin/engram-router.js` — reuses the same already-required
  `ENGRAM_ROUTER_INTERNAL_SECRET`/`AUTH_GATEWAY_INTERNAL_URL` as
  `checkGrant`, no new env var.
- [x] 5. Full suites green: auth-gateway 436/436, engram-router 58/58,
  both lint clean. Committed on `feat/admin-users-panel-05-admin-auth-verify`
  (not pushed — handled separately after review).
- [x] 6a. REGRESSION found and fixed live on the VPS, same day as
  deploying task 5: after deploying, Yenny did a real save test — it
  succeeded locally but never appeared in Cloud's Contributors tab, or
  ANYWHERE in Cloud's own data. Root-caused via direct read-only Postgres
  forensics against the live `engram-cloud-db` container (not guessed):
  `cloud_mutations`/`cloud_chunks` both stopped receiving ANY new row,
  for ANY identity (not just Yenny), at the exact moment of the task-5
  redeploy — `cloud_project_grants` had exactly ONE row (the pre-existing
  shared project), zero grants for anyone's own private project.
  Confirmed via deepwiki: Cloud's managed-token auth for `POST
  /sync/mutations/push` is deny-by-default — a managed (per-principal)
  token can only sync a project its principal has been explicitly
  granted, even that principal's OWN identity-named private default. The
  legacy shared `ENGRAM_CLOUD_TOKEN` used before task 5 had a completely
  DIFFERENT authorization model (`ENGRAM_CLOUD_ALLOWED_PROJECTS` env
  allowlist), so nobody had ever needed a grant for their own space —
  task 5's token swap silently broke that assumption for every identity
  at once, not just new ones.
  Fixed: `ensureEngramCloudLink` (admin-app.js) now self-grants the
  freshly linked principal its own identity-named project right after
  issuing its token — best-effort/swallowed (a transient grant failure
  must never block SSO login or the profile page, same as every other
  Cloud call in this function). 2 new tests: the self-grant call is made
  with the right project name; SSO still succeeds end-to-end even when
  the self-grant call itself fails. 437/437 full suite, lint clean.
- [x] 6b. BACKFILL (operational, not code): the 4 identities already
  linked BEFORE this fix (jagoqui, admin, Yenny, resilience-test-temp)
  never got this self-grant automatically — `ensureEngramCloudLink`'s
  `existing` short-circuit means it never re-runs for an already-linked
  principal, so the fix alone doesn't retroactively unblock them. Granted
  each their own identity-named project directly via Cloud's admin API
  on the VPS, one-time, so they resume syncing immediately without
  waiting to be unlinked/relinked.
- [ ] 6c. Manual E2E on the VPS: Yenny does a FRESH real save into her
  own default private project (after the backfill), confirm it now shows
  up in Cloud's `cloud_mutations`/dashboard Contributors as "Yenny", not
  `LEGACY_SYNC` and not silently dropped.

## Progress Notes

- Confirmed via source read (not assumed) that the existing
  `/internal/engram-grant` tests live in `test/admin-app.test.js`, not a
  separate `test/app.test.js` — the new `/internal/engram-cloud-token`
  tests were added to the same file, right after them, for consistency.
- `insertAdminAccountWithCloudLink` (existing test helper) inserts a
  placeholder `'irrelevant-ciphertext'` string for `ciphertext` — not
  usable for these new tests, which need a REAL decrypt round-trip.
  Inserted the Cloud-link fixture directly with `encrypt()` from
  `crypto.js` instead, for the one test that needs a real token value.
