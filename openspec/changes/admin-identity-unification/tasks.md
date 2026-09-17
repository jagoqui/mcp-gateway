# Tasks: Admin/Engram Cloud Identity Linking

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~350-400 (auth-gateway only: admin-app.js, user-admin.js, admin-panel.js + their tests) |
| 400-line budget risk | Medium |
| Chained PRs recommended | No (single PR likely fits; split into 2 units below regardless, for a clean rollback boundary per unit) |
| Suggested split | Unit 1 (login-time link) → Unit 2 (import) |
| Delivery strategy | auto-chain (session preflight) |
| Chain strategy | n/a unless Unit 2 alone exceeds budget at tasks-completion time — re-assess then |

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Rollback boundary |
|------|------|-----------|----------------------|--------------------|
| 1 | Extract `ensureEngramCloudLink`; call it from `POST /admin/login`'s success path | PR 1 | `node --test test/admin-app.test.js` | Revert the extraction + the one new call site; `GET /admin/engram-cloud/sso` unaffected (still has its own inline-turned-shared logic) |
| 2 | `GET`/`POST /admin/engram-cloud/import` + nav link | PR 2, needs Unit 1's `ensureEngramCloudLink`-adjacent helpers only loosely (independent otherwise) | `node --test test/admin-app.test.js test/user-admin.test.js` | Revert the two new routes, the new `user-admin.js` function, and the nav link |

## Phase 1: Login-Time Cloud Link (Unit 1)

- [x] 1.1 RED `test/admin-app.test.js`: 3 new tests on `POST /admin/login` — first-time admin creates a `engram_cloud_credentials` row; already-linked admin makes no new Cloud calls; Cloud unreachable still returns 302 and creates no row. Only the first was a genuine RED (the other two were vacuously true pre-change, since login made no Cloud calls at all yet — confirmed intentionally, not a test-quality gap).
- [x] 1.2 GREEN: extracted `ensureEngramCloudLink(db, admin)` out of `handleGetEngramCloudSso`'s inline logic (pure refactor, zero behavior change — full Phase 5 SSO test block re-passed unchanged). `handlePostAdminLogin`'s success path now `await`s it inside its own `try/catch` (D2) before writing the redirect response.
- [x] 1.3 REFACTOR: confirmed — `ensureEngramCloudLink` is the only place create-user+issue-token+save happens now; both call sites (`handleGetEngramCloudSso`, `handlePostAdminLogin`) call it, neither duplicates it.

Full suite after Unit 1: 363/363 `node --test` passing (up from 360).

## Phase 2: Engram Cloud Principal Import (Unit 2, independent of Unit 1 beyond shared helpers)

- [x] 2.1 RED `test/user-admin.test.js`: 3 new tests for `importEngramCloudPrincipal` — creates the `users` row (`is_admin = 1`) + `engram_cloud_credentials` row in one transaction; writes exactly one `user.create` audit row; a duplicate local username rolls back all three (user, link, audit).
- [x] 2.2 GREEN: `src/user-admin.js` — added `importEngramCloudPrincipal`, taking an already-issued raw token as a parameter (the async `issueToken` call happens in `admin-app.js` before this runs, per D4 — matches `createManagedUser`'s async-before/sync-inside split).
- [x] 2.3 RED `test/admin-app.test.js`: `GET /admin/engram-cloud/import` — unauthenticated → 401, stub never hit; authenticated → lists a Cloud principal absent from `engram_cloud_credentials`, excludes one that has a row. Found and fixed a substring-assertion bug in the test itself while diagnosing an apparent RED-that-should-be-GREEN result: `'unlinked-one'` contains `'linked-one'` as a substring, so the negative assertion could never pass regardless of whether filtering worked — renamed the fixtures to non-overlapping strings.
- [x] 2.4 GREEN: `handleGetEngramCloudImport` — calls `listEngramCloudUsers()`, diffs against a local `SELECT principal_id FROM engram_cloud_credentials`, renders the list.
- [x] 2.5 RED `test/admin-app.test.js`: `POST /admin/engram-cloud/import` — full 5-step write guard (unauthenticated → 401; mismatched Origin → 403, stub never hit); valid submission issues a token for the chosen principal then imports it, redirects to `/admin/users`; mismatched password confirmation → 302 `?error=mismatch`, nothing created, no Cloud call made at all (fails validation before any network call).
- [x] 2.6 GREEN: `handlePostEngramCloudImport` wired into `handleAdminRequest`. Added a new `unreachable` entry to `ADMIN_PANEL_ERRORS` (not originally planned — needed once the handler's own `issueEngramCloudToken` failure path was written).
- [x] 2.7 GREEN: `renderImportPage`/`renderImportRow` in `admin-panel.js` — per-principal row with its own import form (`principalId` hidden field, `username`/`password`/`passwordConfirm` inputs, `csrf` hidden field), zero `<script>`, reuses `ADMIN_PANEL_ERRORS` for validation-error rendering. Tested indirectly through the route-level tests above (Phase 1's own established precedent for this codebase — no separate renderer-only test file).
- [x] 2.8 Nav: added an "Import from Engram Cloud" link to `renderAdminNav`.

Full suite after Unit 2: 372/372 `node --test` passing (up from 363), lint clean.

## Phase 2b: Member Role Sync (Unit 3, new, 2026-09-17)

User-requested addition after Units 1-2 shipped: local admin-panel role
must be kept in sync with Engram Cloud's own `admin`/`member` role, in
both directions. Resolved with the user: a `member` gets ONLY the
Engram Cloud SSO surface (`GET /admin/engram-cloud/sso` and the
`view=cloud` console tab) — Cloud's own dashboard already enforces
whatever that role can/can't do internally (confirmed earlier via
deepwiki: `dashboardPrincipalSessionClaims.Role` travels in the session
this panel already relays). Every other route (Users, Import, Monitor,
the Cloud admin-proxy routes) stays admin-only — no new fine-grained
permission system is built here.

- [x] 3.1 RED `test/db.test.js`: 2 new tests — `role` column defaults to
  `'admin'`, distinct from `is_admin`; CHECK constraint accepts
  `admin`/`member`, rejects anything else.
- [x] 3.2 GREEN: `src/db.js` — `role TEXT NOT NULL DEFAULT 'admin' CHECK
  (role IN ('admin', 'member'))` added to `users`. `is_admin` keeps its
  existing meaning ("can reach the admin-panel login gate at all", true
  for both roles) unchanged — `role` is the finer distinction WITHIN
  that, a deliberately separate column rather than overloading
  `is_admin`'s existing semantics.
- [x] 3.3 RED `test/admin-app.test.js`: `POST /admin/login` succeeds for
  a `role = 'member'` account — confirmed the existing `is_admin !== 1`
  gate needed no change (trivially true pre-change too, same pattern as
  Unit 1's vacuous-until-meaningful tests).
- [x] 3.4/3.5 RED/GREEN: a shared `rejectNonAdminRole(res, admin)` (D11)
  added right after every admin-only handler's existing auth check —
  `handleGetAdminUsers`, `handlePostAdminUsers`,
  `handlePostAdminUserDisabled`, `handleGetAdminTokens`,
  `handlePostAdminTokensIssue`, `beginTokenWrite` (covers Revoke +
  Regenerate), `handleGetEngramCloudUsers`, `beginEngramCloudWrite`
  (covers the Phase 3 Users/Grant/Token proxy writes),
  `handleGetEngramCloudImport`, `handlePostEngramCloudImport` — 13 call
  sites via 10 edits (3 shared helpers each cover 2+ routes).
  `handleGetAdminConsole` forces `view = 'cloud'` for a member instead of
  rejecting — a plain navigational GET the nav itself never even links
  to for them. 5 new tests: member login succeeds; member rejected (403)
  by Users, Import, and the Cloud admin-proxy; member on
  `?view=monitor` gets redirected to the cloud iframe, not an error;
  member accepted by the SSO route, provisioning a Cloud principal with
  `role: 'member'` (not hardcoded `'admin'`).
- [x] 3.6/3.7 RED/GREEN: `importEngramCloudPrincipal` gained an optional
  `role` param (default `'admin'`, preserving Unit 2's existing tests
  unchanged) stored on the new `users` row. `ensureEngramCloudLink`
  passes `admin.role` to `createEngramCloudUser` instead of the old
  hardcoded `'admin'`. `handlePostEngramCloudImport`'s validation now
  requires `role` to be exactly `'admin'` or `'member'` (A13 allow-list);
  `renderImportRow` renders it as a hidden field, normalizing any
  Cloud role value other than the exact string `'admin'` to `'member'`
  (never a silent admin grant from an unrecognized value). 2 new
  `user-admin.test.js` tests; updated 2 pre-existing Unit 2 import tests
  to submit the now-required `role` field.
- [x] 3.8 Nav: `renderConsolePage` (the only page a member reaches) now
  takes a `role` param and hides the Users link and Monitor tab for a
  member — enforcement is still server-side in the handlers above, this
  is UI-only. `handleGetAdminConsole` passes `admin.role` through.

Full suite after Unit 3: 382/382 `node --test` passing (up from 372), lint clean.

## Phase 3: Manual E2E (both units) — COMPLETE (2026-09-17)

- [x] 3.1 Confirmed by the user directly on this VPS: logged in, the Engram Cloud nav link worked with no second login prompt ("excelente muy bien").
- [x] 3.2 Confirmed by the user directly: `/admin/engram-cloud/import` listed Cloud principals with their roles, import worked.
- [x] 3.3 Verified with a throwaway admin account (`resilience-test-temp`, disabled afterward — not deleted, `admin_audit_log.actor_user_id` is `ON DELETE RESTRICT` by design and correctly refused the delete, preserving its audit rows): stopped `engram-cloud`, logged in — 302 success in 276ms, no `engram_cloud_credentials` row created (provisioning failed fast and was swallowed, exactly per design.md D2). Restarted `engram-cloud`, logged in again — this time the link WAS provisioned, confirming the SSO route's self-healing behavior on the very next login, not just on a manual Cloud-nav visit.

All three units and manual E2E for admin-identity-unification are now complete.

## Phase 4: Follow-ups Found Live (2026-09-17)

Two real issues surfaced immediately after deploying Unit 3, both fixed
same-day:

- [x] 4.1 **Migration bug**: `CREATE TABLE IF NOT EXISTS` is a no-op
  against a table that already exists — it never added `role` to the
  production `users` table, so every pre-existing admin (including real
  ones) got `403 admin_role_required`. Fixed with an explicit
  `migrateAddUsersRoleColumn` (`PRAGMA table_info` check + `ALTER TABLE
  ADD COLUMN`), backfilling every existing row to `'admin'`. New
  `db.test.js` regression test simulates a pre-existing table to prove
  the migration actually runs. Verified live: production `users` table
  gained the column, all 4 existing rows correctly backfilled to admin.
- [x] 4.2 **Login redirect ignored role**: `POST /admin/login`'s success
  fallback was hardcoded `/admin/users`, which a member would just get
  403'd from immediately (`rejectNonAdminRole`). Now role-aware: a
  member's fallback is `/admin/console?view=cloud`, the only surface
  they can actually use; an admin's fallback is unchanged.
- [x] 4.3 **Admin/member accounts invisible in the UI**: nothing ever
  listed admin-panel accounts (as opposed to regular gateway users) or
  their role. `GET /admin/users` now also renders a second, read-only
  "Admin panel accounts" table (new `listAdminAccounts`, mirroring
  `listManagedUsers` for `is_admin = 1` rows) — username, role, status.

Also: mobile responsiveness (shell stacks to one column under 640px,
tables scroll horizontally in a contained wrapper instead of the whole
page) — user-requested, pure CSS, no schema/route changes.

Full suite: 386/386 `node --test` passing, lint clean.
