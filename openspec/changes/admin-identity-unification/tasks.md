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

## Phase 3: Manual E2E (both units)

- [ ] 3.1 On this VPS: create a brand-new local admin (no prior Cloud link), log in, confirm `engram_cloud_credentials` gets a row without visiting the Cloud nav link.
- [ ] 3.2 On this VPS: identify a real Cloud principal with no local link (or create one via `engram cloud bootstrap` / the existing Phase 3 create-user UI without importing it), confirm it appears on `/admin/engram-cloud/import`, import it, log in as the new local account, confirm Cloud SSO works immediately with no second Cloud login.
- [ ] 3.3 Confirm Engram Cloud being briefly unreachable (e.g. stop `engram-cloud` container momentarily) does not block a local admin login, with or without a prior link.
