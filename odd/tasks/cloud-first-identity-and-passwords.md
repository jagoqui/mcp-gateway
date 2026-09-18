# Feature: Cloud-First Identity, Password Self-Service, Grant UX

## Objective

Finish moving member creation fully into Engram Cloud's own hands, add
password reset/self-service for admin-panel logins, make the grant UI
usable (pick from known projects, see last-project-used), and clean up
now-misleading UI (Cloud token's permanently-false "Last used").

## Problem / Why

User-driven (2026-09-18), after live testing: created a Cloud user
("Pruba") directly in Cloud's own dashboard and it never appeared in
`/admin/users` — no reverse sync. Reflecting on this, the user concluded
member creation belongs entirely to Cloud (which already has its own
admin UI for that), and our system's job is just to (a) mirror who
exists over there, (b) issue/manage a LOCAL login (username+password)
for whichever of those principals need one, and (c) manage MCP/project
access for them. Also: admin-triggered password reset for a member who
lost access, member self-service password change, and Cloud's own
"Last used" field for its own token is confirmed dead code upstream
(deepwiki: Cloud never writes it, for ANY route) — showing it is
actively misleading.

## Decisions (resolved with the user)

- Token model: ONE gateway token per admin-panel account, valid across
  their private default + every granted shared project — NOT one token
  per project (asked via AskUserQuestion, user picked the single-token
  model explicitly). "Last used, which project" becomes a column
  alongside the existing `last_used_at`, not a reason to fork tokens.
- `/admin/users/tokens` (the OLD manual "Issue token" page for regular,
  `is_admin=0` users) stays — CONFIRMED via source read this serves a
  real, currently-used, different population (generic gateway Bearer
  tokens for `/mcp/atlassian` too, not just Engram) — the user's own
  `jagoqui` account has 42 active tokens issued this way. Investigated
  per the user's explicit request to verify before removing; the
  answer was "no, don't remove it."
- Cloud's own "Last used" column (Engram Cloud token section, profile
  page) gets REMOVED, not just left showing a permanently-wrong value —
  confirmed via deepwiki this field is dead code on Cloud's own server
  (never written for ANY route, not even dashboard login), so no future
  server-side fix would ever make it accurate either.

## Scope

In scope:
1. **Password reset (admin) + change (self-service member)**
   - `POST /admin/profile/reset-password` — admin-only (any target,
     including their own account is fine, no deny-by-default concern
     here — unlike project grants, this isn't a Cloud-mediated
     permission). Generates a random default password (same
     entropy/generation approach already used for other secrets in this
     codebase — reuse, don't invent a new RNG pattern), bcrypt-hashes it
     via the EXISTING `hashPassword` (tokens.js, already used by
     user-admin.js's account-creation paths — D11), updates
     `users.password_hash`. Shows the raw default password ONCE (D10,
     same show-once pattern as every token/config value on this page —
     reuse `renderMcpConfigBlock`'s sibling pattern, a plain `<p><code>`
     is fine here, no JSON config needed).
   - `POST /admin/profile/change-password` — reachable by admin OR
     member, self only (no `userId` override at all — this one is
     ALWAYS self, simpler than `resolveProfileTarget`, don't reuse it
     for this route). New password + confirmation field, bcrypt-hash,
     update. No "current password" re-entry required — reaching this
     route already requires a live authenticated admin-panel session.
   - Render: a small form on the profile page, admin sees "Reset
     password" (for anyone), everyone sees "Change my password" (self).
2. **Grant UX**
   - Populate a `<datalist>` (native HTML, zero-JS-compatible — works
     under this app's CSP, unlike a JS-driven autocomplete) on the
     existing "Grant a project" `<input>` with the DISTINCT project
     names aggregated from every grant we can see across ALL linked
     principals (Cloud has no "list all projects" admin endpoint —
     confirmed via deepwiki; aggregating from every principal's own
     `GET /admin/users/{id}/grants` is the only available source). Free
     text still works for a genuinely new project name — this is
     autocomplete, not a closed enum.
   - "Last project used" — new nullable `tokens.last_used_project`
     column (migration needed, `CREATE TABLE` alone never retroactively
     adds a column to an existing DB — see `migrateAddUsersRoleColumn`
     in db.js for the established pattern to copy exactly, D11).
     Captured from the raw `X-Engram-Subproject` request header (present
     or absent) at the SAME point `authenticateBearer` (verify.js)
     already bumps `last_used_at` — store the raw header value verbatim
     when present, `NULL` when absent (meaning "their private default").
     Deliberately NOT re-deriving/validating against grants here (that
     would duplicate `deriveProject`'s logic across two services, D11) —
     this is an observability field showing what a client REQUESTED, not
     a second authorization check.
3. **Cloud-first Users page**
   - Extend the EXISTING `/admin/engram-cloud/import` flow (already
     does 90% of this: lists Cloud principals with no local
     `engram_cloud_credentials` link, lets an admin set username +
     password to create one) rather than building a new mechanism
     (D11). Two changes: (a) auto-generate the default password instead
     of requiring the admin to type one (mirrors the reset-password
     generator above, D11 — same generation call); (b) surface this
     inline on `/admin/users` itself (a compact "N Cloud principals
     without a local login — Import" link/banner) instead of it only
     being reachable via the nav's separate "Import from Engram Cloud"
     link, so it's visible where the user actually expects it, per their
     own words.
   - Do NOT add a way to create a brand-new Cloud principal from OUR
     `/admin/users` page — confirmed explicit user decision: Cloud is
     now the only place a new human identity gets created; this system
     only ever attaches a local login on top of an existing one.
4. **Remove the dead Cloud "Last used" column** (profile page's Engram
   Cloud token section) — replace with a short note that Cloud doesn't
   track this (already true for the "usage count"/"machine" claims this
   section makes; extend the same honest-disclosure pattern).
5. **UI/UX pass** — the user explicitly asked for "una UI más amigable,
   con mejor maquetación y experiencia de usuario" across these pages.
   Concretely: consistent spacing/grouping of the profile page's now
   several sections (config, projects, gateway tokens, Cloud token,
   password), clearer visual separation between "view" and "action"
   areas, and the unified Users table's admin-account rows getting the
   same visual polish as the regular-user rows. Keep within the existing
   zero-JS, plain-CSS constraints (no new dependency, no `<script>`)."

Out of scope (explicit):
- Eagerly creating a matching Cloud admin principal AT system-admin-
  creation time. `ensureEngramCloudLink` already does this LAZILY (on
  first SSO/profile visit) with the correct role passed through
  (`createEngramCloudUser({username, role})`) — functionally equivalent
  for any admin that actually logs in, which every admin by definition
  does. Not worth a second, eager code path for the same outcome unless
  a concrete case surfaces where lazy isn't enough.
- Per-project token scoping (explicitly declined by the user via
  AskUserQuestion — single multi-project token stays).
- A real "list all projects that ever existed" admin endpoint — doesn't
  exist upstream; the grant-aggregation datalist is the best available
  approximation, not a claim of completeness.
- Reverse sync of Cloud-side principal edits (e.g. a role change made
  directly in Cloud's dashboard) into our local `users.role` — only the
  initial link/import captures role; not asked for here.

## Task Checklist

- [x] 1. Migration: `tokens.last_used_project TEXT` (nullable), mirrors
  `migrateAddUsersRoleColumn` exactly (`migrateAddTokensLastUsedProjectColumn`,
  db.js). 2 new tests in `test/db.test.js` (fresh-DB column + migration
  of a pre-existing `tokens` table).
- [x] 2. `authenticateBearer` (verify.js) now takes the full `headers`
  object (was just `authorizationHeader`) and captures the raw
  `X-Engram-Subproject` value (or `null`) into `last_used_project` in the
  same `UPDATE` as `last_used_at`. Threaded through `app.js`'s
  `handleVerify` (previously built a curated headers object that
  silently dropped this header entirely). 2 new tests in
  `test/verify.test.js`.
- [x] 3. Password reset (admin-only, any target) + change (self-only,
  either role) — `POST /admin/profile/reset-password` /
  `/admin/profile/change-password` (admin-app.js), new
  `resetUserPassword`/`changeUserPassword`/`generateDefaultPassword`
  (user-admin.js, D8-audited, `password.reset`/`password.change` added
  to `AUDIT_ACTIONS`). Reset renders directly (200, D10 show-once) via
  `sendProfilePage`'s new `rawPassword` param — never a redirect, same
  class of bug fixed twice already this session. 6 new tests.
- [x] 4. Grant `<datalist id="known-projects">` (best-effort aggregate
  across every OTHER linked principal's own grants — Cloud has no "list
  all projects" endpoint) wired to the existing project `<input>` via
  `list="known-projects"`; `last_used_project` column added to the
  Gateway tokens table (`renderProfileTokenRow`). Found and fixed a real
  bug while wiring this: `listTokensForUser`'s explicit column
  projection never included the new column at all, so it always
  rendered "default (private)" even when a real value was stored — RED
  test caught it immediately. 3 new tests.
- [x] 5. `/admin/engram-cloud/import` no longer takes `password`/
  `passwordConfirm` from the form — generates one server-side
  (`generateDefaultPassword`, D11) and renders it directly (200, D10,
  new `renderImportedPage` mirroring `renderTokenIssuedPage`'s exact
  shape) instead of redirecting to `/admin/users`. New shared
  `listUnlinkedEngramCloudPrincipals(db)` (D11 — both this route and the
  new banner below use the SAME set-difference computation, never two).
  `/admin/users` (`handleGetAdminUsers`, now async) shows a banner
  linking to the import page when unlinked principals exist,
  best-effort/swallowed on a Cloud outage. Rewrote the old
  password-confirmation-mismatch test (that behavior no longer exists)
  and added 3 new tests.
- [x] 6. Removed the Engram Cloud token section's "Last used" column
  entirely (`renderProfileCloudTokenRow`/`...Section`) — confirmed dead
  upstream (deepwiki: Cloud never writes it, for ANY route, not even
  dashboard login) — extended the section's existing honest-disclosure
  note to say so. 1 new test (scoped to that table's own `<thead>`
  specifically — the Gateway tokens table's real "Last used" column,
  fixed earlier this session, stays untouched).
- [x] 7. UI/UX pass: wrapped the profile page's now five sections
  (config, Projects, Gateway tokens, Cloud token, Password) each in the
  ALREADY-EXISTING `.mcp` card class (D11 — did not invent a new `.card`
  class after finding `.mcp` already provides exactly this
  border/padding/spacing treatment in `html.js`'s shared stylesheet).
  Users table's admin-account rows already shared `.badge`/table
  conventions with regular-user rows from earlier work — verified, no
  further CSS class changes needed there. Structural readback via the
  full test suite (every section still renders/asserts correctly), no
  new dependency, no `<script>` added.
- [x] 8. Full suite 453/453 (auth-gateway; engram-router untouched by
  this feature, as scoped), lint clean. Committed on
  `feat/admin-users-panel-05-admin-auth-verify` — not pushed, reviewed
  by the coordinating session first.
- [ ] 9. Manual E2E on the VPS.

## Progress Notes

- Real bug found and fixed during item 4 (not a live report — caught by
  a RED test that failed unexpectedly): `listTokensForUser`'s SQL used
  an explicit column list that predated `last_used_project` and never
  got updated when the column was added in item 1 — the render layer
  was correct, the data just never reached it. A reminder that adding a
  column to the schema and to one query's SELECT * equivalent is not
  the same as updating every OTHER explicit projection of that table.
