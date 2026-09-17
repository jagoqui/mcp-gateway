# Proposal: Admin/Engram Cloud Identity Linking

## Intent

Admin-panel accounts (local, SQLite, username+password) and Engram Cloud
managed principals (Postgres, token-only) are two independent user lists
today. Phase 5 (`engram-unified-console`) linked them one-directionally
and lazily: a local admin gets a Cloud principal auto-provisioned only if
and when they click the "Engram Cloud" nav link. This leaves two real
gaps, both confirmed with the user before writing this proposal:

1. A local admin who never clicks that link has no linked Cloud identity
   even though they are fully able to use the panel.
2. Cloud principals that already existed before this admin panel did
   (created directly against Cloud, outside this system) have no local
   admin account at all — they are invisible here, not just unlinked.

This change makes every local admin account carry a linked Cloud
identity, and adds an explicit import path for pre-existing Cloud
principals to become local admin accounts. It deliberately does NOT
change how anyone logs into this panel.

## Explicit Product Decisions (resolved with the user before this proposal)

- **Login mechanism stays local password.** Not a token-paste field, not
  Cloud-only auth. Every existing login flow, cookie, and CSRF mechanism
  is untouched. This was the most consequential of the three questions
  asked — the user initially asked for "one identity, one login," but
  confirmed (once Cloud's token-only auth model was explained) that the
  actual need is satisfied by linking, not by replacing this panel's own
  authentication.
- **Existing local admins**: auto-provision and link a Cloud identity
  automatically, without requiring a manual click — on their next
  successful login to this panel (reusing Phase 5's exact
  create-user+issue-token+encrypt-and-store logic, just triggered from a
  different call site).
- **Existing Cloud-only principals**: need an explicit import step (list
  them, let an operator create a local account for one, assign it a new
  local password) — confirmed as still needed after the auto-link
  decision above, since auto-link only covers the local→Cloud direction.
- **Resilience**: local password auth remains the sole, independent
  login mechanism — if Engram Cloud is down, this panel stays fully
  usable. No coupling is introduced by this change.

## Scope

### In Scope

- Trigger the existing Phase 5 provisioning logic
  (`getEngramCloudCredential`/`saveEngramCloudCredential`/`createEngramCloudUser`/`issueEngramCloudToken`)
  from `POST /admin/login`'s success path for the authenticating admin,
  not only from `GET /admin/engram-cloud/sso`. Idempotent — an admin who
  already has a link is a no-op read, not a second provision.
- A read-only admin page, `GET /admin/engram-cloud/import`, listing every
  Engram Cloud managed user (`listUsers()`, already proxied) that has NO
  row in `engram_cloud_credentials` for any local admin — i.e. principals
  this panel does not yet know about.
- `POST /admin/engram-cloud/import` — creates a new local admin account
  (username, a newly-set local password) linked to a chosen existing
  Cloud `principal_id`. Does not create a new Cloud user (unlike Phase
  5's provisioning) — the principal already exists; this only issues it
  a fresh token (`issueToken`, already proxied) to store as the link's
  credential and creates the corresponding local `users`/
  `engram_cloud_credentials` rows in one transaction (D8 pattern, same as
  every other admin-panel write).
- Nav entry for the import page, admin-only, same pattern as every other
  admin-panel link.

### Out of Scope

- Any change to `POST`/`GET /admin/login`'s authentication mechanism
  itself (still bcrypt + local password) — explicitly rejected by the
  user.
- Any change to Engram Cloud's own auth model, token format, or
  `/dashboard/login` — unrelated, untouched.
- A break-glass/emergency login path — not needed, since local password
  auth is already the untouched, always-available mechanism (no new
  coupling was introduced for it to be a fallback against).
- Removing or replacing Phase 5's lazy on-click provisioning — kept as
  is; this change adds an additional trigger (login), it does not remove
  the existing one (the SSO route still self-heals if login-time
  provisioning somehow failed).
- Un-linking / conflict resolution when a Cloud username collides with
  an unrelated local admin's username — flagged as an open risk below,
  not solved by this change's first version.

## Capabilities

### New Capabilities

- `admin-login-cloud-link`: provisioning triggered from the login path,
  not only the SSO route.
- `engram-cloud-principal-import`: list unlinked Cloud principals, create
  a local admin account for one.

### Modified Capabilities

- None in `openspec/specs/` — no prior archived change owns this exact
  surface; this builds on `engram-unified-console`'s Phase 5 (still
  active, not yet archived) rather than superseding it.

## Approach

**Reuse Phase 5's provisioning functions verbatim; change only where
they are called from.** `handlePostAdminLogin`'s existing success path
gains one additional step, after the session cookie is set: call the
same `getEngramCloudCredential`/provision-if-missing logic
`handleGetEngramCloudSso` already has. Extracting that shared logic into
one function both routes call is the natural refactor (D11 "no second
implementation" precedent already established in this codebase for
exactly this kind of duplication).

**Import is the mirror image of Phase 5's provisioning, not a new
mechanism.** Phase 5: local account exists → create Cloud principal →
issue token → link. Import: Cloud principal exists → create local
account → issue token → link. Same `engram_cloud_credentials` table,
same encryption, same transaction pattern — only the starting point and
which side gets newly created differs.

**"Unlinked" is computed by set difference, not a new sync flag.**
`listUsers()` returns every Cloud principal; a `SELECT principal_id FROM
engram_cloud_credentials` gives every already-linked one. The import
page's list is simply the former minus the latter — no new state to
keep consistent, computed fresh on every page load.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `services/auth-gateway/src/admin-app.js` | Modified | `handlePostAdminLogin` gains a post-session provisioning step (extracted, shared with `handleGetEngramCloudSso`); new `GET`/`POST /admin/engram-cloud/import` routes |
| `services/auth-gateway/src/user-admin.js` | Modified | New local-account-creation path for import (creates a `users` row + its Cloud link in one transaction, D8) |
| `services/auth-gateway/src/admin-panel.js` | Modified | New `renderImportPage`; nav gains an "Import from Engram Cloud" link |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Login-time provisioning adds an Engram Cloud round-trip (create user + issue token) to every first-time login's critical path, slowing it down or failing it if Cloud is briefly unreachable | Med | Provisioning failure must never fail the login itself — same "graceful, logged, non-fatal" treatment `relayEngramCloudCall` already establishes elsewhere; the SSO route remains a self-healing retry point regardless |
| A Cloud principal's `username` collides with an unrelated existing local admin's username on import | Low-Med | `POST /admin/engram-cloud/import` must require an explicit, possibly-different local username, never assume identity from Cloud's own username field |
| Importing a Cloud principal issues it a brand-new token — if that principal already has other tokens in active use elsewhere (e.g. a human's own CLI), this adds one more without revoking anything, which is intentional but worth calling out explicitly in the UI copy | Low | Token issuance is additive/non-destructive by Engram Cloud's own design (confirmed in Phase 3); no other token is touched |

## Rollback Plan

Both pieces are additive. Reverting the login-time provisioning call
leaves Phase 5's lazy on-click provisioning exactly as it was. Reverting
the import routes removes two routes and one nav link; no schema
migration to undo beyond `engram_cloud_credentials`, which Phase 5
already introduced and this change does not alter.

## Dependencies

- Phase 5 (`engram-unified-console`, already implemented and deployed
  this session): `engram_cloud_credentials` table, `crypto.js`
  encrypt/decrypt, `engram-cloud-client.js`'s `createUser`/`issueToken`.
- A working `ENGRAM_CLOUD_ADMIN_TOKEN` (already provisioned).

## Success Criteria

- [ ] A local admin with no prior Cloud link, logging in for the first
      time after this change ships, has a row in
      `engram_cloud_credentials` immediately after login — without
      visiting the Engram Cloud nav link first
- [ ] `GET /admin/engram-cloud/import` lists a Cloud principal that has
      no local account, and does NOT list one that already does
- [ ] Using the import form creates a working local admin login for a
      pre-existing Cloud principal, and that admin's Engram Cloud SSO
      (Phase 5) works immediately using the issued-at-import token
- [ ] Cloud being unreachable never prevents a local admin from logging
      in
