# Feature: Self-Service MCP Profile Page

## Objective

Every admin-panel account (admin or member) can see their own MCP
client config for `/mcp/engram` — Bearer token + which Engram Cloud
subprojects they're granted — and copy it into their own MCP host
config. An admin can additionally view any account's profile, not just
their own.

## Problem / Why

User-requested (2026-09-17). Admin-panel accounts have never had an MCP
Bearer token issued at all (that only happened for regular gateway
users historically). There was also no page anywhere showing which
Engram Cloud projects an account can reach, or a ready-to-paste MCP
config block.

## Scope

In scope:
- `GET /admin/profile` (self) and `GET /admin/profile?userId=N` (admin
  viewing another admin-panel account) — reachable by BOTH roles,
  unlike every other admin-app.js route added this session.
- Auto-issue an MCP Bearer token (existing `issueToken`, reusing the
  `tokens` table — no new table) the first time a profile has none,
  same lazy-provisioning pattern as Cloud identity linking.
- List the account's own Engram Cloud project grants (new
  `listGrants(principalId)` — `GET /admin/users/{id}/grants`, confirmed
  real via deepwiki) filtered to ones usable via `/mcp/engram`
  (`engram-router`'s `deriveProject` always produces
  `<username>.<subproject>` — only grants starting with `<username>.`
  are reachable this way at all).
- One read-only, click-to-select `<input>` (D10 show-once pattern,
  zero-JS — no real "click to copy" is possible under this app's CSP)
  per usable grant, containing the full MCP client config JSON.
- `POST /admin/profile/regenerate-token` — self for a member, or a
  chosen `userId` for an admin. Reuses `regenerateToken` (already
  exists, `user-admin.js`).
- `POST /admin/profile/revoke-token` — same eligibility rule as
  regenerate; lets a member "quitar" (revoke) their own token without
  issuing a replacement, added 2026-09-18 after the user asked for
  member self-service control over their own MCP access, not just
  copy/regenerate.
- Nav links: "Profile" in `renderAdminNav` (admin) and in
  `renderConsolePage`'s header (member — currently the only page they
  can reach).

Out of scope (explicitly, from the exploration/decision conversation):
- A "true" one-click copy button — technically impossible under this
  app's zero-JS CSP (`default-src 'none'`, no `script-src`), same
  constraint already accepted for the password show/hide toggle.
- Any project the account is NOT granted access to.
- Changing how `engram-router` derives project identity, or the Cloud
  grants system itself — read-only consumers of both.

## Constraints / Decisions

- Token auto-issuance: confirmed with the user — same lazy pattern as
  `ensureEngramCloudLink` (Phase 5), not a manual "Issue" button.
- Raw token values are NEVER retrievable after issuance (D10, this
  codebase's own established rule — `tokens.token_hash` only). So:
  - First-ever profile view (no token existed) → the just-issued raw
    value is shown, once, in the config block(s).
  - A later view (token already existed before this request) → no raw
    value available; show token metadata (label/created/last_used) +
    a "Regenerate" button instead of a config block with a real
    secret. Regenerating re-enters the "just issued" state.
- A member can never view or regenerate another account's profile —
  `userId` is honored only for `admin.role === 'admin'`.

## Task Checklist

- [x] 1. RED/GREEN `test/engram-cloud-client.test.js`: `listGrants(principalId)` — `GET /admin/users/:id/grants`, returns the array as-is. 2 new tests.
- [x] 2. RED/GREEN `test/admin-app.test.js`: `GET /admin/profile` (self, member) — auto-issues a token on first visit, config block(s) rendered with the real Bearer value, one per grant matching `<username>.*`.
- [x] 3. RED/GREEN: `GET /admin/profile` on a SECOND visit (token already exists) — no raw value anywhere in the response body; token metadata + Regenerate form rendered instead.
- [x] 4. RED/GREEN: `GET /admin/profile?userId=N` — 403 for a member (own profile only); works for an admin, viewing another account's grants/token state.
- [x] 5. RED/GREEN: `POST /admin/profile/regenerate-token` — self (member or admin) always allowed; `userId` for another account admin-only; full 5-step write guard (Origin/CSRF); re-enters the "just issued" state with a fresh raw value.
- [x] 6. Nav: "Profile" link added to `renderAdminNav` and to `renderConsolePage`'s header (member-reachable).
- [x] 7a. RED/GREEN `test/admin-app.test.js`: `POST /admin/profile/revoke-token` — self (member) revokes the active token, leaves none active; `userId` for another account rejected for a member (403); works for an admin revoking a target account's token. New `revokeProfileToken` (`user-admin.js`, D8 audited, generic across roles like `regenerateToken` — deliberately NOT reusing `revokeManagedToken`, which re-checks `getManagedUser`/is_admin=0 only and would wrongly reject an admin-panel account target; also named distinctly from the pre-existing CLI-only `revokeToken(db, {token})`). Added a "Revoke" button next to "Regenerate" in `renderProfilePage`'s existing-token markup. 3 new tests.
- [x] 7b. BUG FIX (reported live by the user 2026-09-18: "solo veo regenerar pero no me muestra nada"): `POST /admin/profile/regenerate-token`'s success path used to discard `regenerateToken`'s returned `rawToken` and 302-redirect to `GET /admin/profile` — which by then already sees an active token and never shows a raw value again (D10, hashed at rest). The freshly regenerated token was minted but the user could never see/copy it. Fixed by extracting `sendProfilePage` (shared by GET and the regenerate success path) and rendering it DIRECTLY (200) with the fresh `rawToken`, matching the established convention already used by `handlePostAdminTokensRegenerate` for regular users. RED/GREEN: updated the existing regenerate-token test to assert 200 + the raw config body, instead of 302. 145/145 admin-app tests, 405/405 full suite, lint clean.
- [ ] 7. Manual E2E on the VPS: real admin and a real member each see their own correct grants/config; admin can view a member's profile; regenerate produces a working new token (old one stops working) AND SHOWS it; member can revoke their own token.

Also added along the way: `getAdminAccount` (user-admin.js, the admin/member mirror of `getManagedUser`) to resolve `?userId=` safely.

Full suite: 405/405 `node --test` passing (auth-gateway), lint clean.

## Progress Notes

- A separate, much bigger ask surfaced mid-task: the user wants
  collaborative/shared Engram projects (no per-identity prefix). Explored
  `engram-router`'s actual mechanism (one dedicated child process per
  exact `identity.subproject` string, no access to auth-gateway's Cloud
  grants at all) and confirmed this needs a real cross-service redesign,
  not a quick tweak. User explicitly chose to finish this feature first;
  the collaborative-projects idea is deferred, recorded separately in
  Engram memory (not this file — it isn't part of this feature).
