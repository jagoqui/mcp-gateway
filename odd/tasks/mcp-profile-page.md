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
- [x] 7c. BUG FIX (found live during E2E on the VPS 2026-09-18, right after deploying 7b, with the built-in bootstrap `admin` account which has zero Engram Cloud grants): `renderMcpConfigBlock`/`renderProfilePage`'s `configBlocks` only ever rendered ONE block PER GRANT (`subprojects.map(...)`) — with zero grants, `configBlocks` was an empty string, so the freshly issued raw Bearer token was computed but never shown ANYWHERE on the page, just the "No Engram Cloud project grants yet" text. This is the deeper root cause behind the original "solo veo regenerar pero no me muestra nada" report — 7b fixed the redirect losing the value, but even with 7b alone, an account with no grants still saw nothing. Fixed: `renderMcpConfigBlock` now accepts `subproject: string | null`; `null` renders the account's own PRIVATE default project config (no `X-Engram-Subproject` header at all — matches engram-shared-projects' own contract for the unprefixed default). `renderProfilePage` now ALWAYS prepends this default block whenever `rawToken` is present, before any per-grant shared blocks. RED/GREEN: new test asserting the raw token is visible via a "Default (private)" block even with zero grants. 146/146 admin-app tests, 406/406 full suite, lint clean.
- [x] 8. BOTH TOKEN SYSTEMS SHOWN SEPARATELY (user-requested 2026-09-18, after live E2E of 7c): the profile page conflated "the one gateway token" with everything the user actually wanted — full history, and Engram Cloud's OWN separate token. Researched via deepwiki against `Gentleman-Programming/engram` (the real upstream repo, resolved from this repo's own Dockerfile `REPO=`) BEFORE designing, per the user's explicit ask: Cloud's admin API (`GET/POST /admin/users/{id}/tokens`, `POST /admin/tokens/{id}/revoke`) tracks id/name/prefix/created_by/created_at/last_used_at/revoked_at/revoked_by/reason — confirmed it does NOT track usage count or client/machine/IP, disclosed honestly in the UI copy rather than silently omitted. User chose (AskUserQuestion) to show both systems as separate sections rather than just the gateway token's own history.
  - `engram-cloud-client.js`: new `listTokens({principalId})` (GET) and `revokeCloudToken({tokenId, reason})` (POST), following the existing `listGrants`/`engramCloudRequest` conventions exactly. 4 new tests (URL-encoding + happy path each).
  - `admin-audit.js`: new `AUDIT_ACTIONS` entry `cloud_token.revoke`; new `DETAIL_ALLOWED_KEYS` entry `cloudTokenId` (a Cloud token's id is an opaque STRING, deliberately kept out of the numeric `target_token_id` column — that column is this codebase's own INTEGER token ids, a different id space). 2 new/updated tests.
  - REAL BUG FOUND while adding the gateway-token history table (not yet reported live, found via review): `renderProfilePage`'s Regenerate/Revoke forms always emitted a hidden `userId` field, even for a member viewing their OWN profile — `resolveProfileTarget` rejects ANY non-null `userId` from a non-admin, even one matching their own id, so a member clicking either button through the REAL rendered form got a 403. Never caught because every existing test built its POST body by hand without a `userId` key, instead of submitting what the actual form emits. Fixed: the hidden field is now only emitted when `target.id !== viewer.id` (`viewer` gained an `id` field). 3 new tests, including one that renders the real form and asserts the field's presence/absence, then submits exactly what the fixed form emits.
  - `renderProfilePage` rebuilt: `tokenMeta` (one token) replaced by `gatewayTokens` (full history, active+revoked, via the existing `listTokensForUser`) rendered as a table (`renderProfileTokenRow`/`renderProfileGatewayTokensSection`, same visual shape as the regular-users `renderTokenRow`, pointed at `/admin/profile/*` routes); new `cloudTokens` (Cloud's own list, `null` hides the section entirely when there's no Cloud link at all, `[]` shows an empty table) rendered separately (`renderProfileCloudTokenRow`/`renderProfileCloudTokensSection`) with a Revoke action per active row.
  - New `POST /admin/profile/cloud-token/revoke` (admin-app.js) — same write-guard/`resolveProfileTarget` eligibility shape as the gateway-token routes; calls `revokeCloudToken` (no local DB row to mutate, so no `db.transaction` needed for the revoke itself — the audit row still gets one, for consistency); records `cloud_token.revoke` success/failure via `recordAudit`.
  - REAL BUG found and fixed DURING implementation (before any live report — caught by a genuinely hanging test): `sendProfilePage` called `cloudTokens.map(...)` inside `renderProfilePage` AFTER `res.writeHead(200, ...)` had already run — a non-array Cloud response (e.g. Cloud briefly returning something malformed) would throw there, leaving `res.end()` never called and the HTTP response hung forever (confirmed via a real reproduction: an unstubbed test route defaulting to `{}` instead of an array hung the whole test file). Fixed defensively: `cloudTokens = Array.isArray(result) ? result : [];` right after the fetch, never trusting the shape downstream. New regression test locks this in.
  - 11 new tests total across the two new sections/bug fixes (self-vs-admin userId field ×3, gateway-token history, Cloud-token section rendering, Cloud-token section hidden with no link, malformed-response defensive test, cloud-token revoke ×4). Full suite 422/422 (auth-gateway), lint clean.
- [x] 9. PROJECTS SECTION + ADMIN-ONLY GRANT (user-requested 2026-09-18): profile now shows a dedicated "Projects" section (project/granted-by/granted-at, not just bare names) instead of the old one-line "Granted subprojects: ..." text, plus an admin-only "Grant a project" form. Deny-by-default, quoted from the user: "New managed users are deny-by-default: they cannot sync any project until an admin grants one explicitly." — granting is ALWAYS admin-only, even for an admin granting their OWN profile a project, checked via `rejectNonAdminRole` BEFORE `resolveProfileTarget` is ever called (that helper's own role gate only fires when a `userId` is present, which would let a member slip through on their own profile otherwise). Scoped to the profile page ONLY (not also inline on `/admin/users` — asked the user, they picked profile-only, `/admin/users`'s existing "Profile" link already reaches it).
  - New `POST /admin/profile/grant-project` (admin-app.js), reusing the already-existing `grantProject`/`grantEngramCloudProject` client wrapper (D11 — it already existed for the JSON-relay `/admin/engram-cloud/users/:id/grants` route, no second implementation needed). Same 5-step write guard shape as every other `/admin/profile/*` write.
  - `admin-audit.js`: new `project.grant` action + `project` detail key, audited on both success and failure (the existing JSON-relay grant route has NO audit at all — a real, pre-existing gap, not something to match; audited here for consistency with `cloud_token.revoke`, added the same session).
  - `renderProfilePage` grew an `errorCode` param (mirroring `renderUsersPage`/`renderTokensPage`'s existing pattern) — the profile page previously had NO way to show an error banner at all; needed for invalid-project-name / Cloud-unreachable / no-link feedback on the new grant form. `handleGetAdminProfile` now reads `?error=` from the query string.
  - 8 new tests: Projects section renders full grant metadata; grant form visible for admin, NEVER for a member (even reading their own profile); grant succeeds for self and for an admin-chosen target; a member is rejected even with no explicit target; empty project name redirects `error=invalid_project`; no Cloud link redirects `error=not_found`; a Cloud-side grant failure redirects `error=unreachable` and audits a failure row.
  - Full suite 431/431 (auth-gateway), lint clean.
- [ ] 7. Manual E2E on the VPS: real admin and a real member each see their own correct grants/config; admin can view a member's profile; regenerate produces a working new token (old one stops working) AND SHOWS it; member can revoke their own token AND their Cloud token; the userId-self-bug fix holds for a real member clicking through the actual page; an admin can grant a new project and see it show up immediately.

Also added along the way: `getAdminAccount` (user-admin.js, the admin/member mirror of `getManagedUser`) to resolve `?userId=` safely.

- [x] 10. BUG FIX (reported live 2026-09-18: "los gateway token aparecen sin uso"): the Gateway tokens table's "Last used" column always showed "never", even for a token being actively used every time an MCP client authenticated — because `authenticateBearer` (verify.js) never wrote to `tokens.last_used_at` anywhere in the codebase; the column existed and was rendered, but nothing ever updated it. Fixed with a single `UPDATE tokens SET last_used_at = datetime('now') WHERE id = ?` right after a successful Bearer authentication (never for an invalid/revoked/disabled attempt). This runs on every proxied MCP request (the same hot path `/verify` already documents as performance-sensitive) — a single indexed UPDATE by primary key, no new query added to the read path. 2 new tests in `test/verify.test.js` (bumps on success, untouched on a revoked/invalid attempt). 439/439 full suite, lint clean.

Full suite: 439/439 `node --test` passing (auth-gateway), lint clean.

## Progress Notes

- A separate, much bigger ask surfaced mid-task: the user wants
  collaborative/shared Engram projects (no per-identity prefix). Explored
  `engram-router`'s actual mechanism (one dedicated child process per
  exact `identity.subproject` string, no access to auth-gateway's Cloud
  grants at all) and confirmed this needs a real cross-service redesign,
  not a quick tweak. User explicitly chose to finish this feature first;
  the collaborative-projects idea is deferred, recorded separately in
  Engram memory (not this file — it isn't part of this feature).
