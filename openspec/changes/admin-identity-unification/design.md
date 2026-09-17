# Design: Admin/Engram Cloud Identity Linking

## Context

Phase 5 (`engram-unified-console`) added `engram_cloud_credentials`
(`user_id` PK/FK, `principal_id`, encrypted `ciphertext`, `updated_at`)
and lazy provisioning triggered only from `GET /admin/engram-cloud/sso`.
This change adds a second provisioning trigger (login) and the reverse
direction (import), reusing that same table and the same
`engram-cloud-client.js` functions (`createUser`, `issueToken`) without
modification.

## Decisions

### D1: Extract Phase 5's provision-if-missing logic into a shared function

`handleGetEngramCloudSso` currently inlines: check for an existing
credential → if missing, `createEngramCloudUser` + `issueEngramCloudToken`
+ `saveEngramCloudCredential`. Extract this into one function,
`ensureEngramCloudLink(db, admin)`, returning the token (existing or
newly provisioned) or throwing on failure. Both `handleGetEngramCloudSso`
and the new login-path call site use it. No behavior change for the SSO
route itself — pure extraction.

**Why**: D11 (this codebase's own established rule) — no second
implementation of the same provisioning steps.

### D2: Login-time provisioning is awaited, but its failure is caught and swallowed, never surfaced

`handlePostAdminLogin` awaits `ensureEngramCloudLink` (already-existing,
already-open `db` handle, same request/response cycle every other admin
route uses — no new fire-and-forget pattern introduced into a codebase
that does not otherwise have one), wrapped in its own `try/catch` that
discards the error, BEFORE writing the success response. Matches
`relayEngramCloudCall`'s "never let an Engram Cloud failure become a raw
error the caller sees" discipline, adapted here to "never let it affect
an unrelated success path at all."

**Why**: explicit user decision — Cloud's availability must never affect
*whether* this panel's own login succeeds; a swallowed error already
satisfies that. The one accepted trade-off: an admin's very first login
(the only time this call does real work — every later login is a fast
existing-row check, not a network round-trip) pays one Engram Cloud
round-trip of latency. Judged acceptable rather than adding an
unprecedented background-task pattern for a one-time, first-login-only
cost.

### D4: Import creates the local account and Cloud link in one transaction, same as every other admin-panel write (D8)

`hashPassword` (async, bcrypt) and `issueEngramCloudToken` (async,
network) both run BEFORE the synchronous `db.transaction(() => {...})`
callback — the same async-before/sync-inside split `createManagedUser`
already uses for its own async `hashPassword` call. Inside the
transaction: insert the `users` row (`is_admin = 1`), insert the
`engram_cloud_credentials` row, record the audit entry. A duplicate
local username throws inside the transaction and rolls back the whole
write, including the already-issued Cloud token's local storage — the
token itself was already issued server-side by that point (an
unavoidable ordering cost of "network call must precede a sync DB
transaction"), so a failed import leaves one harmless unused token on
the Cloud side, never a partial/inconsistent local row.

**Why**: matches this codebase's own D8 pattern exactly; the one
accepted imperfection (an orphaned Cloud token on a failed import) is
explicitly called out here rather than silently accepted.

### D5: The import list is computed fresh on every page load, not cached or flagged

`GET /admin/engram-cloud/import` calls `listUsers()` (existing proxy)
and `SELECT principal_id FROM engram_cloud_credentials`, then filters
the former by the latter in-process. No new "imported" flag on either
table.

**Why**: matches proposal.md's approach section — avoids a second source
of truth that could drift from the actual `engram_cloud_credentials`
rows.

### D6: Local username is a required, independent form field on import — never defaulted from the Cloud principal's own username

The import form's `username` field has no pre-filled default. The
handler validates it exists and is non-empty, exactly like
`handlePostEngramCloudUsers` already validates its own `username` field
— but does not read the Cloud principal's `username` into it.

**Why**: explicit spec requirement (collision safety) — auto-filling
would be a convenience footgun the first time a Cloud username collides
with an existing unrelated local admin.

## Interfaces

```
POST /admin/login (modified)
  — unchanged request/response contract; success path additionally
    fire-and-forget calls ensureEngramCloudLink(db, authenticatedAdmin)

GET /admin/engram-cloud/import
  — admin-gated (same pattern as GET /admin/users)
  — 200: HTML list of { principal_id, username, role } for every Cloud
    principal absent from engram_cloud_credentials

POST /admin/engram-cloud/import
  — admin-gated, full 5-step write guard (D7 origin, CSRF) — same as
    every other admin-panel mutating POST
  — body: { principalId, username, password, passwordConfirm }
  — 302 to /admin/users on success (same D10-consistent pattern as
    every other zero-JS admin form — no raw token in this response
    either way, since the issued token is stored server-side only, never
    rendered)
  — 400 on a duplicate local username, missing fields, or password
    mismatch
```

## Non-Goals (unchanged from proposal.md's Out of Scope)

Login mechanism, Cloud's own auth model, and a break-glass path are
explicitly not touched — see proposal.md.
