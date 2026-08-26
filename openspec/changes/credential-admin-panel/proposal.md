# Proposal: Credential Admin Panel

## Intent

`decideVerify()` answers an un-enrolled Atlassian request with
`enrollUrl: https://auth.{domain}/me/atlassian` — a POST-only JSON route that
404s in a browser. The gateway points users at a page that does not exist, so
enrollment is hand-written `curl`. Give each user one authenticated page to
manage their own MCP credentials, honest about what each MCP can do.

## Scope

### In Scope

- `GET /credentials` — server-rendered HTML, cookie-gated by Caddy's existing
  `auth.{$DOMAIN}` catch-all (no Caddyfile auth change)
- `GET /me/credentials` — JSON status; never returns ciphertext or plaintext
- `DELETE /me/atlassian` — clears the caller's own row
- CSRF defense on cookie-authenticated writes (first browser write-path here)
- Static MCP capability registry module (no new table)
- Repoint `enrollUrl` to `/credentials`

### Out of Scope

- Generic per-user `mcp_credentials` schema for MCPs that cannot consume it
- Per-user MCP containers (contradicts the shared-gateway goal)
- Build step, SPA framework, static-asset serving (CSS/JS inline)
- Managing other users' credentials; rotating shared team secrets
- `config.yaml`'s "Node.js/Express" drift (pre-existing; it is `node:http`)

## Capabilities

### New Capabilities

- `credential-admin-panel`: route inventory, capability registry, status
  disclosure limits, CSRF requirement

### Modified Capabilities

- `gateway-auth`: cookie-authenticated writes MUST carry a valid CSRF token;
  Bearer path unchanged. `openspec/specs/` is empty (gateway-foundation
  unarchived) — if still unarchived at spec time, fold this into
  `credential-admin-panel` rather than emit a delta.

## Approach

**Capability honesty.** Only `mcp-atlassian` reads a per-request
`Authorization` header. `mcp-context7` and `mcp-engram-tool` are
`supergateway --stdio` wrappers with boot-time env keys; supergateway has no
incoming-header → child-process injection path. The panel lists every MCP but
renders a form only where per-user credentials actually work.

```js
// src/mcp-registry.js — static, no table
{ id: 'atlassian', perUserCredentials: true }
{ id: 'context7', perUserCredentials: false, sharedSecretEnv: 'CONTEXT7_API_KEY',
  note: 'Shared team credential — configured by an admin, not per-user.' }
{ id: 'engram', perUserCredentials: false, sharedSecretEnv: 'ENGRAM_API_KEY', note: '…' }
```

Status projects `{ enrolled, scheme, cloudId, updatedAt }` per-user and
`{ perUserCredentials: false, configured, note }` for shared. `configured` is a
boolean from env presence; the value is never disclosed — matching
`bin/admin.js issue-token`'s show-once idiom.

**CSRF: stateless HMAC token bound to the session** (OWASP HMAC Based Token).
Token = `base64url({uid, nonce, iat})` + `.` + HMAC-SHA256 under a
domain-separated derivation of `AUTH_GATEWAY_SESSION_SECRET`, reusing
`session.js`'s `sign()`/`timingSafeEqual`. Hidden field in the page, echoed as
`X-CSRF-Token`; verified for signature, `uid` match, and max age, plus a strict
`Origin` check.

- Not plain double-submit: sibling subdomains under `jagoqui.tech` make cookie
  injection real, which naive double-submit does not survive.
- Not synchronizer: needs new server-side state for no added strength.
- Enforced only when auth came from the cookie. Bearer is never browser-ambient,
  so CLI `POST /me/atlassian` stays unbroken.

**TDD split.** All auth-gateway code (routes, CSRF, registry, status projection,
renderer) is strict-TDD under `node --test`. Caddyfile and compose are untouched
infra; only the new path is documented.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `src/app.js` | Modified | 3 routes → 6; first HTML response |
| `src/csrf.js` | New | Issue/verify HMAC CSRF tokens |
| `src/mcp-registry.js` | New | Static capability registry |
| `src/panel.js` | New | HTML render, inline CSS/JS |
| `src/verify.js` | Modified | `enrollUrl` → `/credentials` |
| `test/**` | New | Test-first for the above |
| `README.md` | Modified | Document `/credentials` |

`db.js` unchanged — no migration.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Unauthenticated `/credentials` 302s to `GET /login`, which 404s — panel unreachable when logged out | High | Open question; a minimal `GET /login` page likely belongs in scope |
| CSRF becomes theater (token never verified) | Med | Forged/absent/wrong-uid tests must go RED first |
| Panel leaks credential material | Med | Allow-list projection; test asserts ciphertext never appears |
| Registry drifts as MCPs are added | Med | Test asserts every compose MCP has an entry |
| Over 400 changed lines | Med | Slice: (1) CSRF + registry + status, (2) HTML panel |

## Rollback Plan

Purely additive: no migration, no Caddy auth change, no new persisted data.
`git revert` and rebuild the auth-gateway image; existing
`atlassian_credentials` rows and all Bearer clients are unaffected.

## Dependencies

- None external. Reuses `authenticate()`, `session.js`, `crypto.js`.

## Success Criteria

- [ ] Logged-in user sets and clears an Atlassian credential from the page, and
      sees Context7/Engram as read-only shared-credential rows
- [ ] Cookie write with missing/forged/other-user CSRF token rejected; Bearer
      write still succeeds without one
- [ ] No response body ever contains credential material
- [ ] auth-gateway suite green under `node --test`, written test-first
- [ ] No new runtime dependency, no build step
