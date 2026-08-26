# Design: Credential Admin Panel

## Technical Approach

Seven new/changed routes on the existing `node:http` dispatcher in `src/app.js`: five
new (`GET /login`, `GET /credentials`, `GET /me/credentials`, `POST /me/atlassian/delete`,
`DELETE /me/atlassian`) and two modified (`POST /login` gains an Origin check, `POST
/me/atlassian` gains the CSRF guard and form support). Two
server-rendered HTML pages (`GET /login`, `GET /credentials`) with **zero JavaScript** —
plain `<form method="post">` only — so the pages need no build step, no external assets,
and carry no script-execution surface at all. Cookie-authenticated writes gain a stateless
HMAC CSRF token plus a strict `Origin` check; the Bearer path is untouched.

`GET /login` is **in scope** (added after the proposal was written): `decideVerify()` already
redirects browsers to `https://auth.{domain}/login?next=…`, and that target 404s today.

## Verified Preconditions

| Assumption | Verified against | Result |
|---|---|---|
| `GET /login` is not gated by `forward_auth` | `Caddyfile:57-61` | **Confirmed.** `handle /login*` is a plain `reverse_proxy`, above the catch-all. Prefix match covers `/login?next=…`. No Caddyfile change needed. |
| `/credentials` IS gated | `Caddyfile:69-76` | **Confirmed.** Falls to `handle { forward_auth … }`. |
| A CSP exists today | `app.js` `sendJson()` (sets only `Content-Type`); `Caddyfile` (no `header` directive) | **No CSP exists.** Inline `<script>` would not be blocked — but see D4: we ship none, then add a CSP. |
| `sign()` reusable from `session.js` | `session.js:24` | **Not exported.** Must be exported (D1). |

## Architecture Decisions

### D1 — Reuse `session.js` primitives via export, not duplication
**Choice**: export `sign(payload, secret)`; extract `verifySessionToken`'s inline
length-check + `crypto.timingSafeEqual` into an exported `timingSafeCompare(a, b)` and call
it from both `verifySessionToken` and `csrf.js`.
**Rejected**: re-implementing HMAC/compare in `csrf.js` — two copies of a security primitive
drift, and a length-check omission in the copy is a silent timing leak.
**Rationale**: one HMAC implementation; both are pure functions already covered by tests.

### D2 — Auth method must be reported, not re-sniffed
**Choice**: add `authenticateWithMethod(db, headers, secret) → { user, method: 'bearer'|'cookie' } | null`
in `verify.js`; keep `authenticate()` as a thin wrapper so `decideVerify` and existing tests
are unchanged.
**Rejected**: sniffing in `app.js` via "does an `Authorization: Bearer` header exist". A
request carrying a **garbage Bearer header and a valid session cookie** authenticates by
cookie but would be classified `bearer` — a complete CSRF bypass. This gets its own RED test.

### D3 — HMAC CSRF token, not double-submit or synchronizer
Per proposal. Sibling subdomains under `jagoqui.tech` make cookie injection real, which naive
double-submit does not survive; synchronizer needs new server state for no added strength.
Note `SameSite=Lax` does **not** cover this: sibling subdomains are same-site.

### D4 — Zero JavaScript on both pages, then add a CSP
**Choice**: no `<script>` anywhere; inline `<style>` only. To make that possible,
`POST /me/atlassian` also accepts `application/x-www-form-urlencoded`, and deletion gets a
form-reachable `POST /me/atlassian/delete` (HTML forms cannot send `DELETE`).
Because no script exists, HTML responses can carry a maximally strict header:

    Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
    Cache-Control: no-store
    X-Content-Type-Options: nosniff

**Rejected**: inline `fetch()` glue (needs `script-src 'unsafe-inline'`, which is the exact
thing a CSP exists to forbid); `_method=DELETE` override (route-confusion footgun with no
framework to normalize it).
**Rationale**: `style-src 'unsafe-inline'` is required by the inline `<style>`, but inline
*style* has no script-execution power. `frame-ancestors 'none'` also blocks clickjacking of
the destructive "Remove credential" button. `no-store` matters: the page embeds a CSRF token.

### D5 — Login CSRF: `Origin` check, no token
Login CSRF is **real here**, not theoretical. `readJsonBody` never checks `Content-Type`, so a
cross-site `<form enctype="text/plain">` can deliver a body that parses as valid JSON with no
preflight. A victim logged into the *attacker's* account would enroll their Atlassian PAT into
it. `SameSite=Lax` does not stop this — it governs cookie *sending*, not `Set-Cookie`.
**Choice**: apply the same origin check to `POST /login`, **reject on mismatch, allow on absent**.
**Rationale**: a pre-session token has nothing to bind to and would require server state or a
second cookie (rejected in D3). Browsers always send `Origin` on cross-site POSTs, so
mismatch-rejection closes the vector; allowing absent keeps `curl`/CLI login and every existing
`login.test.js` case working. Cookie-authed writes are stricter (absent ⇒ reject) because they
have a token and no CLI depends on cookie auth.
**Session fixation**: not applicable — `handleLogin` mints a fresh token and `Set-Cookie`
replaces any prior value. No change needed; asserted by test.

### D6 — Status projection is its own module
**Choice**: `src/credential-status.js`, not folded into `panel.js` (a small deviation from the
proposal's file list). It is consumed by both `GET /me/credentials` (JSON) and `GET /credentials`
(HTML), and as a pure DB→object function it is the natural TDD unit.

### D7 — Expected origin from `config.domain`, never `req.headers.host`
The `Host` header is attacker-influencable. Expected origin is always `https://${config.domain}`
composed server-side. Threat-matrix row R3.

## Interfaces / Contracts

### `src/csrf.js`

```js
const CSRF_DOMAIN = 'mcp-gateway.csrf.v1';
const DEFAULT_MAX_AGE_SECONDS = 43200; // 12h
const CLOCK_SKEW_SECONDS = 60;

/** HMAC-SHA256(sessionSecret, CSRF_DOMAIN) → base64url. Domain separation: a
 *  CSRF token can never be replayed as a session cookie, or vice versa. */
export function deriveCsrfSecret(sessionSecret)

/** @returns {string} '<payloadB64url>.<sigB64url>' */
export function issueCsrfToken(uid, sessionSecret, now = Date.now())

/** @returns {boolean} — never throws */
export function verifyCsrfToken(token, { uid, sessionSecret, now, maxAgeSeconds })

/** @returns {boolean} — strict when strict=true (absent headers rejected) */
export function isAcceptableOrigin({ origin, referer }, { domain, strict })
```

**Exact byte contract.**

    payloadObj  = { uid: <number>, nonce: <string>, iat: <number> }
    nonce       = crypto.randomBytes(16).toString('base64url')   // 22 chars
    iat         = Math.floor(now / 1000)                          // UNIX seconds
    payloadB64  = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url')
    sig         = sign(payloadB64, deriveCsrfSecret(sessionSecret))   // base64url
    token       = payloadB64 + '.' + sig

Key order in `JSON.stringify` is irrelevant: verification never re-serializes — it signs the
**received payload string as-is**, then parses. No canonicalization bug is possible.

**Verification algorithm — ordered, every failure returns `false`, never throws:**

1. `token` is a non-empty string.
2. Split at the **first** `.` (`indexOf`, matching `verifySessionToken`'s idiom). No `.` ⇒ false.
3. Recompute `sig` over the payload substring; `timingSafeCompare` (length pre-check first).
4. **Only now** base64url-decode + `JSON.parse` the payload. Attacker-controlled bytes are
   never parsed before the signature holds. Non-object / parse failure ⇒ false.
5. `typeof p.uid === 'number' && p.uid === expectedUid` — strict `===`. This is the session binding.
6. `typeof p.nonce === 'string' && p.nonce.length > 0`.
7. `Number.isFinite(p.iat)`; `age = floor(now/1000) - p.iat`;
   reject if `age > maxAgeSeconds` **or** `age < -CLOCK_SKEW_SECONDS` (future-dated).

**`isAcceptableOrigin` algorithm:**

    expected = `https://${domain}`
    if (origin present)  → return origin.trim() === expected     // literal 'null' ⇒ false
    if (referer present) → parse with new URL(); parse failure ⇒ false;
                           return `${u.protocol}//${u.host}` === expected
    else                 → return !strict                        // strict: cookie writes
                                                                 // non-strict: POST /login

**Token transport**: `X-CSRF-Token` header first; else body field `csrf`. Form posts cannot set
headers, so the body field is what the no-JS pages use. `DELETE /me/atlassian` has no body, so
it must use the header.

### `src/mcp-registry.js`

```js
export const MCP_REGISTRY = Object.freeze([
  Object.freeze({ id: 'atlassian', label: 'Atlassian (Jira / Confluence)',
    route: '/mcp/atlassian', composeService: 'mcp-atlassian', perUserCredentials: true }),
  Object.freeze({ id: 'context7', label: 'Context7',
    route: '/mcp/context7', composeService: 'mcp-context7', perUserCredentials: false,
    sharedSecretEnv: 'CONTEXT7_API_KEY',
    note: 'Shared team credential — configured by an admin, not per-user. ' +
          'supergateway --stdio reads it once at boot; there is no incoming-header ' +
          'to child-process injection path, so per-user credentials cannot work here.' }),
  Object.freeze({ id: 'engram', label: 'Engram',
    route: '/mcp/engram', composeService: 'mcp-engram-tool', perUserCredentials: false,
    sharedSecretEnv: 'ENGRAM_API_KEY', note: '…same…' }),
]);
export function getMcp(id)
```

Drift test regex-scans `docker-compose.yml` for `^  (mcp-[a-z0-9-]+):` (no YAML dep — the
zero-runtime-dep constraint holds) and asserts every match has a registry `composeService`.
Documented coupling: the test resolves `../../../docker-compose.yml`.

### `src/credential-status.js`

```js
/** @returns {{ username: string, mcps: Array<PerUserStatus | SharedStatus> }} */
export function buildCredentialStatus(db, user, env = process.env)
// PerUserStatus: { id, label, perUserCredentials: true, enrolled, scheme, cloudId, updatedAt }
// SharedStatus:  { id, label, perUserCredentials: false, configured, note }
```

**Disclosure limit** — the query is literally
`SELECT scheme, cloud_id, updated_at FROM atlassian_credentials WHERE user_id = ?`.
Never `SELECT *`: ciphertext cannot reach the projection even by accident. `configured` is
`Boolean(env[sharedSecretEnv])` — the value is never read into the response, matching
`bin/admin.js issue-token`'s show-once idiom.

### `src/html.js`

```js
export function escapeHtml(value)              // & < > " '  → entities; null/undefined → ''
export function renderDocument({ title, body }) // <!doctype> + <meta charset/viewport> + <style>
export const PAGE_HEADERS  // the D4 header set + Content-Type: text/html; charset=utf-8
```

Escaping sinks (each gets a RED test): `username`, `scheme`, `cloudId`, `next`, and any error
text. `cloudId` is fully attacker-controlled via `POST /me/atlassian` — a stored-XSS sink.

### `src/panel.js`

```js
export function renderPanel({ status, csrfToken, errorCode })
export const PANEL_ERRORS = Object.freeze({
  invalid: 'That credential was rejected — check the token and scheme.',
  csrf:    'Your page expired. Reload and try again.',
});
```

`errorCode` is looked up in the frozen `PANEL_ERRORS` allow-list; an unknown `?error=` value
renders **no banner**. The raw query value is never echoed (reflected-XSS guard).

Per-MCP markup, `perUserCredentials: true`:

```html
<section class="mcp">
  <h2>Atlassian (Jira / Confluence) <span class="badge">enrolled</span></h2>
  <p class="state">Scheme <code>Token</code> · cloud <code>cloud-123</code> · updated 2026-08-25 10:11:12</p>
  <form method="post" action="/me/atlassian">
    <input type="hidden" name="csrf" value="…">
    <label>API token <input type="password" name="token" required autocomplete="off"></label>
    <label>Scheme <input type="text" name="scheme" value="Token" required></label>
    <label>Cloud ID <input type="text" name="cloudId" autocomplete="off"></label>
    <button type="submit">Save credential</button>
  </form>
  <form method="post" action="/me/atlassian/delete" class="danger">
    <input type="hidden" name="csrf" value="…">
    <button type="submit">Remove credential</button>
  </form>
</section>
```

`perUserCredentials: false` (read-only, no form, no CSRF token — nothing to submit):

```html
<section class="mcp">
  <h2>Context7 <span class="badge">shared credential</span></h2>
  <p class="state">CONTEXT7_API_KEY is configured.</p>
  <p class="note">Shared team credential — configured by an admin, not per-user. …</p>
</section>
```

### `src/login-page.js`

```js
export function renderLoginPage({ next, error, username })
export function sanitizeNext(raw)  // → safe path, default '/credentials'
```

```html
<main>
  <h1>Sign in</h1>
  <p class="error">Invalid username or password.</p><!-- only when error -->
  <form method="post" action="/login">
    <input type="hidden" name="next" value="/credentials">
    <label>Username <input type="text" name="username" value="alice" required autofocus autocomplete="username"></label>
    <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</main>
```

**Failure rendering** (no JS, no validation library): the server re-renders this exact page with
status **401**, a plain `<p class="error">`, the username preserved (escaped), the password field
empty, and `next` carried through. The message is generic — `Invalid username or password.` —
never distinguishing unknown-user / bad-password / disabled, matching the existing uniform 401.

**`sanitizeNext`**: accept only a value starting with a single `/` that is not `//` and not `/\`
(protocol-relative and backslash open-redirect bypasses). Anything else ⇒ `/credentials`.

### Shared inline CSS (single `<style>` in `renderDocument`)

```css
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:44rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
.who{margin:0 0 2rem;opacity:.7}
.mcp{border:1px solid currentColor;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}
.mcp h2{font-size:1.1rem;margin:0 0 .5rem}
.state{font-size:.9rem;opacity:.75;margin:0 0 1rem}
.badge{display:inline-block;font-size:.75rem;padding:.1rem .5rem;border:1px solid currentColor;border-radius:999px;vertical-align:.1em}
label{display:block;margin:0 0 .75rem;font-size:.9rem}
input{display:block;width:100%;margin-top:.25rem;padding:.5rem;font:inherit;border:1px solid currentColor;border-radius:4px;background:transparent;color:inherit}
button{font:inherit;padding:.5rem 1rem;border-radius:4px;border:1px solid currentColor;background:transparent;color:inherit;cursor:pointer}
.danger{margin-top:.75rem;opacity:.8}
.error{border:1px solid currentColor;padding:.5rem .75rem;border-radius:4px;margin:0 0 1rem}
.note{margin:0;font-size:.9rem;opacity:.75}
```

## Route Table — exact `app.js` dispatcher additions

Inserted after the existing `POST /me/atlassian` branch, before the `404` fallthrough. All
paths are exact-string comparisons on `pathname`, so branch order is not load-bearing.

| # | Method | Path | Auth | CSRF (cookie auth only) | Response |
|---|---|---|---|---|---|
| — | GET | `/verify` | — | — | unchanged |
| 1 | GET | `/login` | none (Caddy carve-out) | — | `200 text/html` login page |
| — | POST | `/login` | none | Origin: reject-on-mismatch only (D5) | JSON `200`/`401`, **or** form ⇒ `302 <next>` / `401 text/html` |
| 2 | GET | `/credentials` | required | — (safe method) | `200 text/html`; unauth+HTML ⇒ `302 /login?next=%2Fcredentials`; unauth ⇒ `401` JSON |
| 3 | GET | `/me/credentials` | required | — (safe method) | `200` JSON status |
| — | POST | `/me/atlassian` | required | **required** | JSON `200`, or form ⇒ `302 /credentials` |
| 4 | POST | `/me/atlassian/delete` | required | **required** | `302 /credentials` (form-only) |
| 5 | DELETE | `/me/atlassian` | required | **required** (header transport) | `200` JSON |

`GET /credentials` redirects **relatively** (`/login?next=…`), unlike `decideVerify`'s absolute
`https://auth.${domain}/login?…`. Deliberate: same-origin by construction, and it works over
`http://127.0.0.1:<port>` in tests. Caddy's catch-all normally 302s the unauthenticated browser
before this route is reached; the in-route check is defense-in-depth and makes it testable
without Caddy.

### Body parsing

`readBody(req) → { isForm: boolean, data: object }` replaces direct `readJsonBody` use on the
write routes, keeping the 64 KiB cap:

- `Content-Type` starts with `application/x-www-form-urlencoded` ⇒ `Object.fromEntries(new URLSearchParams(raw))`, `isForm: true`
- otherwise (including absent) ⇒ `JSON.parse`, `isForm: false` — today's exact behavior

**Response mode is driven by `isForm`, not by `wantsHtml(accept)`.** A JSON API client sending
`Accept: */*` must never start receiving 302s; a urlencoded body is an unambiguous browser
signal. Every existing `login.test.js` / `enrollment.test.js` case keeps its JSON response.

### Cookie-write guard order

1. `authenticateWithMethod()` ⇒ `401 {error:'unauthenticated'}` if none.
2. If `method === 'cookie'`: `isAcceptableOrigin(..., { strict: true })` ⇒ `403 {error:'csrf_origin_rejected'}`.
   Checked **before** body parsing so the cheap reject always fires first for a real cross-site attempt.
3. Parse body (`400 {error:'invalid_request_body'}` on failure).
4. If `method === 'cookie'`: `verifyCsrfToken()` ⇒ `403 {error:'csrf_token_invalid'}` (form ⇒ `302 /credentials?error=csrf`).
5. Validate fields, then proceed. `method === 'bearer'` skips 2 and 4 entirely — CLI is unbroken.

## Data Flow

```
Browser                Caddy                     auth-gateway
   │  GET /credentials   │                            │
   ├────────────────────►│ forward_auth /verify ─────►│ decideVerify: no user
   │                     │◄─── 302 auth.D/login?next= ┤ (Accept: text/html)
   │◄─── 302 ────────────┤                            │
   │  GET /login?next=…  │ handle /login* (NO auth) ─►│ renderLoginPage(sanitizeNext)
   │◄─── 200 html ───────┤◄───────────────────────────┤
   │  POST /login (form) │ ─────────────────────────► │ Origin mismatch? 403
   │                     │                            │ verifyPassword → createSessionToken
   │◄─ 302 next + cookie ┤◄───────────────────────────┤ Set-Cookie (fresh — no fixation)
   │  GET /credentials   │ forward_auth /verify ─────►│ 204 + X-Gateway-User
   │                     │ reverse_proxy ────────────►│ buildCredentialStatus + issueCsrfToken
   │◄─── 200 html ───────┤◄───────────────────────────┤ CSP: default-src 'none'; no <script>
   │ POST /me/atlassian  │ ─────────────────────────► │ cookie ⇒ Origin(strict) + CSRF
   │◄─── 302 /credentials┤◄───────────────────────────┤ encrypt() + upsert
```

## File Changes

| File | Action | Description |
|---|---|---|
| `src/csrf.js` | Create | Derive, issue, verify HMAC CSRF tokens; `isAcceptableOrigin` |
| `src/mcp-registry.js` | Create | Frozen static capability registry + `getMcp` |
| `src/credential-status.js` | Create | Allow-list DB→status projection |
| `src/html.js` | Create | `escapeHtml`, `renderDocument`, `PAGE_HEADERS` |
| `src/panel.js` | Create | `/credentials` markup + `PANEL_ERRORS` allow-list |
| `src/login-page.js` | Create | `/login` markup, `sanitizeNext` |
| `src/session.js` | Modify | Export `sign`; extract + export `timingSafeCompare` (D1) |
| `src/verify.js` | Modify | Add `authenticateWithMethod` (D2); `enrollUrl` → `/credentials` |
| `src/app.js` | Modify | 5 route branches, `readBody`, cookie-write guard, HTML headers |
| `test/*.test.js` | Create/Modify | See Testing Strategy |
| `README.md` | Modify | Document `/credentials` and `/login` |

`db.js` unchanged — no migration. `Caddyfile` and `docker-compose.yml` unchanged (verified above).

## Testing Strategy

Strict TDD (`strict_tdd: true`), `node --test`, one test file per module — matching the existing
`test/*.test.js` granularity and the `openDb(':memory:')` + `server.listen(0)` + `fetch` harness.

| File | Layer | Key RED tests |
|---|---|---|
| `test/csrf.test.js` | Unit | round-trip; tampered payload; tampered sig; wrong `uid`; missing `.`; non-JSON payload; expired (`iat` older than max age); future-dated beyond skew; derived secret ≠ session secret (a session cookie must not verify as a CSRF token, and vice versa); `isAcceptableOrigin` matrix (match / mismatch / literal `null` / Referer-only / unparseable Referer / absent × strict, non-strict) |
| `test/mcp-registry.test.js` | Unit | shape per entry; frozen; every `^  mcp-*` compose service has an entry; atlassian is the only `perUserCredentials: true` |
| `test/credential-status.test.js` | Unit | not-enrolled shape; enrolled shape; **no key holds the ciphertext or plaintext**; `configured` true/false from env; env value never appears in output |
| `test/html.test.js` | Unit | `& < > " '` escaped; `null`/`undefined` ⇒ `''`; a `<script>`-bearing `cloudId` renders inert |
| `test/panel.test.js` | Integration | `200` + `text/html`; unauth+HTML ⇒ `302 /login?next=%2Fcredentials`; unauth JSON ⇒ `401`; renders all three MCPs; shared rows have no `<form>`; **body contains no `<script`**; CSP + `Cache-Control: no-store` headers present; hidden `csrf` field verifies for the caller's `uid`; malicious `cloudId` escaped; unknown `?error=` renders no banner |
| `test/login.test.js` (extend) | Integration | `GET /login` ⇒ `200` form; CSP + `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` headers present; `next` preserved + escaped; `sanitizeNext` rejects `//evil.com`, `/\evil.com`, `https://evil`, empty ⇒ `/credentials`; form POST success ⇒ `302 <next>` + `Set-Cookie`; form POST failure ⇒ `401 text/html` with generic error, username preserved, no password echo; JSON POST behavior unchanged; cross-site `Origin` ⇒ `403`; absent `Origin` still `200` (CLI) |
| `test/csrf-enforcement.test.js` | Integration | cookie write, no token ⇒ `403 csrf_token_invalid`; forged token ⇒ `403`; **another user's valid token ⇒ `403`**; valid ⇒ `200`; Bearer with no token ⇒ `200`; **garbage Bearer + valid cookie ⇒ still `403`** (D2 bypass); cookie `DELETE` via `X-CSRF-Token`; cross-site Origin on a cookie write ⇒ `403 csrf_origin_rejected`; absent Origin on a cookie write ⇒ `403 csrf_origin_rejected` |
| `test/verify.test.js` (extend) | Integration | `enrollUrl` is `https://auth.{domain}/credentials` |

## Threat Matrix

The design changes **routing**. Template rows are VCS/shell-oriented and are `N/A`; a routing
supplement follows, as the template has no routing row.

| Boundary | Applicability | Design response |
|---|---|---|
| Documentation-like paths | **N/A** — no file classification or execution; no file is read as code | — |
| Git repository selection | **N/A** — no VCS interaction at runtime | — |
| Commit state | **N/A** — no VCS interaction | — |
| Push state | **N/A** — no VCS interaction | — |
| PR commands | **N/A** — no subprocess or PR automation; zero `child_process` use | — |

### Routing supplement (all Applicable)

| # | Adversarial case | Design response | Planned RED test |
|---|---|---|---|
| R1 | Open redirect via `?next=//evil.com`, `/\evil.com`, `https://evil` | `sanitizeNext` — single leading `/`, not `//`, not `/\`; else `/credentials` | `login.test.js` |
| R2 | Cross-site form POST to a cookie-authed write | `isAcceptableOrigin(strict)` + HMAC token bound to `uid` | `csrf-enforcement.test.js` |
| R3 | Spoofed `Host` header to satisfy the origin check | Expected origin composed from `config.domain`, never `req.headers.host` (D7) | `csrf.test.js` + integration with a forged `Host` |
| R4 | Bearer/cookie confusion to skip CSRF | `authenticateWithMethod` reports the mechanism that actually succeeded (D2) | garbage-Bearer + valid-cookie test |
| R5 | Cross-site login CSRF via `enctype="text/plain"` JSON-shaped body | Origin mismatch ⇒ `403` on `POST /login` (D5) | `login.test.js` |
| R6 | Stored XSS via `cloudId` (attacker-written, panel-rendered) | `escapeHtml` on every interpolation + CSP `default-src 'none'` | `html.test.js`, `panel.test.js` |
| R7 | Reflected XSS via `/credentials?error=<payload>` | Frozen `PANEL_ERRORS` allow-list; raw value never echoed | `panel.test.js` |
| R8 | Credential material leaking into a response | Explicit column list, never `SELECT *`; allow-list projection | `credential-status.test.js`, `panel.test.js` |
| R9 | CSRF token replayed as a session cookie (or vice versa) | Domain-separated key derivation, `CSRF_DOMAIN` | `csrf.test.js` |
| R10 | Clickjacked "Remove credential" button | `frame-ancestors 'none'` | `panel.test.js` header assertion |

## Migration / Rollout

No migration — no schema change, no new persisted data, no Caddyfile or compose change. Purely
additive routes. `git revert` + image rebuild restores the prior state; existing
`atlassian_credentials` rows and all Bearer clients are unaffected.

Delivery slices (400-line guard): **(1)** `session.js` exports + `csrf.js` + `mcp-registry.js` +
`credential-status.js` + `GET /me/credentials` + CSRF enforcement on the existing write;
**(2)** `html.js` + `panel.js` + `login-page.js` + `GET /login` + `GET /credentials` +
`POST /me/atlassian/delete` + `enrollUrl` repoint + README.

## Open Questions

- [ ] `POST /me/atlassian` form path returns `302 /credentials?error=invalid` on validation
      failure rather than re-rendering with the submitted values. Acceptable (the token field
      must never be re-echoed anyway), but it loses the `scheme`/`cloudId` the user typed.
- [ ] `deriveCsrfSecret` runs an HMAC on every issue and verify. Negligible at this traffic,
      and caching it would defeat `getSessionSecret()`'s deliberate no-cache rotation property.
      Confirming we accept the cost, not the cache.
