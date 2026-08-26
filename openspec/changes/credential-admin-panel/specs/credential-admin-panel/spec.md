# Credential Admin Panel Specification

## Purpose

One page per user to manage their own MCP credentials: a no-JS login entry
point, a capability-honest registry, and CSRF-protected cookie writes.
`openspec/specs/` is empty (`gateway-auth` unarchived), so CSRF/auth-method
requirements live here instead of a delta.

## Requirements

### Requirement: GET /login Browser Entry Point

The system MUST serve `GET /login` unauthenticated as a zero-JavaScript HTML
form (`username`, `password`, hidden `next`, `POST /login`, no `<script>`).
`next` MUST be sanitized: only a value starting with a single `/`, not `//`
and not `/\`, else default `/credentials`.

#### Scenario: Login page renders with no script
- GIVEN no session cookie
- WHEN `GET /login?next=%2Fcredentials` is sent
- THEN response is `200 text/html` with login inputs and no `<script>` tag

#### Scenario: Unsafe next value is neutralized
- GIVEN `next=//evil.example`, `/\evil.example`, or `https://evil.example`
- WHEN `GET /login` renders
- THEN the hidden `next` field value is `/credentials`

### Requirement: POST /login Origin Check Prevents Login CSRF

Because `readJsonBody` ignores `Content-Type`, a cross-site `text/plain`
form can log a victim into the attacker's account. The system MUST reject
`POST /login` with `403 {"error":"csrf_origin_rejected"}` when
`Origin`/`Referer` is present and mismatches `https://{config.domain}`, and
MUST allow the request when both are absent (CLI/curl unaffected).

#### Scenario: Cross-site login attempt rejected
- GIVEN `POST /login` carrying `Origin: https://evil.example`
- WHEN processed
- THEN response is `403 {"error":"csrf_origin_rejected"}` and no cookie is set

#### Scenario: CLI login without Origin still succeeds
- GIVEN valid credentials, no `Origin`/`Referer`
- WHEN `POST /login` is sent as JSON
- THEN response is `200` with `Set-Cookie`, unchanged from today

### Requirement: GET /credentials HTML Panel Access Control

`GET /credentials` MUST require authentication (Bearer or cookie). An
unauthenticated `Accept: text/html` request MUST redirect to
`/login?next=%2Fcredentials`; other unauthenticated requests get `401`. An
authenticated response MUST embed a CSRF token per per-user-credential MCP.

#### Scenario: Unauthenticated request redirects to login
- GIVEN no valid Bearer token or session cookie
- WHEN `GET /credentials` is sent with `Accept: text/html`
- THEN response is `302 Location: /login?next=%2Fcredentials`

#### Scenario: Authenticated user loads the panel
- GIVEN a valid session cookie
- WHEN `GET /credentials` is sent
- THEN response is `200 text/html` with a CSRF hidden field for the atlassian entry

### Requirement: Strict Security Headers on Rendered HTML

`GET /login` and `GET /credentials` responses MUST carry exactly
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
`Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

#### Scenario: Panel headers present, no script in body
- GIVEN an authenticated session
- WHEN `GET /credentials` is fetched
- THEN all three headers match exactly and the body contains no `<script`

#### Scenario: Login page headers present, no script in body
- GIVEN no session cookie
- WHEN `GET /login` is fetched
- THEN all three headers match exactly and the body contains no `<script`

### Requirement: GET /me/credentials Status Projection

For an authenticated caller, the system MUST return one entry per registry
MCP: `{id, label, perUserCredentials:true, enrolled, scheme, cloudId, updatedAt}`
for per-user MCPs, or `{id, label, perUserCredentials:false, configured, note}`
for shared ones, where `configured` derives only from env presence.

#### Scenario: Mixed enrolled and shared status
- GIVEN `alice` has an `atlassian_credentials` row and `CONTEXT7_API_KEY` is set
- WHEN `GET /me/credentials` is sent with a valid session cookie
- THEN `atlassian.enrolled` is `true` and `context7.configured` is `true`

#### Scenario: Unauthenticated request
- GIVEN no valid Bearer token or session cookie
- WHEN `GET /me/credentials` is sent
- THEN response is `401 {"error":"unauthenticated"}`

### Requirement: Capability Registry Completeness

The system MUST declare every MCP service in `docker-compose.yml` as one
frozen registry entry: `perUserCredentials:true` for `atlassian`, or
`perUserCredentials:false` with `sharedSecretEnv`/`note` for `context7` and
`engram`.

#### Scenario: Registry covers every compose MCP
- GIVEN the MCP service names in `docker-compose.yml`
- WHEN the registry module is enumerated
- THEN every compose MCP id has exactly one matching registry entry

### Requirement: Credential Write and Delete Routes Are User-Scoped

`POST /me/atlassian` MUST accept `application/json` and
`application/x-www-form-urlencoded`. `POST /me/atlassian/delete`
(form-only) and `DELETE /me/atlassian` (JSON) MUST both delete only the row
where `user_id` equals the authenticated caller's id.

#### Scenario: Form submission creates a credential
- GIVEN a valid session cookie and CSRF token
- WHEN `POST /me/atlassian` is sent form-encoded
- THEN response is `302 Location: /credentials`

#### Scenario: Delete never affects another user's row
- GIVEN `bob` has a row and `alice` does not
- WHEN `alice` sends `POST /me/atlassian/delete` with valid credentials and CSRF token
- THEN response is `302 Location: /credentials` and `bob`'s row is unchanged

### Requirement: CSRF Protection on Cookie-Authenticated Writes

The system MUST issue a stateless HMAC token bound to `uid` when rendering
`GET /credentials`, and verify it on `POST /me/atlassian`,
`POST /me/atlassian/delete`, and `DELETE /me/atlassian` whenever the request
authenticated via cookie, rejecting missing/forged/wrong-`uid`/expired
(>43200s+60s skew) tokens with `403 {"error":"csrf_token_invalid"}`. Auth
method MUST come from `authenticateWithMethod()`, not header sniffing: a
garbage `Authorization: Bearer` header plus a valid cookie MUST still
authenticate as `cookie` and require a valid CSRF token. Bearer requests
MUST NOT require one.

Before the CSRF token is checked, a cookie-authenticated write MUST also
reject a mismatched OR absent `Origin`/`Referer` (`isAcceptableOrigin`'s
strict mode: unlike `POST /login`, an absent header is not given the benefit
of the doubt here) with `403 {"error":"csrf_origin_rejected"}`, as
defense-in-depth alongside the token.

#### Scenario: Missing, forged, or bypass-attempt tokens rejected
- GIVEN a valid session cookie and EITHER a tampered/absent `X-CSRF-Token`
  OR a garbage `Authorization: Bearer` header with no CSRF token
- WHEN `DELETE /me/atlassian` is sent
- THEN `authenticateWithMethod()` reports `cookie` and response is `403 {"error":"csrf_token_invalid"}`

#### Scenario: Cross-site or absent Origin on a cookie write rejected
- GIVEN a valid session cookie and a valid CSRF token, but `Origin` set to
  `https://evil.example` (or `Origin`/`Referer` both absent)
- WHEN `POST /me/atlassian` is sent
- THEN response is `403 {"error":"csrf_origin_rejected"}`

#### Scenario: Bearer write requires no CSRF token
- GIVEN a valid Bearer token, no cookie, no CSRF token
- WHEN `POST /me/atlassian` is sent with a valid JSON body
- THEN response is `200 {"ok":true}`

### Requirement: Credential Material Never Disclosed

No response body from any auth-gateway route MUST ever contain
`atlassian_credentials.ciphertext`, the decrypted plaintext token, or any
`sharedSecretEnv` value.

#### Scenario: Panel and status routes never echo secrets
- GIVEN known plaintext, ciphertext, and `CONTEXT7_API_KEY` values in the fixture
- WHEN all credential-panel route responses are inspected
- THEN none of the three secret values appear anywhere

### Requirement: enrollUrl Points to the Credential Panel

`decideVerify()`'s `403 no_atlassian_credential` body MUST set `enrollUrl`
to `https://auth.{domain}/credentials`.

#### Scenario: Unenrolled user hits an Atlassian route
- GIVEN an authenticated user with no `atlassian_credentials` row
- WHEN `GET /verify` is called with `X-Forwarded-Uri: /mcp/atlassian/...`
- THEN response is `403 {"error":"no_atlassian_credential","enrollUrl":"https://auth.{domain}/credentials"}`
