# Tasks: Credential Admin Panel

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1,750 total (5 slices, ~305–405 each) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2 → PR3 → PR4 → PR5 (5 units, not the design's 2) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

**Design vs. actual**: the design's proposal/design docs estimated 2 slices. Sizing each
new/modified file plus its test file (per the testing-strategy table) puts slice 1 alone
(`session.js`+`csrf.js`+`mcp-registry.js`+`credential-status.js`+`GET /me/credentials`+CSRF
enforcement) at ~950 lines and slice 2 at ~800 — both already over budget. Re-split into 5
independently shippable units below; unit 4 is borderline (~405) and may need a further split
if actual diffs run larger than estimated.

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | `session.js` exports + `csrf.js` (~305 lines) | PR 1 | `node --test test/session.test.js test/csrf.test.js` | N/A — pure unit tests, no HTTP server | Revert `csrf.js`, `test/csrf.test.js`, `test/session.test.js`, session.js export diff; nothing else depends on them yet |
| 2 | Registry + status projection + `GET /me/credentials` (~335) | PR 2 | `node --test test/mcp-registry.test.js test/credential-status.test.js test/enrollment.test.js` | in-process `server.listen(0)` + `fetch('/me/credentials')` (existing harness) | Revert the two new src files, their tests, and the single new `app.js` branch |
| 3 | CSRF guard on existing `POST /me/atlassian` + new `DELETE /me/atlassian` (~338); needs PR1 | PR 3 | `node --test test/verify.test.js test/csrf-enforcement.test.js` | in-process server + `fetch` with cookie/bearer/forged headers | Revert `authenticateWithMethod`, the guard wiring on `POST /me/atlassian`, the new `DELETE /me/atlassian` branch entirely, and `csrf-enforcement.test.js` |
| 4 | Login page: `html.js` + `login-page.js` + `GET`/`POST /login` (~405); needs PR1 | PR 4 | `node --test test/html.test.js test/login.test.js` | in-process server + `fetch` for `GET`/`POST /login` | Revert `html.js`, `login-page.js`, their tests, and the two `/login` app.js branches |
| 5 | Panel + delete route + `enrollUrl` + docs (~385); needs PR1-4 | PR 5 | `node --test test/panel.test.js test/verify.test.js` | in-process server + `fetch` for `GET /credentials`, `POST /me/atlassian/delete` | Revert `panel.js`, its test, the three new app.js branches, enrollUrl line, README section |

## Phase 1: Shared Crypto Primitives (Unit 1, PR 1)

- [x] 1.1 RED `test/session.test.js`: `sign()`/`timingSafeCompare()` exported, correct HMAC/compare behavior (D1).
- [x] 1.2 GREEN: export `sign(payload, secret)`; extract+export `timingSafeCompare(a,b)` in `src/session.js`; use it in `verifySessionToken`.
- [x] 1.3 REFACTOR: confirm `login.test.js`/`enrollment.test.js` stay green after extraction.
- [x] 1.4 RED `test/csrf.test.js`: round-trip; tampered payload; tampered sig; wrong `uid`; missing `.`; non-JSON payload; expired; future-dated beyond skew; domain-separated secret (R9); `isAcceptableOrigin` matrix — match/mismatch/literal `null`/referer-only/unparseable referer/absent×strict/non-strict (R3).
- [x] 1.5 GREEN: implement `deriveCsrfSecret`, `issueCsrfToken`, `verifyCsrfToken` (7-step algorithm, D7 origin from `config.domain`), `isAcceptableOrigin` in `src/csrf.js`.
- [x] 1.6 REFACTOR: extract shared token-split/decode helper if duplicated across functions.

## Phase 2: Registry, Status Projection, GET /me/credentials (Unit 2, PR 2)

- [x] 2.1 RED `test/mcp-registry.test.js`: shape per entry; frozen; every compose `mcp-*` service has an entry; atlassian is the only `perUserCredentials:true`.
- [x] 2.2 GREEN: `src/mcp-registry.js` — frozen `MCP_REGISTRY` + `getMcp(id)`.
- [x] 2.3 RED `test/credential-status.test.js`: not-enrolled shape; enrolled shape; no ciphertext/plaintext key present (R8); `configured` true/false; env value never in output.
- [x] 2.4 GREEN: `src/credential-status.js` — `buildCredentialStatus(db,user,env)`, explicit column `SELECT`, never `SELECT *`.
- [x] 2.5 RED `test/enrollment.test.js` (extend): `GET /me/credentials` mixed enrolled+shared status; unauthenticated → `401`.
- [x] 2.6 GREEN: `src/app.js` — add `GET /me/credentials` branch calling `buildCredentialStatus`.

## Phase 3: CSRF Enforcement on POST /me/atlassian + New DELETE /me/atlassian (Unit 3, PR 3)

`POST /me/atlassian` is the one existing write route (pre-dates this change) and gains the
guard. `DELETE /me/atlassian` does not exist yet — per `proposal.md`'s In Scope list, it is
created in this unit already wrapped by the guard (there is no unguarded intermediate state).

- [x] 3.1 RED `test/verify.test.js` (extend): `authenticateWithMethod` returns `'bearer'|'cookie'`; garbage Bearer + valid cookie ⇒ `'cookie'` (D2/R4); no match ⇒ `null`.
- [x] 3.2 GREEN: `src/verify.js` — add `authenticateWithMethod(db,headers,secret)`; `authenticate()` stays a thin wrapper.
- [x] 3.3 RED `test/csrf-enforcement.test.js`: cookie write no token→403 `csrf_token_invalid`; forged token→403; another user's valid token→403; valid→200; Bearer no token→200; garbage Bearer+valid cookie→403 (R4); cookie `DELETE` via `X-CSRF-Token`; cross-site Origin→403 `csrf_origin_rejected` (R2); absent Origin→403 `csrf_origin_rejected`.
- [x] 3.4 GREEN: `src/app.js` — `readBody()` (form/JSON dual parse, 64 KiB cap kept); apply the 5-step cookie-write guard to the existing `POST /me/atlassian` branch; add the new `DELETE /me/atlassian` branch with the same guard from creation.
- [x] 3.5 REFACTOR: extract the guard steps into one shared function reused by both branches.

## Phase 4: Login Page (Unit 4, PR 4)

- [ ] 4.1 RED `test/html.test.js`: `escapeHtml` neutralizes `& < > " '`; `null`/`undefined`→`''`; `<script>`-bearing value renders inert (R6).
- [ ] 4.2 GREEN: `src/html.js` — `escapeHtml`, `renderDocument`, `PAGE_HEADERS` (CSP + `no-store` + `nosniff`, R10).
- [ ] 4.3 RED `test/login.test.js` (extend): `GET /login`→200 form, no `<script>`, CSP+`no-store`+`nosniff` headers present; `next` preserved+escaped; `sanitizeNext` rejects `//evil`, `/\evil`, `https://evil`→`/credentials` (R1); form POST success→302+`Set-Cookie` (fresh, no fixation); form POST failure→401 html, generic error, username preserved, password not echoed; JSON POST behavior unchanged; cross-site Origin→403 (R5); absent Origin→200 (CLI).
- [ ] 4.4 GREEN: `src/login-page.js` — `renderLoginPage`, `sanitizeNext`; wire `GET /login` + `POST /login` (Origin reject-on-mismatch/allow-on-absent, D5) in `src/app.js`.

## Phase 5: Credentials Panel, Route Wiring, Docs (Unit 5, PR 5)

- [ ] 5.1 RED `test/panel.test.js`: 200+`text/html`; unauth+html→302 `/login?next=%2Fcredentials`; unauth JSON→401; all 3 MCPs render; shared rows have no `<form>`; body has no `<script`; CSP+`no-store` headers present; hidden `csrf` field verifies for caller `uid`; malicious `cloudId` escaped (R6); unknown `?error=`→no banner (R7).
- [ ] 5.2 GREEN: `src/panel.js` — `renderPanel`, frozen `PANEL_ERRORS` allow-list; wire `GET /credentials` in `src/app.js` (redirect-on-unauth-html, 401 JSON otherwise).
- [ ] 5.3 RED (extend `test/panel.test.js`/`csrf-enforcement.test.js`): form `POST /me/atlassian`→302 `/credentials`; `POST /me/atlassian/delete`→302, only caller's row deleted.
- [ ] 5.4 GREEN: `src/app.js` — add `POST /me/atlassian/delete` branch; make `POST /me/atlassian` response-mode-aware (`isForm`→302, else JSON).
- [ ] 5.5 RED `test/verify.test.js` (extend): `enrollUrl` is `https://auth.{domain}/credentials`.
- [ ] 5.6 GREEN: `src/verify.js` — repoint `enrollUrl`.
- [ ] 5.7 Update `README.md`: document `/login` and `/credentials`.
