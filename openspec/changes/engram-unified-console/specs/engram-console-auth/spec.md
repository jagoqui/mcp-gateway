# Engram Console Auth Specification

## Purpose

Add the missing admin login page for auth-gateway's already-implemented
admin-session machinery, so it becomes the single credential gating
engram-monitor and the new Engram Cloud admin UI.

## Requirements

### Requirement: GET /admin/login serves a zero-JS login form

The system MUST serve `GET /admin/login` unauthenticated, mirroring the
existing regular-user `GET /login` pattern (`login-page.js`): a plain
`<form method="post">`, no client-side script, `next` param preserved and
sanitized the same way.

#### Scenario: Admin login page renders with no script

- GIVEN no admin session cookie
- WHEN a browser requests `GET /admin/login`
- THEN it receives a 200 HTML form with no `<script>` tag

### Requirement: POST /admin/login authenticates only an is_admin user

`POST /admin/login` MUST verify the submitted username/password against
`users.password_hash`, and MUST reject a valid password belonging to a
non-admin (`is_admin = 0`) user with the same generic failure message
already used by the regular login (never distinguishing "wrong password"
from "not an admin" to an attacker).

#### Scenario: Valid admin credentials issue the admin session cookie

- GIVEN a user row with `is_admin = 1` and a known password
- WHEN `POST /admin/login` submits matching username/password
- THEN the response sets `__Host-admin_session` (via
  `serializeAdminSessionCookie`, already implemented) and redirects to `next`

#### Scenario: Valid credentials for a non-admin user are rejected

- GIVEN a user row with `is_admin = 0` and a known correct password
- WHEN `POST /admin/login` submits that exact username/password
- THEN the response is the same generic failure as a wrong password — no
  admin session cookie is set

### Requirement: An expired or absent admin session redirects to login, not a bare 401

For any admin-gated route reached via a browser (`Accept: text/html`), an
invalid session MUST redirect to `GET /admin/login?next=<original path>`,
matching the existing `GET /admin/verify` behavior already implemented —
this requirement only confirms the new gated routes (Monitor, Engram Cloud
admin proxy) reuse that same decision, not a new one.

#### Scenario: An unauthenticated browser request to a newly-gated route redirects to login

- GIVEN no valid admin session
- WHEN a browser requests `monitor.{$DOMAIN}` or an Engram-Cloud-admin-proxy
  route
- THEN it is redirected to `admin.{$DOMAIN}/login?next=<that path>`
