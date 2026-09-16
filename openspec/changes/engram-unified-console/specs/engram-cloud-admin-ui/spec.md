# Engram Cloud Admin UI Specification

## Purpose

Let an admin manage Engram Cloud's users, project grants, and tokens from
engram-monitor's own UI, without the browser ever holding the real Engram
Cloud managed-admin token.

## Requirements

### Requirement: The Engram Cloud managed-admin token is held only server-side

auth-gateway MUST hold the real Engram Cloud managed-admin token
(`ENGRAM_CLOUD_ADMIN_TOKEN`, a new env var) and use it only in its own
outbound requests to Engram Cloud's `/admin/*` API. It MUST NOT be returned
in any response body, header, cookie, or log line reachable by the browser.

#### Scenario: The token never reaches a browser-visible surface

- GIVEN an admin uses the Engram Cloud user-management UI
- WHEN any request/response in that flow is inspected
- THEN `ENGRAM_CLOUD_ADMIN_TOKEN`'s value never appears in it

### Requirement: New admin-gated proxy routes mirror Engram Cloud's admin API

auth-gateway MUST expose `GET/POST /admin/engram-cloud/users`,
`POST /admin/engram-cloud/users/:id/grants`, and
`POST /admin/engram-cloud/users/:id/tokens`, each gated by the same admin
session as every other `/admin/*` route, forwarding to the corresponding
real Engram Cloud endpoint using the server-held token.

#### Scenario: An admin creates a new Engram Cloud user from the UI

- GIVEN a valid admin session
- WHEN the UI submits a new-user form to `POST /admin/engram-cloud/users`
- THEN auth-gateway calls Engram Cloud's real `POST /admin/users` with the
  server-held token and relays the created user back to the UI

#### Scenario: A non-admin or unauthenticated request is rejected before reaching Engram Cloud

- GIVEN no valid admin session
- WHEN a request hits any `/admin/engram-cloud/*` route
- THEN it is rejected the same way every other `/admin/*` route already is
- AND no outbound call to Engram Cloud is made

### Requirement: engram-monitor's UI lists, grants, and issues tokens through the proxy

engram-monitor MUST gain pages (using its existing component library) to:
list Engram Cloud users, grant/revoke a project for a user, and issue a
token for a user — each calling the corresponding proxy route above, never
Engram Cloud directly.

#### Scenario: A newly-issued token is shown exactly once

- GIVEN an admin issues a token for a user via the UI
- WHEN the proxy route's response includes the raw token
- THEN the UI displays it once, with the same "copy it now" treatment
  Engram Cloud's own CLI/dashboard already uses for this — never persisted
  client-side beyond that single display
