# Gateway Auth Specification

## Purpose

Single-perimeter authentication for the gateway: one long-lived credential per
person, issued and validated by `auth-gateway`, consumed by Caddy via
`forward_auth`.

## Requirements

### Requirement: Multi-user credential store

The system MUST store one credential per person (not a shared team token),
keyed by user identity, so revocation is scoped to an individual.

#### Scenario: Two users hold independent tokens

- GIVEN two registered users, Alice and Bob
- WHEN each completes login and receives a token
- THEN Alice's token and Bob's token are distinct records
- AND revoking Alice's token does not affect Bob's access

### Requirement: Long-lived tokens without automatic expiry

The system MUST issue tokens that remain valid indefinitely until an admin
manually revokes them. The system MUST NOT apply automatic time-based
expiry to issued tokens in this slice.

#### Scenario: Token remains valid after extended time

- GIVEN a token issued 90 days ago that has not been revoked
- WHEN it is presented to `/verify`
- THEN the system returns a successful authentication result

#### Scenario: Admin revokes a token

- GIVEN an admin revokes a specific user's token
- WHEN that token is presented afterward
- THEN the system rejects it as invalid

### Requirement: Bearer or HttpOnly-cookie validation

The system MUST accept either an `Authorization: Bearer <token>` header or a
valid HttpOnly session cookie as proof of authentication, and MUST treat
either form as equally sufficient.

#### Scenario: Bearer token accepted

- GIVEN a valid issued token
- WHEN a request presents it as `Authorization: Bearer <token>`
- THEN the system authenticates the request

#### Scenario: HttpOnly cookie accepted

- GIVEN a valid session established via login
- WHEN a browser request presents the HttpOnly cookie
- THEN the system authenticates the request

#### Scenario: Neither credential present

- GIVEN a request with no Bearer header and no valid cookie
- WHEN it reaches `/verify`
- THEN the system rejects it with an unauthenticated response

### Requirement: GET /verify endpoint contract

The system MUST expose `GET /verify` as the `forward_auth` target: it MUST
return a success status (allowing Caddy to proceed) when credentials are
valid, and a failure status (blocking the request) when they are not.

#### Scenario: Verify succeeds for authenticated request

- GIVEN a valid Bearer token or cookie on the incoming request
- WHEN Caddy calls `GET /verify` via `forward_auth`
- THEN `/verify` responds with a success status
- AND Caddy forwards the original request upstream

#### Scenario: Verify fails for unauthenticated request

- GIVEN no valid credential on the incoming request
- WHEN Caddy calls `GET /verify`
- THEN `/verify` responds with a failure status
- AND Caddy blocks the request from reaching upstream
