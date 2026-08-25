# Reverse Proxy Routing Specification

## Purpose

Caddy-based routing on `{$DOMAIN}` subdomains with TLS and a single
`forward_auth` gate protecting every route except the auth service's own
public entry points.

## Requirements

### Requirement: Subdomain-based routing on {$DOMAIN}

The system MUST route each backend service on its own subdomain of
`{$DOMAIN}` (e.g. `auth.{$DOMAIN}`, `engram.{$DOMAIN}`, MCP subdomains),
terminating TLS at the proxy.

#### Scenario: Request routed to correct upstream

- GIVEN Caddy configured with routes for `auth.{$DOMAIN}` and
  `engram.{$DOMAIN}`
- WHEN a TLS request arrives for `engram.{$DOMAIN}`
- THEN Caddy forwards it to the `engram-cloud` upstream, not `auth-gateway`

### Requirement: forward_auth gates every route except auth login/verify

The system MUST apply `forward_auth` to every configured route, with the
sole exceptions of `auth.{$DOMAIN}/login` and `auth.{$DOMAIN}/verify`, which
MUST remain reachable without prior authentication.

#### Scenario: Unauthenticated request to a gated route is blocked

- GIVEN no valid credential on the request
- WHEN a request arrives for any route other than `/login` or `/verify` on
  `auth.{$DOMAIN}`
- THEN Caddy blocks the request via `forward_auth` before reaching upstream

#### Scenario: Login route reachable without prior auth

- GIVEN no valid credential on the request
- WHEN a request arrives for `auth.{$DOMAIN}/login`
- THEN Caddy forwards it to `auth-gateway` without invoking `forward_auth`

### Requirement: engram.{$DOMAIN} is gated by forward_auth

The system MUST apply `forward_auth` to `engram.{$DOMAIN}` in addition to
engram-cloud's own native authentication; the gateway perimeter check is not
optional or bypassable for this route.

#### Scenario: Unauthenticated request to engram is blocked at the proxy

- GIVEN no valid gateway credential on the request
- WHEN a request arrives for `engram.{$DOMAIN}`
- THEN Caddy blocks it via `forward_auth` before it reaches `engram-cloud`

#### Scenario: Authenticated request reaches engram-cloud

- GIVEN a valid gateway credential on the request
- WHEN a request arrives for `engram.{$DOMAIN}`
- THEN Caddy forwards it to `engram-cloud`, which applies its own auth
