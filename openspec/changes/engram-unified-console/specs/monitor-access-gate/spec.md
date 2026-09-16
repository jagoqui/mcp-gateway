# Monitor Access Gate Specification

## Purpose

Replace engram-monitor's current SSH-tunnel-only, zero-auth exposure with a
real domain gated by the same admin session as the rest of the console, now
that both conditions that justified the tunnel-only design (no auth of its
own; its backend API had none either) are addressed by this change.

## Requirements

### Requirement: engram-monitor is reachable at a real domain, admin-gated

The system MUST route `monitor.{$DOMAIN}` through Caddy to engram-monitor,
with `forward_auth` against `GET /admin/verify` — the same mechanism
already gating every other admin-only surface.

#### Scenario: An authenticated admin reaches the dashboard directly

- GIVEN a valid admin session
- WHEN a browser requests `https://monitor.{$DOMAIN}`
- THEN engram-monitor's dashboard loads, no SSH tunnel required

#### Scenario: An unauthenticated request never reaches engram-monitor's container

- GIVEN no valid admin session
- WHEN a request hits `monitor.{$DOMAIN}`
- THEN `forward_auth` rejects it before engram-monitor is reached

### Requirement: engram-monitor leaves network_mode: host

engram-monitor MUST join the shared `gateway` Docker network like every
other proxied service, rather than binding the host's own network
namespace — that mode existed only to reach the bare host's loopback-only
`engram serve`, which this change replaces with the shared, network-native
`engram-serve` bridge service.

#### Scenario: engram-monitor reaches its backend over the Docker network, not the host loopback

- GIVEN the shared `engram-serve` bridge service is running
- WHEN engram-monitor's nginx proxies `/api/*`
- THEN it reaches `engram-serve` by Docker service name, not
  `127.0.0.1:7437`
