# Engram Identity Routing Specification

## Purpose

Derive the Engram Cloud project for a remote MCP session strictly from the
gateway's own verified identity — never from anything the client sends —
so one authenticated user can never read or write another user's memories
through the shared `/mcp/engram*` endpoint.

## Requirements

### Requirement: Project name derived exclusively from verified identity

The router MUST derive the Engram project name only from the `X-Gateway-User`
header as set by auth-gateway's `/verify` response (never absent on a
successful `forward_auth` check). The router MUST NOT read a project name
from the request URL path, query string, request body, or any other
client-supplied header.

#### Scenario: Two users get isolated projects

- GIVEN Alice and Bob each have valid gateway accounts
- WHEN each sends an MCP `initialize` through `/mcp/engram`
- THEN Alice's session is bound to a project derived from her identity
- AND Bob's session is bound to a project derived from his identity
- AND neither session's `mem_search` results include the other's memories

#### Scenario: A client-supplied project hint is ignored

- GIVEN a request carries an attacker-chosen `X-Engram-Project: someone-elses-project`
  header or a `/mcp/engram/someone-elses-project` path
- WHEN the router processes the request
- THEN the resulting project is still derived only from the request's own
  verified `X-Gateway-User`, not from that header or path segment

### Requirement: An optional client-supplied sub-project always stays namespaced under the identity

The router MAY accept an `X-Engram-Subproject` header to let one gateway
user separate memories per local repo (a remote HTTP MCP session has no
other way to know which repo the caller is in — there is no channel for a
client's local CWD to cross this transport). The final project MUST always
be the verified identity, optionally suffixed with the subproject value
(`<identity>.<subproject>`) — the subproject alone MUST NEVER be usable as
the project, so no value a client sends can ever address another user's
namespace. The join separator MUST be a character engram's own project-name
normalization never collapses (a literal `.` — engram collapses runs of
`-`/`_` but leaves dots untouched) and MUST be reserved exclusively for this
join: neither the identity nor the subproject may themselves contain it, or
the join stops being unambiguous. Separators within a segment MUST NOT
repeat (no `--`/`__`) for the same reason — engram would collapse a repeated
run, which could make a different, genuinely single-separator value collide
with it. An invalid/malformed subproject value MUST fall back to the bare
identity rather than rejecting the request.

#### Scenario: A subproject header separates two repos for the same user

- GIVEN Alice sends `X-Engram-Subproject: repo-a` on one request and
  `X-Engram-Subproject: repo-b` on another
- WHEN both requests carry her own verified identity
- THEN the two requests resolve to two different projects, both namespaced
  under Alice's own identity (e.g. `alice.repo-a` and `alice.repo-b`)

#### Scenario: A subproject value can never stand alone or collide with another user

- GIVEN Alice sends `X-Engram-Subproject: bob` (Bob's own identity)
- WHEN the router resolves her project
- THEN the result is `alice.bob`, never plain `bob` — Bob's own project is
  never reachable through Alice's session no matter what subproject value
  she sends

### Requirement: Missing or malformed identity is treated as unauthenticated

The router MUST NOT trust that Caddy's `forward_auth` is the only thing
standing between it and the network. A request reaching the router without
a well-formed `X-Gateway-User` header MUST be rejected, never routed to a
default or shared project.

#### Scenario: Malformed identity header rejected

- GIVEN a request reaches the router with an empty or missing `X-Gateway-User`
  header (e.g. a misconfigured internal route, or a direct request that
  bypassed Caddy)
- WHEN the router evaluates the request
- THEN it responds with an authentication error
- AND no `engram mcp` child process is spawned or reused for it
