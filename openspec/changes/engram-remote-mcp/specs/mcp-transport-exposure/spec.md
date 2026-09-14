# MCP Transport Exposure Specification (engram delta)

## Purpose

`openspec/specs/` is empty (`gateway-foundation` unarchived), so this is
written directly rather than as a formal ADDED/MODIFIED delta against a
baseline — same precedent as `credential-admin-panel`. This supersedes only
`gateway-foundation`'s "engram exposed via supergateway" requirement; the
`context7` and `mcp-atlassian` requirements from that spec are unaffected
and unrepeated here.

## Requirements

### Requirement: engram exposed via the per-identity process bridge

The system MUST expose the `engram` MCP server over streamable HTTP through
`engram-identity-routing` + `engram-process-bridge`, not through one shared,
single-project `supergateway`-wrapped process. The previous single-process
`mcp-engram-tool` service is retired by this change.

#### Scenario: engram responds over streamable HTTP, isolated per identity

- GIVEN the new router service running in front of per-identity
  `supergateway`-wrapped `engram mcp` children
- WHEN an authenticated MCP client sends `initialize` through `/mcp/engram`
- THEN the client receives a valid MCP `initialize` response
- AND the session it establishes is scoped to that client's own identity's
  project, per `engram-identity-routing`

#### Scenario: Unauthenticated request never reaches a child process

- GIVEN no valid gateway credential is presented
- WHEN a request hits `/mcp/engram*`
- THEN Caddy's `forward_auth` rejects it before the router is reached
- AND no `engram mcp` child process is spawned or touched
