# MCP Transport Exposure Specification

## Purpose

Expose each pilot MCP server over streamable HTTP, using the packaging
style native to that server: wrap stdio servers with `supergateway`, use a
native HTTP transport directly when the server provides one.

## Requirements

### Requirement: context7 exposed via supergateway

The system MUST expose `context7` over streamable HTTP by wrapping its
stdio interface with `supergateway`.

#### Scenario: context7 responds over streamable HTTP

- GIVEN the `mcp-context7` service running with `supergateway` wrapping the
  `context7` stdio process
- WHEN an MCP client sends `initialize` over streamable HTTP
- THEN the client receives a valid MCP `initialize` response

### Requirement: engram exposed via supergateway

The system MUST expose the `engram` MCP server over streamable HTTP by
wrapping its stdio interface with `supergateway`.

#### Scenario: engram MCP responds over streamable HTTP

- GIVEN the `mcp-engram-tool` service running with `supergateway` wrapping
  the `engram` stdio process
- WHEN an MCP client sends `initialize` over streamable HTTP
- THEN the client receives a valid MCP `initialize` response

### Requirement: mcp-atlassian exposed via native streamable-HTTP transport

The system MUST expose `mcp-atlassian` using its own native
`--transport streamable-http` flag, without a `supergateway` or other stdio
wrapper.

#### Scenario: mcp-atlassian responds over its native transport

- GIVEN the `mcp-atlassian` service started with `--transport streamable-http`
- WHEN an MCP client sends `initialize` over streamable HTTP
- THEN the client receives a valid MCP `initialize` response

### Requirement: Documented stdio-wrapper fallback for mcp-atlassian

IF upstream issue `sooperset/mcp-atlassian#507` blocks the native
streamable-HTTP transport, THEN the system MUST support falling back to a
`mcp-proxy`-wrapped stdio deployment for `mcp-atlassian` as a documented
alternative.

#### Scenario: Native transport blocked by upstream bug

- GIVEN `mcp-atlassian`'s native streamable-HTTP transport fails due to
  issue #507
- WHEN the fallback is applied
- THEN `mcp-atlassian` runs in stdio mode wrapped by `mcp-proxy`
- AND it remains reachable over streamable HTTP through that wrapper

### Requirement: Per-user Atlassian credentials reach mcp-atlassian per request

The system MUST support per-user Atlassian credentials (not a shared
service account) reaching the `mcp-atlassian` container on a per-request
basis, so each gateway user's own Atlassian permissions apply to their
requests.

The exact injection mechanism (e.g. `forward_auth` `copy_headers` forwarding
a stored per-user credential, vs. the MCP client supplying it directly) is
NOT specified here and is pending `sdd-design`.

#### Scenario: Two users get their own Atlassian identity

- GIVEN Alice and Bob each have distinct Atlassian credentials known to the
  gateway
- WHEN each sends a request through `mcp-atlassian`
- THEN Alice's request is authorized against Alice's Atlassian account
- AND Bob's request is authorized against Bob's Atlassian account,
  independent of the injection mechanism chosen at design time
