# Engram Process Bridge Specification

## Purpose

Bridge each identity's MCP Streamable HTTP session to its own
`supergateway`-wrapped `engram mcp` child process, with cloud autosync
correctly scoped to this repo's own `engram-cloud` service, and with a hard
stopgap ceiling on concurrently running children.

## Requirements

### Requirement: One supergateway-wrapped engram mcp child per identity

The router MUST spawn a `supergateway --stdio "engram mcp" --outputTransport
streamableHttp` child process per distinct identity (as derived by
`engram-identity-routing`), with `ENGRAM_PROJECT` set to that identity's
project. An identity with an already-running, healthy child MUST reuse it
rather than spawning a duplicate.

#### Scenario: First request for a new identity spawns a child

- GIVEN no child process exists yet for Alice's identity
- WHEN Alice's first MCP request arrives
- THEN a new `engram mcp` child is spawned with `ENGRAM_PROJECT` set to
  Alice's derived project
- AND the request is proxied to that child once it is ready

#### Scenario: Subsequent requests reuse the existing child

- GIVEN a healthy child process already exists for Alice's identity
- WHEN another request from Alice arrives
- THEN no new child process is spawned
- AND the request is proxied to the existing child

### Requirement: Autosync enabled and scoped to this repo's engram-cloud

Every spawned child MUST be started with `ENGRAM_CLOUD_AUTOSYNC=1`,
`ENGRAM_CLOUD_TOKEN`, and `ENGRAM_CLOUD_SERVER` set so that its writes
replicate to this repo's own `engram-cloud` compose service (internal
address), not the separately-managed host-level Engram Cloud deployment.

#### Scenario: A saved memory appears in Engram Cloud without a manual sync step

- GIVEN Alice's child process is running with autosync configured
- WHEN Alice's session calls `mem_save`
- THEN the observation is written locally immediately
- AND it becomes visible via this repo's `engram-cloud` service shortly
  after, with no manual `engram sync` invocation

### Requirement: A project is enrolled before its first child is spawned

`ENGRAM_CLOUD_AUTOSYNC=1`/`ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_SERVER` alone
are NOT sufficient for autosync to push anything: engram's local SQLite
store requires the project to be explicitly enrolled first (equivalent to
running `engram cloud enroll <project>`), and this enrollment is local
state that env vars cannot substitute for. The bridge MUST run this
enrollment itself, once per project, before spawning that project's first
child — never relying on a human running it out of band, since that would
reintroduce the per-project VPS action this whole change exists to avoid.
If enrollment fails, the bridge MUST NOT spawn a child or occupy a port for
that attempt, and a subsequent request for the same project MUST be able to
retry enrollment cleanly.

#### Scenario: First-ever request for a project enrolls it before spawning

- GIVEN no child has ever been spawned for Bob's project
- WHEN Bob's first request arrives
- THEN the bridge enrolls Bob's project
- AND only after that succeeds does it spawn Bob's child

#### Scenario: A failed enrollment leaves no state for a retry to trip over

- GIVEN enrollment fails (e.g. the cloud server is briefly unreachable)
- WHEN the bridge handles that failure
- THEN no child is spawned and no port/identity map entry is left behind
- AND the next request for that same project can attempt enrollment again

### Requirement: Bounded concurrent process count

The bridge MUST enforce a maximum number of concurrently running `engram
mcp` children. A request that would require spawning a new child beyond
that ceiling MUST fail with an explicit error rather than spawn without
bound. The exact reap/idle-timeout policy for existing children is out of
scope for this requirement (see proposal.md), but the ceiling itself is not
optional.

#### Scenario: Request above the ceiling is rejected explicitly

- GIVEN the configured maximum number of concurrent children is already
  running, all for other identities
- WHEN a request from a not-yet-seen identity arrives
- THEN the router responds with an explicit capacity error
- AND no additional child process is spawned

### Requirement: A freshly-spawned child is not proxied to until it is actually ready

A newly spawned child needs real startup time before it accepts
connections. The bridge MUST wait for the child's port to actually accept a
connection before resolving the request that triggered the spawn, up to a
bounded timeout — proxying to a not-yet-listening port produces a
`bad_gateway` error for what would otherwise be a transient, self-resolving
condition. If the child never becomes ready within the timeout, the bridge
MUST clean up its state (release the port, drop the map entry) so a retry
can attempt a fresh spawn rather than being told a child already exists.

#### Scenario: A slow-starting child does not surface as a proxy error

- GIVEN a freshly spawned child needs a moment before its port accepts
  connections
- WHEN the triggering request would otherwise be proxied immediately
- THEN the bridge waits until the port is actually accepting connections
  before proxying
- AND the caller never sees a `bad_gateway` error caused purely by that
  startup delay

#### Scenario: A child that never becomes ready does not permanently block that identity

- GIVEN a spawned child never starts accepting connections within the
  timeout
- WHEN the wait times out
- THEN the bridge's internal state for that identity is cleaned up
- AND a subsequent request for the same identity can trigger a fresh spawn
  attempt

### Requirement: Dead child detected before or during proxying

IF a child process backing an identity has exited or become unresponsive,
THEN the router MUST detect this rather than proxy indefinitely into a dead
connection, and MUST respawn a replacement child for that identity's next
request.

#### Scenario: Crashed child is replaced, not silently hung

- GIVEN a child process for Bob's identity has crashed
- WHEN Bob sends another request
- THEN the router detects the dead child
- AND a new child is spawned for Bob rather than the request hanging or
  silently failing against the dead process
