# Proposal: Engram Remote MCP

## Intent

Using Engram from a new machine requires installing the `engram` binary locally, and "current project" is auto-detected from the local CWD. Let any authenticated gateway user add one zero-install MCP entry —
`{ "engram-remote-mcp": { "url": "https://mcp.jagoqui.tech/mcp/engram", "type": "http" } }` — that talks to a per-user Engram instance running on the VPS, with continuous autosync to Engram Cloud, and with each user's memories isolated into their own project with no per-user VPS-side admin action.

## Scope

### In Scope

- A new small Node service (`services/engram-router/`, name TBD at design) that terminates one MCP Streamable HTTP endpoint per authenticated identity, deriving the project from the trusted `X-Gateway-User` header (never from client-supplied text)
- Per-identity backing process: a `supergateway`-wrapped `engram mcp` child, spawned on demand with `ENGRAM_PROJECT=<identity>`, `ENGRAM_CLOUD_AUTOSYNC=1`, `ENGRAM_CLOUD_TOKEN`, `ENGRAM_CLOUD_SERVER` set for that child only
- Fix `mcp-engram-tool`'s `docker-compose.yml` `environment:` block — replace the non-functional `ENGRAM_API_KEY` with nothing (superseded by the new service; `mcp-engram-tool` as a *shared, single-project* bridge is retired by this change, see below)
- Point autosync at **this repo's own `engram-cloud` service** (internal Docker network address `http://engram-cloud:18080`), not the separately-managed host-level `~/.engram/` stack — see Approach
- Correct `services/auth-gateway/src/mcp-registry.js`'s `engram` entry (currently claims a shared `ENGRAM_API_KEY` credential that does not exist — confirmed dead in both `docker-compose.yml` and this registry)

### Out of Scope

- Process-pool sizing, idle-reap timing, and max-concurrent-process limits — deferred by explicit user decision; this change must not leave the resource-exhaustion risk *unaddressed* (see Risks), but the exact policy is a later change
- Sub-project granularity within one user's namespace (e.g. one project per repo) — this change gives each gateway user exactly one Engram project
- Migrating or dual-writing data already synced to the host-level `~/.engram/` Postgres (the `jagoqui`/`Yenny Fernanda` managed-admin setup done this session) — that deployment is untouched by this change
- A generic "any stdio MCP, dynamically HTTP-exposed" platform — this change is Engram-specific; generalizing the pattern is a later change if it proves out

## Capabilities

### New Capabilities

- `engram-identity-routing`: derive an Engram project deterministically and exclusively from the gateway's own verified identity; reject/never trust a client-supplied project value
- `engram-process-bridge`: spawn, reuse, and eventually reap one `engram mcp` child per identity, each with its own cloud-sync credential scope

### Modified Capabilities

- `mcp-transport-exposure` (from `gateway-foundation`): `/mcp/engram*`'s backend changes from one static `supergateway`-wrapped process to the new per-identity router
- **Supersedes** `gateway-foundation`'s confirmed decision "Engram Cloud: shared team memory, one project/namespace visible to every token holder — no per-user isolation needed." Re-confirmed with the user this session: isolation is now per-authenticated-identity, not shared. Rationale: the sync credential this change requires (legacy wildcard token, see Approach) has zero per-request access control of its own — a shared namespace with that credential model would mean nothing separates one user's memories from another's at the transport layer, which is unacceptable now that this is reachable by any gateway user, not just trusted operators running local CLI

## Approach

**Reuse `supergateway` per identity instead of reimplementing MCP Streamable HTTP.** The new router does *not* speak the MCP wire protocol itself. On a session's first request it reads `X-Gateway-User` (already guaranteed on every authenticated `/mcp/*` request — verified in `decideVerify()`), and either reverse-proxies to an already-running `supergateway --stdio "engram mcp" --outputTransport streamableHttp` child bound to that identity's ephemeral local port, or spawns one first. All MCP protocol correctness (session IDs, SSE framing, JSON-RPC) stays inside the already-battle-tested `supergateway` (already vendored, pinned at 3.4.3 in this repo's `Dockerfile`) — the new component's job is only identity extraction, process lifecycle, and HTTP reverse-proxying. This is a materially smaller and safer surface than hand-rolling the transport.

**Cloud sync target: this repo's own `engram-cloud` service, not the host's `~/.engram/` stack.** `docker-compose.yml` already runs `engram-cloud` (own Postgres, `ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_ALLOWED_PROJECTS` env vars already scaffolded) on the same `gateway` Docker network as every `mcp-*` service — reachable internally at `http://engram-cloud:18080`, no public hop needed for this traffic. Its own code comment ("runs internally for future team-sync use") describes exactly this change. The host-level `~/.engram/` deployment (publicly reachable at `engram-cloud.jagoqui.tech`, used this session to bootstrap the `jagoqui`/`Yenny Fernanda` managed-admin accounts) is a separate, independently-managed instance with its own Postgres and is not touched by this change.

**Sync credential: the legacy `ENGRAM_CLOUD_TOKEN` + `ENGRAM_CLOUD_ALLOWED_PROJECTS=*` model, not a managed principal token.** Confirmed via source: managed tokens are deny-by-default with no wildcard grant — every project needs an explicit admin `--grant-project`, which would recreate exactly the "VPS-side action per new user" this change exists to avoid. Only the legacy env-token model accepts sync pushes for a project name it has never seen before. The router process passes this one legacy token to every spawned `engram mcp` child; per-user isolation is enforced entirely by the router (identity → project derivation), never by Engram Cloud's own authorization, since that authorization is deliberately wide open by design here.

**`mcp-engram-tool` is retired, not kept alongside the router.** Running both the old static single-project bridge and the new per-identity router at `/mcp/engram*` would be an ambiguous, unadvertised second path into the same Engram Cloud data. The Caddy route and compose service are repointed to the new router.

## Affected Areas

| Area | Impact | Description |
|---|---|---|
| `services/engram-router/` (name TBD) | New | Identity extraction, per-identity process lifecycle, HTTP reverse proxy |
| `docker-compose.yml` | Modified | `mcp-engram-tool` retired/repointed to the new service; wire `ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_ALLOWED_PROJECTS=*` for `engram-cloud` |
| `Caddyfile` | Modified | `/mcp/engram*` backend target changes |
| `services/auth-gateway/src/mcp-registry.js` | Modified | Correct the dead `ENGRAM_API_KEY` claim on the `engram` entry |
| `Dockerfile` | Possibly Modified | Only if the new service needs its own image rather than reusing `x-mcp-image` — open question for `sdd-design` |
| `.env.example` | Modified | New/renamed vars for the router's engram-cloud credential |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Unbounded spawned `engram mcp` processes (one per identity, no reap policy yet) exhaust VPS memory/FDs under enough distinct users | Med-High | Out of scope for the *policy*, but this change must ship a hard ceiling (e.g. max concurrent children, reject-with-503 above it) as a stopgap — a full reap/pool design is a follow-up change, not "no limit at all" |
| Legacy wildcard token gives the router (and therefore, indirectly, every authenticated gateway user through it) blanket write access to any Engram Cloud project name on this instance | Med | This is inherent to the "no VPS action per user" requirement, not a bug; mitigated by the fact the router — not the client — is the only thing that ever sets the project name, and it derives it only from server-verified identity |
| `supergateway` child crash mid-session leaves the router proxying to a dead port | Med | Design phase must specify health-check-before-proxy or a fast-fail + respawn behavior |
| `engram mcp`'s project-resolution / autosync env-var contract (verified this session against 2.0.0-rc.11-era source) drifts in a future engram release | Low | Pin `ENGRAM_VERSION` build arg as already done for the existing binary |
| Over 400 changed lines | Med | Likely slices: (1) router service + tests, (2) compose/Caddy/registry wiring |

## Rollback Plan

`mcp-engram-tool`'s compose service and Caddy route are not deleted from history — reverting this change's compose/Caddyfile diff restores the old static single-project bridge immediately. The new router service is additive (new directory); removing it and reverting the two modified files fully restores pre-change behavior. No data migration is introduced (Engram Cloud project rows are created lazily by sync itself, same as today).

## Dependencies

- `engram-cloud`'s own Postgres must be healthy (already a compose `depends_on`)
- `ENGRAM_CLOUD_TOKEN_PEPPER` is deliberately **not** required for this credential path (legacy model only) — do not accidentally couple this change to the managed-token pepper
- Reuses `X-Gateway-User` / auth-gateway's existing `/verify` contract unchanged

## Success Criteria

- [ ] Two different authenticated gateway users, hitting the same public URL with no local `engram` binary, get memories that never appear in each other's Engram Cloud project
- [ ] A `mem_save` through this route is visible via Engram Cloud's own admin/dashboard shortly after, with no manual `engram sync` step
- [ ] An unauthenticated request to `/mcp/engram*` is rejected before ever reaching the router (unchanged `forward_auth` behavior)
- [ ] `mcp-engram-tool`'s dead `ENGRAM_API_KEY` reference no longer exists anywhere in the repo
