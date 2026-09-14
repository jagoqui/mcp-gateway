# Tasks: Engram Remote MCP

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1,180 total (5 slices, ~150–360 each) |
| 400-line budget risk | Med |
| Chained PRs recommended | Yes |
| Suggested split | PR1 → PR2 → PR3 → PR4 → PR5 |
| Delivery strategy | auto-chain |
| Chain strategy | pending |

Decision needed before apply: chain strategy only (delivery strategy already resolved to auto-chain).

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | Identity derivation + validation (~200 lines incl. tests) | PR 1 | `node --test test/identity.test.js` | N/A — pure unit tests | Revert `src/identity.js`, its test; nothing else depends on it yet |
| 2 | Port allocator (~160 lines incl. tests) | PR 2 | `node --test test/port-allocator.test.js` | N/A — pure unit tests | Revert `src/port-allocator.js`, its test |
| 3 | Process manager: spawn/reuse/respawn/ceiling (~360 lines incl. tests); needs PR1+PR2 | PR 3 | `node --test test/process-manager.test.js` | stub/fake child process (no real `engram` binary needed in this unit's tests) | Revert `src/process-manager.js`, its test |
| 4 | Reverse proxy + HTTP server wiring (`app.js`) (~360 lines incl. tests); needs PR1-3 | PR 4 | `node --test test/app.test.js` | in-process `server.listen(0)` + `fetch`, stubbed process manager | Revert `src/app.js`, `bin/*` entrypoint, its test |
| 5 | Dockerfile + compose/Caddyfile cutover + `mcp-registry.js` fix + docs (~100 lines, infra, not unit-tested); needs PR1-4 | PR 5 | Manual E2E smoke (two identities, real `engram mcp`) per design.md's Testing Strategy | `docker compose up`, curl/MCP client smoke script | Revert the compose/Caddyfile diff — restores `mcp-engram-tool` immediately (proposal.md's Rollback Plan) |

## Phase 1: Identity Derivation (Unit 1, PR 1)

- [x] 1.1 RED `test/identity.test.js`: valid `X-Gateway-User` → identity string; missing header → rejected; empty-string header → rejected; header containing path/shell-metacharacter-like content → rejected or safely normalized (never passed through raw); a second, client-supplied identity-like header (e.g. `X-Engram-Project`) has zero effect on the result (spec: `engram-identity-routing`).
- [x] 1.2 GREEN: `src/identity.js` — `deriveIdentity(headers)`, returns a validated project-safe string or `null`.
- [x] 1.3 REFACTOR: single `IDENTITY_PATTERN` constant is the sole validation source; reused as-is (no second copy needed yet — later units call `deriveIdentity`, not the pattern directly).

## Phase 2: Port Allocator (Unit 2, PR 2)

- [x] 2.1 RED `test/port-allocator.test.js`: allocates sequential free ports from the configured range; refuses once the range is exhausted; releasing a port makes it allocatable again; double-release is a no-op, not a crash.
- [x] 2.2 GREEN: `src/port-allocator.js` — `createPortAllocator({base,max})` returning `allocate()`/`release(port)`.

## Phase 3: Process Manager (Unit 3, PR 3, needs PR1+PR2)

- [x] 3.1 RED `test/process-manager.test.js`: first request for a new identity spawns a (stubbed) child with `ENGRAM_PROJECT` set to that identity, plus `ENGRAM_CLOUD_AUTOSYNC=1`/`ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_SERVER` forwarded (spec: `engram-process-bridge`).
- [x] 3.2 RED (extend): a second request for an already-seen, healthy identity reuses the existing child — no second spawn.
- [x] 3.3 RED (extend): a dead/exited child is detected and replaced on the next request for that identity, not proxied into silently.
- [x] 3.4 RED (extend): a request for a not-yet-seen identity once `MAX_ENGRAM_CHILDREN` are already running returns an explicit capacity error; no additional spawn occurs.
- [x] 3.5 GREEN: `src/process-manager.js` — `getOrCreateChild(identity)`; injectable `spawnChild` (default `realSpawnChild`, using `node:child_process.spawn` on `supergateway`), tests use a stub instead.
- [x] 3.6 REFACTOR: single `isHealthy(child)` predicate (checks `exitCode === null`, matching Node's own ChildProcess field) used by both the reuse and respawn paths — no duplicate check.

## Phase 4: Reverse Proxy + HTTP Server (Unit 4, PR 4, needs PR1-3)

- [x] 4.1 RED `test/app.test.js`: request with valid identity is proxied byte-for-byte (headers + body) to the process manager's resolved child port; request with rejected/missing identity never reaches the process manager at all (spec: `engram-identity-routing`'s "missing identity" requirement).
- [x] 4.2 RED (extend): a streamed/chunked response from the (stubbed) child is forwarded without being fully buffered first — proven by timing (first client chunk arrives before the backend even writes its second chunk), not just final body equality.
- [x] 4.3 GREEN: `src/app.js` — `createApp(processManager)`/`createServer(processManager)`; `bin/engram-router.js` entrypoint (mirrors `services/auth-gateway`'s split).
- [x] 4.4 REFACTOR: verified — `ENGRAM_CLOUD_TOKEN` only ever flows into `buildEnv()` (process-manager.js), never into a response body, header, or `console.log` call anywhere in `src/`/`bin/`.

**Note (non-blocking):** `npm run typecheck` reports module-resolution-level errors (`Cannot find name 'process'/'console'/node:* imports`) despite an installed `@types/node`/`typescript` byte-identical to `auth-gateway`'s — confirmed via diff, not a version or config drift on this service's side. Runtime tests (22/22, `node --test`) and `prettier --check` are both clean. Tracked as a known environment anomaly, same tolerance this repo's own `tsc` baseline already gets in `credential-admin-panel`'s apply-progress notes — not re-investigated further here since it does not indicate a real type error.

## Phase 5: Infra Cutover (Unit 5, PR 5, needs PR1-4)

- [x] 5.1 `services/engram-router/Dockerfile` — multi-stage build per design.md (engram binary fetch+checksum-verify, `supergateway@3.4.3` install, Node app runtime), mirroring the root `Dockerfile`'s `artifacts`/`nodetools` stage shape.
- [x] 5.2 `docker-compose.yml` — removed `mcp-engram-tool`; added `engram-router` service (own build context, `ENGRAM_CLOUD_TOKEN` reused from `engram-cloud`'s own var — same legacy token both sides must agree on). `engram-cloud`'s own block already forwarded `ENGRAM_CLOUD_ALLOWED_PROJECTS` from `.env` generically — no compose change needed there, documented instead in `.env.example`/comments. YAML validated (`python3 -c "import yaml; yaml.safe_load(...)"`).
- [x] 5.3 `Caddyfile` — repointed `handle /mcp/engram*` to `engram-router:9000`, same `forward_auth`/`copy_headers X-Gateway-User X-Gateway-User-Id` shape as every other `/mcp/*` block.
- [x] 5.4 `services/auth-gateway/src/mcp-registry.js` — removed the dead `ENGRAM_API_KEY` claim; `sharedSecretEnv` is now optional per-entry (engram has none, isolated per-identity instead). `credential-status.js`'s `configured` computation updated to treat "no `sharedSecretEnv`" as always-configured rather than false-by-missing-env-lookup. Test suite extended (not just left green): `mcp-registry.test.js` and `credential-status.test.js` updated/added for the new invariant. Full auth-gateway suite: 212/212 passing, eslint clean, prettier clean for every file this unit touched (pre-existing drift in `admin-audit.js`/`admin-auth.js`/their tests/`db.test.js` — from the separate in-progress admin-users-panel branch — left untouched, same precedent as prior units).
- [x] 5.5 `.env.example` + root `README.md` — documented `engram-router`'s env vars (reuses `ENGRAM_CLOUD_TOKEN`, no new var), the now-mandatory `ENGRAM_CLOUD_ALLOWED_PROJECTS=*`, and the `mcp-engram-tool` retirement in both the architecture diagram and the "adding a new MCP" walkthrough.
**Post-deploy amendment (found via real E2E, not anticipated at design time):** deployment surfaced two real gaps, both fixed with the same TDD rigor as the original units, tests extended (not just kept green):
- `deriveProject` (`src/identity.js`) added: an optional client-supplied `X-Engram-Subproject` header now layers onto the trusted identity (`<identity>.<subproject>`) so one gateway user can separate memories per repo, since a remote HTTP MCP session has no channel for the client's local CWD at all — confirmed via real-world testing, not just protocol theory. The identity always prefixes the result; an invalid subproject silently falls back to the bare identity rather than rejecting the request. `engram-identity-routing` spec updated with the new requirement.
- **Follow-up fix, found by the user's own live test within minutes of the above:** the first version of this joined with `--` (double dash). Verified against engram's actual `NormalizeProject`/`CanonicalizeProjectName` source (via deepwiki, not assumed): it lowercases and collapses consecutive `-`/`_` runs into one, but leaves dots untouched. `identity--subproject` therefore silently collapsed server-side to `identity-subproject` — meaning a bare identity like `"yenny-fernanda"` and a *different* identity+subproject pair like `"yenny"` + `"fernanda"` could land in the exact same Engram Cloud project, defeating the whole isolation guarantee this change exists to provide. Fixed by: reserving `.` (never collapsed) as the sole join separator, removing `.` from the allowed identity/subproject character set (so the join is provably unambiguous), and rejecting any identity/subproject containing a repeated `-`/`_` run (so a segment can never itself collapse into colliding with a different segment). `IDENTITY_PATTERN` tightened accordingly; new tests lock in the collision-proof property directly (not just individual validation cases). Full suite: 34/34 passing, lint/format clean.
- `waitUntilReady` (`src/process-manager.js`) added: a freshly-spawned child needs real startup time (`supergateway` + `engram mcp` both booting) before its port accepts connections — the first request after every fresh spawn was hitting a `bad_gateway`, observed live in this session's own deploy. `getOrCreateChild` now polls the port before resolving, with cleanup (map entry + port released) on timeout so a retry can spawn fresh. `engram-process-bridge` spec updated with the new requirement. Full suite: 30/30 passing, lint/format clean.

**Second post-deploy amendment (found via real E2E — autosync genuinely never synced a single row, for any project, ever, confirmed by querying `cloud_mutations` directly):** root cause verified against engram's actual source: `ENGRAM_CLOUD_AUTOSYNC`/`ENGRAM_CLOUD_TOKEN`/`ENGRAM_CLOUD_SERVER` alone are not sufficient — engram's local SQLite requires a project to be explicitly **enrolled** first (`engram cloud enroll <project>`, local state env vars cannot substitute for), which nothing in this change ever ran. Fixed with the same TDD rigor:
- `process-manager.js`: new `realEnrollProject`/`enrollProject` — runs `engram cloud enroll <project>` to completion before spawning that project's first child; on failure, releases the port and spawns nothing, so a retry can attempt enrollment cleanly. `engram-process-bridge` spec updated with the new requirement.
- `realSpawnChild`'s child stdout/stderr were also previously left completely unconsumed (default `stdio: 'pipe'`, nothing ever read it) — every error the wrapped process ever printed, autosync included, was silently discarded, which is what made this take three separate live-debugging rounds (env-var checks, a Postgres query, then finally this) instead of one glance at `docker compose logs`. Now piped to the router's own stdout/stderr, prefixed per identity.
- `docker-compose.yml`: added `engram_router_data` volume at `/home/app/.engram` — engram's local SQLite (and therefore `sync_enrolled_projects`, plus any not-yet-synced local memory) was being silently wiped on every plain image rebuild before this. Full suite: 37/37 passing, lint/format clean.

- [ ] 5.6 Manual E2E smoke per design.md's Testing Strategy: two distinct gateway identities through the real stack, confirm cross-identity isolation and that a `mem_save` reaches `engram-cloud` with no manual sync step. **Not run** — requires `docker compose build`/`up` on the VPS (sudo), which this session cannot execute directly; handed back to the user.
