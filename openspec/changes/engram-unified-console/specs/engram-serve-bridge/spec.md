# Engram Serve Bridge Specification

## Purpose

Give engram-monitor a backend that keeps its existing REST calls working
unchanged while staying bidirectionally synchronized with this repo's own
Engram Cloud — so editing/viewing in Monitor is editing/viewing the real,
shared data, not a disconnected local copy.

## Requirements

### Requirement: A shared engram serve instance with autosync enabled

The system MUST run one `engram serve` process (new compose service) with
`ENGRAM_CLOUD_AUTOSYNC=1`, `ENGRAM_CLOUD_TOKEN`, and `ENGRAM_CLOUD_SERVER`
pointed at this repo's own `engram-cloud` service — the same legacy
wildcard credential model `engram-router` already uses, for the same
reason (this instance must be able to sync projects it did not create
itself, without a manual per-project VPS action).

#### Scenario: A write through engram-monitor becomes visible in Engram Cloud's dashboard

- GIVEN the shared `engram-serve` instance is running with autosync enabled
- WHEN an admin creates or edits an observation via engram-monitor's UI
- THEN the change is visible via Engram Cloud's own dashboard shortly
  after, with no manual sync step

### Requirement: Local writes and cloud-pulled writes are both visible

Because this instance is shared across every project (unlike
`engram-router`'s one-project-per-identity children), it MUST NOT pin a
single `ENGRAM_PROJECT` override — each REST call determines its own
project explicitly, matching how engram-monitor's existing multi-project UI
already expects to work.

#### Scenario: Two different projects are both usable through the same instance

- GIVEN observations exist for two different projects in Engram Cloud
- WHEN engram-monitor requests each project's observations through the
  shared instance
- THEN both are retrievable, neither forced into a single fixed project

### Requirement: The local store survives redeploys

Same lesson as `engram-router`'s own local store (see
`engram-remote-mcp`'s tasks.md): this instance's local SQLite (enrollment
state included) MUST be on a persistent volume, not the container's
writable layer, or a plain image rebuild silently wipes it.

#### Scenario: A rebuild does not lose enrollment or not-yet-synced data

- GIVEN the shared instance has enrolled at least one project
- WHEN its container image is rebuilt and recreated
- THEN enrollment state and any not-yet-synced local data are still present
  after the recreate
