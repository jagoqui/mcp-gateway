# Service Composition Specification

## Purpose

Docker Compose topology wiring the reverse proxy, auth gateway, pilot MCP
servers, and the shared Engram Cloud stack together with the networks,
volumes, and environment variables they need.

## Requirements

### Requirement: Compose topology includes all defined services

The system MUST define, in `docker-compose.yml`, at least the following
services: `caddy`, `auth-gateway`, `mcp-context7`, `mcp-atlassian`,
`mcp-engram-tool`, `engram-cloud`, `engram-cloud-db` (postgres), and
`engram-monitor`.

#### Scenario: All services reach a healthy state

- GIVEN `docker-compose.yml` defines the required services
- WHEN `docker compose up -d` runs
- THEN every listed service reaches a running/healthy state

#### Scenario: Service depends on its dependency being ready

- GIVEN `engram-cloud` depends on `engram-cloud-db`
- WHEN `docker compose up -d` runs
- THEN `engram-cloud-db` becomes ready before `engram-cloud` accepts traffic

### Requirement: Engram Cloud is shared team memory, not per-user

The system MUST configure `engram-cloud` as a single shared project/namespace
visible to every valid gateway token holder. The system MUST NOT partition
`engram-cloud` data per individual user in this slice.

#### Scenario: Two authenticated users see the same memory

- GIVEN Alice and Bob both hold valid gateway tokens
- WHEN each queries `engram-cloud` for the same project/namespace
- THEN both receive access to the same shared memory data
- AND neither is isolated into a private per-user namespace

### Requirement: Environment-sourced configuration, no committed secrets

The system MUST source all secrets and per-deployment configuration (API
keys, tokens, DB credentials) from runtime environment variables backed by
an untracked `.env` file, using `.env.example` as the documented template.
The system MUST NOT commit real secret values to the repository.

#### Scenario: Compose reads values from .env

- GIVEN a populated `.env` file matching `.env.example`
- WHEN `docker compose up -d` runs
- THEN each service receives its configuration via environment variables
  sourced from `.env`

#### Scenario: .env is excluded from version control

- GIVEN the repository's `.gitignore`
- WHEN `.env` exists in the working tree
- THEN `.env` is not tracked or committed, while `.env.example` is
