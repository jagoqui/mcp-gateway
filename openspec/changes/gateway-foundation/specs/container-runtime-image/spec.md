# Container Runtime Image Specification

## Purpose

A shared multi-stage base image (Node 22 + uv/Python) that installs
GitHub-release binaries safely: resolving the real latest release and
verifying its checksum before install.

## Requirements

### Requirement: Multi-stage Dockerfile with Node 22 and uv/Python

The system MUST build the shared base image as a multi-stage Dockerfile
providing Node 22 and `uv`/Python runtimes for the pilot MCP servers.

#### Scenario: Image builds cold-cache

- GIVEN a clean Docker build cache
- WHEN `docker compose build` runs
- THEN the multi-stage build completes successfully
- AND the resulting image contains a working Node 22 runtime and a working
  `uv`/Python runtime

### Requirement: Resolve `latest` GitHub release via API

The system MUST resolve the `latest` tag for each GitHub-release binary
dependency by querying the GitHub API at build time. The system MUST NOT
hardcode a specific release version as the default resolution path.

#### Scenario: Build resolves current latest release

- GIVEN no pinned version override is supplied
- WHEN the image build downloads a GitHub-release binary
- THEN the build first queries the GitHub API to determine the current
  `latest` release tag
- AND downloads the asset matching that resolved tag

#### Scenario: Pinned tag override is honored

- GIVEN a build argument pins an explicit release tag for a dependency
- WHEN the image build downloads that binary
- THEN the build uses the pinned tag instead of querying `latest`

### Requirement: Mandatory checksum verification before install

The system MUST verify each downloaded GitHub-release binary against the
`checksums.txt` published in that same release before installing it. The
system MUST fail the build if verification fails or `checksums.txt` is
unavailable.

#### Scenario: Checksum matches

- GIVEN a downloaded binary and its corresponding entry in the release's
  `checksums.txt`
- WHEN the build computes the binary's checksum
- THEN it matches the published value
- AND the build proceeds to install the binary

#### Scenario: Checksum mismatch fails the build

- GIVEN a downloaded binary whose computed checksum does not match
  `checksums.txt`
- WHEN the build verifies it
- THEN the build fails and does not install the binary
