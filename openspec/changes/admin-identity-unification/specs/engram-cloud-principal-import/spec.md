# Engram Cloud Principal Import Specification

## Purpose

Let an operator turn a pre-existing Engram Cloud managed principal
(created outside this admin panel) into a working local admin account,
so it stops being invisible to this system.

## Requirements

### Requirement: The import page lists only Cloud principals with no local link

`GET /admin/engram-cloud/import` MUST list every Engram Cloud managed
user (via the existing `listUsers()` proxy) that has no corresponding
row in `engram_cloud_credentials`. It MUST NOT list a principal that
already has a local link, whether created by Phase 5's provisioning or
by a prior import.

#### Scenario: An unlinked principal appears, a linked one does not

- GIVEN Engram Cloud has a principal with no `engram_cloud_credentials`
  row, and another principal that already has one
- WHEN an admin loads `GET /admin/engram-cloud/import`
- THEN the unlinked principal appears in the list
- AND the already-linked principal does not

### Requirement: Importing creates a local account and issues a fresh link token

`POST /admin/engram-cloud/import` MUST accept a chosen `principal_id`, a
new local `username`, and a new local `password`; create the local admin
account (bcrypt-hashed, `is_admin = 1`); issue that principal a fresh
Engram Cloud token (`issueToken`, the existing proxy call); and store the
encrypted link (`engram_cloud_credentials`) — all in one transaction
(D8: mutation and any related record land together or not at all).

#### Scenario: A successful import produces a working local login and a working Cloud SSO

- GIVEN an unlinked Cloud principal shown on the import page
- WHEN an admin submits the import form with a new username/password for it
- THEN a new local admin account exists with those credentials
- AND `engram_cloud_credentials` has a row linking it to that principal
- AND logging in as the new account and visiting the Engram Cloud nav
  link succeeds without a second Cloud login, using the token issued at
  import time

#### Scenario: The chosen local username must be explicit, never assumed from Cloud

- GIVEN a Cloud principal whose own `username` field collides with an
  existing, unrelated local admin account's username
- WHEN an operator imports that principal
- THEN the import form requires them to choose a different local
  username explicitly — it is never auto-filled from the Cloud
  principal's own username in a way that could silently collide

### Requirement: Import never revokes or otherwise touches the principal's other tokens

Issuing a fresh token for the imported principal MUST be additive only.

#### Scenario: A principal with an existing, actively-used token is imported

- GIVEN a Cloud principal that already has one or more active tokens
  issued outside this system
- WHEN it is imported
- THEN those existing tokens remain valid and untouched
- AND only one new token is added, the one this import stores
