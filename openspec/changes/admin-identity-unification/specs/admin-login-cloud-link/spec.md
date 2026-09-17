# Admin Login Cloud Link Specification

## Purpose

Guarantee every local admin ends up with a linked Engram Cloud identity
without requiring them to visit the Cloud nav link first — while never
letting Engram Cloud's availability affect whether login to this panel
succeeds.

## Requirements

### Requirement: A successful admin login provisions a Cloud link if one is missing

After `POST /admin/login` authenticates an admin and sets the session
cookie, the system MUST check whether that admin already has a row in
`engram_cloud_credentials`. If not, it MUST provision one using the same
create-user/issue-token/encrypt-and-store logic Phase 5's
`GET /admin/engram-cloud/sso` already uses.

#### Scenario: A first-time admin gets linked on login, without visiting the SSO route

- GIVEN an admin with no `engram_cloud_credentials` row
- WHEN they submit valid credentials to `POST /admin/login`
- THEN the login succeeds and redirects as normal
- AND a `engram_cloud_credentials` row now exists for that admin

#### Scenario: An already-linked admin's login is a no-op for provisioning

- GIVEN an admin who already has a `engram_cloud_credentials` row
- WHEN they log in again
- THEN no new Cloud user or token is created, and the existing row is
  left untouched

### Requirement: Cloud provisioning failure never fails the login itself

If the Cloud provisioning step (create user, issue token, or the
encrypted write) fails for any reason, the admin's login MUST still
succeed exactly as it would without this feature.

#### Scenario: Engram Cloud is unreachable during login

- GIVEN Engram Cloud is down or unreachable
- WHEN an admin with no prior link submits valid credentials to
  `POST /admin/login`
- THEN the login still succeeds (session cookie set, normal redirect)
- AND no `engram_cloud_credentials` row is created
- AND the failure does not surface as a login error to the admin

### Requirement: The existing lazy on-click provisioning is unchanged

`GET /admin/engram-cloud/sso`'s own provision-if-missing check MUST
remain exactly as Phase 5 built it, so it still self-heals a link that
login-time provisioning failed to create.

#### Scenario: A link that failed at login time is created on first Cloud visit instead

- GIVEN an admin whose login-time provisioning failed (e.g. Cloud was
  down at that moment) and who has no `engram_cloud_credentials` row
- WHEN they later visit `GET /admin/engram-cloud/sso`
- THEN provisioning runs there exactly as it did before this change,
  and succeeds if Cloud is reachable now
