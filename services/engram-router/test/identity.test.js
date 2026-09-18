import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveIdentity, deriveProject } from '../src/identity.js';

test('valid X-Gateway-User header yields that identity', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'jagoqui' }), 'jagoqui');
});

test('missing X-Gateway-User header is rejected', () => {
  assert.equal(deriveIdentity({}), null);
});

test('empty-string X-Gateway-User header is rejected', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': '' }), null);
});

test('non-string X-Gateway-User header is rejected', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': ['jagoqui', 'yenny'] }), null);
});

test('header containing path-traversal-like content is rejected, never normalized', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': '../../etc/passwd' }), null);
});

test('header containing shell-metacharacter-like content is rejected', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'jagoqui; rm -rf /' }), null);
  assert.equal(deriveIdentity({ 'x-gateway-user': '$(whoami)' }), null);
  assert.equal(deriveIdentity({ 'x-gateway-user': 'jagoqui`id`' }), null);
});

test('header longer than the allowed length is rejected', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'a'.repeat(65) }), null);
});

test('a client-supplied project-like header has zero effect on the result', () => {
  const withExtra = deriveIdentity({
    'x-gateway-user': 'jagoqui',
    'x-engram-project': 'someone-elses-project',
  });
  const withoutExtra = deriveIdentity({ 'x-gateway-user': 'jagoqui' });
  assert.equal(withExtra, withoutExtra);
  assert.equal(withExtra, 'jagoqui');
});

test('dashed/underscored usernames within the allow-list are accepted', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'yenny-fernanda' }), 'yenny-fernanda');
  assert.equal(deriveIdentity({ 'x-gateway-user': 'user_123' }), 'user_123');
});

test("a dot is rejected — reserved for deriveProject's own identity/subproject join", () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'jagoqui.gomez' }), null);
});

test('a doubled separator is rejected — engram itself collapses "--"/"__" to one, which could collide with a different, genuinely single-separator value', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': 'ab--cd' }), null);
  assert.equal(deriveIdentity({ 'x-gateway-user': 'ab__cd' }), null);
});

test('a leading or trailing separator is rejected', () => {
  assert.equal(deriveIdentity({ 'x-gateway-user': '-jagoqui' }), null);
  assert.equal(deriveIdentity({ 'x-gateway-user': 'jagoqui-' }), null);
});

// engram-shared-projects (2026-09-18): deriveProject's contract changed —
// X-Engram-Subproject no longer joins onto the identity ("identity.sub").
// It now names a SHARED, bare, unprefixed project outright — collaboration
// across identities is the whole point, gated by an actual Engram Cloud
// grant (checked by process-manager.js, not here). No header at all still
// means the private, always-available identity-scoped default, with no
// grant check ever required for it. deriveProject now returns
// { identity, project, isShared } instead of a bare string.

test('deriveProject with no subproject header returns the private identity-scoped default, isShared: false', () => {
  assert.deepEqual(deriveProject({ 'x-gateway-user': 'jagoqui' }), {
    identity: 'jagoqui',
    project: 'jagoqui',
    isShared: false,
  });
});

test('deriveProject with a valid subproject header returns that BARE project (no identity prefix), isShared: true', () => {
  assert.deepEqual(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': 'skills-registry' }),
    { identity: 'jagoqui', project: 'skills-registry', isShared: true },
  );
});

test('deriveProject rejects the whole request when identity itself is missing/invalid, regardless of subproject', () => {
  assert.equal(deriveProject({ 'x-engram-subproject': 'skills-registry' }), null);
});

test('deriveProject falls back to the private identity-scoped default when the subproject header is invalid, rather than rejecting the request', () => {
  assert.deepEqual(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': '../../etc/passwd' }),
    { identity: 'jagoqui', project: 'jagoqui', isShared: false },
  );
  assert.deepEqual(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': '' }),
    { identity: 'jagoqui', project: 'jagoqui', isShared: false },
  );
});

test('a subproject value can now equal another identity — this is the point (shared collaboration), gated by the grant check elsewhere, not by this function', () => {
  const result = deriveProject({ 'x-gateway-user': 'alice', 'x-engram-subproject': 'bob' });
  assert.deepEqual(result, { identity: 'alice', project: 'bob', isShared: true });
});

test('a bare private identity and a same-named shared project are the SAME project string now — deliberate: a shared project can reuse anyone\'s username as its name, the grant check is the only thing gating access to it, not the string itself', () => {
  const privateDefault = deriveProject({ 'x-gateway-user': 'yenny-fernanda' });
  const sameNameShared = deriveProject({
    'x-gateway-user': 'someone-else',
    'x-engram-subproject': 'yenny-fernanda',
  });
  assert.equal(privateDefault.project, 'yenny-fernanda');
  assert.equal(sameNameShared.project, 'yenny-fernanda');
  assert.equal(privateDefault.isShared, false);
  assert.equal(sameNameShared.isShared, true);
});
