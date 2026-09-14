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

// deriveProject layers an OPTIONAL client-supplied sub-project onto the
// trusted identity — never a replacement for it. The identity always
// prefixes the final project, so one user can never collide with or read
// another user's namespace no matter what they put in the header.

test('deriveProject with no subproject header returns the bare identity (backward compatible)', () => {
  assert.equal(deriveProject({ 'x-gateway-user': 'jagoqui' }), 'jagoqui');
});

test('deriveProject with a valid subproject header combines identity.subproject', () => {
  assert.equal(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': 'skills-registry' }),
    'jagoqui.skills-registry',
  );
});

test('deriveProject rejects the whole request when identity itself is missing/invalid, regardless of subproject', () => {
  assert.equal(deriveProject({ 'x-engram-subproject': 'skills-registry' }), null);
});

test('deriveProject falls back to the bare identity when the subproject header is invalid, rather than rejecting the request', () => {
  assert.equal(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': '../../etc/passwd' }),
    'jagoqui',
  );
  assert.equal(
    deriveProject({ 'x-gateway-user': 'jagoqui', 'x-engram-subproject': '' }),
    'jagoqui',
  );
});

test("deriveProject never lets a subproject value alone collide with another user's bare identity", () => {
  // Alice setting X-Engram-Subproject to literally "bob" must never produce
  // plain "bob" — it always stays prefixed under alice's own identity.
  const result = deriveProject({ 'x-gateway-user': 'alice', 'x-engram-subproject': 'bob' });
  assert.equal(result, 'alice.bob');
  assert.notEqual(result, 'bob');
});

test("a bare identity and identity+subproject can never collide after engram's own normalization", () => {
  // engram lowercases and collapses runs of consecutive "-"/"_" — it does
  // NOT collapse dots. "yenny-fernanda" (bare) and "yenny"+"fernanda"
  // (joined) are provably distinct strings post-normalization because the
  // join always contains exactly one "." that neither identity nor
  // subproject can ever themselves contain.
  const bareCompoundIdentity = deriveProject({ 'x-gateway-user': 'yenny-fernanda' });
  const identityPlusSubproject = deriveProject({
    'x-gateway-user': 'yenny',
    'x-engram-subproject': 'fernanda',
  });
  assert.equal(bareCompoundIdentity, 'yenny-fernanda');
  assert.equal(identityPlusSubproject, 'yenny.fernanda');
  assert.notEqual(bareCompoundIdentity, identityPlusSubproject);
});
