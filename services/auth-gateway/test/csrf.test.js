import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveCsrfSecret,
  issueCsrfToken,
  verifyCsrfToken,
  isAcceptableOrigin,
} from '../src/csrf.js';
import { sign, createSessionToken, verifySessionToken } from '../src/session.js';

const SESSION_SECRET = 'csrf-test-session-secret';
const UID = 42;

test('issueCsrfToken/verifyCsrfToken round-trip succeeds for the same uid+secret', () => {
  const now = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, now);
  assert.equal(typeof token, 'string');
  assert.ok(token.includes('.'));
  const ok = verifyCsrfToken(token, { uid: UID, sessionSecret: SESSION_SECRET, now });
  assert.equal(ok, true);
});

test('verifyCsrfToken rejects a tampered payload (signature no longer matches)', () => {
  const now = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, now);
  const [payloadB64, sig] = token.split('.');
  const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  const tamperedPayload = Buffer.from(
    JSON.stringify({ ...decoded, uid: UID + 1 }),
    'utf8',
  ).toString('base64url');
  const tampered = `${tamperedPayload}.${sig}`;
  const ok = verifyCsrfToken(tampered, { uid: UID, sessionSecret: SESSION_SECRET, now });
  assert.equal(ok, false);
});

test('verifyCsrfToken rejects a tampered signature', () => {
  const now = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, now);
  const [payloadB64] = token.split('.');
  const tampered = `${payloadB64}.not-the-real-signature`;
  const ok = verifyCsrfToken(tampered, { uid: UID, sessionSecret: SESSION_SECRET, now });
  assert.equal(ok, false);
});

test('verifyCsrfToken rejects a token issued for a different uid', () => {
  const now = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, now);
  const ok = verifyCsrfToken(token, { uid: UID + 1, sessionSecret: SESSION_SECRET, now });
  assert.equal(ok, false);
});

test('verifyCsrfToken rejects a token missing the "." separator', () => {
  const ok = verifyCsrfToken('no-separator-here', {
    uid: UID,
    sessionSecret: SESSION_SECRET,
    now: Date.now(),
  });
  assert.equal(ok, false);
});

test('verifyCsrfToken rejects a payload that is not valid JSON, even with a valid signature', () => {
  const csrfSecret = deriveCsrfSecret(SESSION_SECRET);
  const payloadB64 = Buffer.from('not-json-at-all', 'utf8').toString('base64url');
  const sig = sign(payloadB64, csrfSecret);
  const token = `${payloadB64}.${sig}`;
  const ok = verifyCsrfToken(token, { uid: UID, sessionSecret: SESSION_SECRET, now: Date.now() });
  assert.equal(ok, false);
});

test('verifyCsrfToken rejects an expired token (iat older than max age)', () => {
  const issuedAt = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, issuedAt);
  const maxAgeSeconds = 100;
  const verifyNow = issuedAt + (maxAgeSeconds + 1) * 1000;
  const ok = verifyCsrfToken(token, {
    uid: UID,
    sessionSecret: SESSION_SECRET,
    now: verifyNow,
    maxAgeSeconds,
  });
  assert.equal(ok, false);
});

test('verifyCsrfToken accepts a token right at the max-age boundary', () => {
  const issuedAt = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, issuedAt);
  const maxAgeSeconds = 100;
  const verifyNow = issuedAt + maxAgeSeconds * 1000;
  const ok = verifyCsrfToken(token, {
    uid: UID,
    sessionSecret: SESSION_SECRET,
    now: verifyNow,
    maxAgeSeconds,
  });
  assert.equal(ok, true);
});

test('verifyCsrfToken rejects a future-dated token beyond the clock skew allowance', () => {
  const issuedAt = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, issuedAt);
  // Verifying "now" more than CLOCK_SKEW_SECONDS (60s) before iat.
  const verifyNow = issuedAt - 61_000;
  const ok = verifyCsrfToken(token, { uid: UID, sessionSecret: SESSION_SECRET, now: verifyNow });
  assert.equal(ok, false);
});

test('verifyCsrfToken accepts a token within the clock skew allowance', () => {
  const issuedAt = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, issuedAt);
  const verifyNow = issuedAt - 30_000;
  const ok = verifyCsrfToken(token, { uid: UID, sessionSecret: SESSION_SECRET, now: verifyNow });
  assert.equal(ok, true);
});

test('verifyCsrfToken accepts a token right at the clock skew boundary', () => {
  const issuedAt = Date.now();
  const token = issueCsrfToken(UID, SESSION_SECRET, issuedAt);
  // CLOCK_SKEW_SECONDS is 60; age === -60 exactly must still be accepted
  // (the rejection is age < -CLOCK_SKEW_SECONDS, a strict less-than).
  const verifyNow = issuedAt - 60_000;
  const ok = verifyCsrfToken(token, { uid: UID, sessionSecret: SESSION_SECRET, now: verifyNow });
  assert.equal(ok, true);
});

test('verifyCsrfToken never throws on malformed input', () => {
  assert.doesNotThrow(() => {
    verifyCsrfToken(undefined, { uid: UID, sessionSecret: SESSION_SECRET, now: Date.now() });
    verifyCsrfToken(null, { uid: UID, sessionSecret: SESSION_SECRET, now: Date.now() });
    verifyCsrfToken('', { uid: UID, sessionSecret: SESSION_SECRET, now: Date.now() });
    verifyCsrfToken(/** @type {any} */ (123), {
      uid: UID,
      sessionSecret: SESSION_SECRET,
      now: Date.now(),
    });
    // Missing options object and a non-string sessionSecret must also fail
    // closed rather than throw (options is caller-supplied, not part of the
    // token, but the "never throws" contract covers the whole signature).
    verifyCsrfToken(issueCsrfToken(UID, SESSION_SECRET), /** @type {any} */ (undefined));
    verifyCsrfToken(issueCsrfToken(UID, SESSION_SECRET), /** @type {any} */ ({ uid: UID }));
    verifyCsrfToken(issueCsrfToken(UID, SESSION_SECRET), {
      uid: UID,
      sessionSecret: /** @type {any} */ (null),
    });
  });
});

test('verifyCsrfToken returns false (not throw) for a missing options object or invalid sessionSecret', () => {
  const token = issueCsrfToken(UID, SESSION_SECRET);
  assert.equal(verifyCsrfToken(token, /** @type {any} */ (undefined)), false);
  assert.equal(verifyCsrfToken(token, /** @type {any} */ ({ uid: UID })), false);
  assert.equal(
    verifyCsrfToken(token, { uid: UID, sessionSecret: /** @type {any} */ (null) }),
    false,
  );
});

test('domain separation (R9): a CSRF token is never valid as a session token', () => {
  const csrfToken = issueCsrfToken(UID, SESSION_SECRET, Date.now());
  const asSession = verifySessionToken(csrfToken, SESSION_SECRET);
  assert.equal(asSession, null);
});

test('domain separation (R9): a session token is never valid as a CSRF token', () => {
  const sessionToken = createSessionToken({ uid: UID }, SESSION_SECRET);
  const ok = verifyCsrfToken(sessionToken, {
    uid: UID,
    sessionSecret: SESSION_SECRET,
    now: Date.now(),
  });
  assert.equal(ok, false);
});

test('deriveCsrfSecret is deterministic and differs from the raw session secret', () => {
  const derived = deriveCsrfSecret(SESSION_SECRET);
  assert.equal(typeof derived, 'string');
  assert.notEqual(derived, SESSION_SECRET);
  assert.equal(derived, deriveCsrfSecret(SESSION_SECRET));
});

// --- isAcceptableOrigin matrix (R3) ---

const DOMAIN = 'auth.example.test';
const EXPECTED = `https://${DOMAIN}`;

test('isAcceptableOrigin: Origin present and matching returns true', () => {
  const ok = isAcceptableOrigin(
    { origin: EXPECTED, referer: undefined },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, true);
});

test('isAcceptableOrigin: Origin present and mismatching returns false', () => {
  const ok = isAcceptableOrigin(
    { origin: 'https://evil.example', referer: undefined },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, false);
});

test('isAcceptableOrigin: literal "null" Origin is never treated as a match', () => {
  const strict = isAcceptableOrigin(
    { origin: 'null', referer: undefined },
    { domain: DOMAIN, strict: true },
  );
  const nonStrict = isAcceptableOrigin(
    { origin: 'null', referer: undefined },
    { domain: DOMAIN, strict: false },
  );
  assert.equal(strict, false);
  assert.equal(nonStrict, false);
});

test('isAcceptableOrigin: Referer-only present and matching returns true', () => {
  const ok = isAcceptableOrigin(
    { origin: undefined, referer: `${EXPECTED}/credentials` },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, true);
});

test('isAcceptableOrigin: Referer-only present and unparseable returns false', () => {
  const ok = isAcceptableOrigin(
    { origin: undefined, referer: 'not a valid url at all' },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, false);
});

test('isAcceptableOrigin: Referer-only present and mismatching host returns false', () => {
  const ok = isAcceptableOrigin(
    { origin: undefined, referer: 'https://evil.example/path' },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, false);
});

test('isAcceptableOrigin: both absent under strict:true returns false', () => {
  const ok = isAcceptableOrigin(
    { origin: undefined, referer: undefined },
    { domain: DOMAIN, strict: true },
  );
  assert.equal(ok, false);
});

test('isAcceptableOrigin: both absent under strict:false returns true', () => {
  const ok = isAcceptableOrigin(
    { origin: undefined, referer: undefined },
    { domain: DOMAIN, strict: false },
  );
  assert.equal(ok, true);
});

test('isAcceptableOrigin: missing headers or options object returns false, never throws', () => {
  assert.doesNotThrow(() => {
    assert.equal(
      isAcceptableOrigin(/** @type {any} */ (undefined), { domain: DOMAIN, strict: true }),
      false,
    );
    assert.equal(
      isAcceptableOrigin({ origin: EXPECTED, referer: undefined }, /** @type {any} */ (undefined)),
      false,
    );
    assert.equal(
      isAcceptableOrigin(
        { origin: EXPECTED, referer: undefined },
        /** @type {any} */ ({ strict: true }),
      ),
      false,
    );
  });
});
