import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createGrantChecker } from '../src/grant-client.js';

const SECRET = 'test-internal-secret';

/** @type {http.Server} */
let backend;
/** @type {{ url?: string, headers?: any }} */
let lastRequest;
/** @type {{ status: number, body: any }} */
let nextResponse;

beforeEach(async () => {
  lastRequest = {};
  nextResponse = { status: 200, body: { granted: true } };
  backend = http.createServer((req, res) => {
    lastRequest = { url: req.url, headers: req.headers };
    res.writeHead(nextResponse.status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(nextResponse.body));
  });
  await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
});

afterEach(async () => {
  await new Promise((resolve) => backend.close(resolve));
});

function baseUrl() {
  const address = /** @type {any} */ (backend.address());
  return `http://127.0.0.1:${address.port}`;
}

test('sends the identity/project as query params and the shared secret as a header', async () => {
  const checkGrant = createGrantChecker({ baseUrl: baseUrl(), secret: SECRET });
  await checkGrant({ identity: 'jagoqui', project: 'team-alpha' });
  assert.equal(lastRequest.url, '/internal/engram-grant?identity=jagoqui&project=team-alpha');
  assert.equal(lastRequest.headers['x-internal-secret'], SECRET);
});

test('returns true when the endpoint reports granted:true', async () => {
  nextResponse = { status: 200, body: { granted: true } };
  const checkGrant = createGrantChecker({ baseUrl: baseUrl(), secret: SECRET });
  assert.equal(await checkGrant({ identity: 'a', project: 'b' }), true);
});

test('returns false when the endpoint reports granted:false', async () => {
  nextResponse = { status: 200, body: { granted: false } };
  const checkGrant = createGrantChecker({ baseUrl: baseUrl(), secret: SECRET });
  assert.equal(await checkGrant({ identity: 'a', project: 'b' }), false);
});

test('fails closed (false) on a non-2xx response', async () => {
  nextResponse = { status: 401, body: { error: 'unauthenticated' } };
  const checkGrant = createGrantChecker({ baseUrl: baseUrl(), secret: SECRET });
  assert.equal(await checkGrant({ identity: 'a', project: 'b' }), false);
});

test('fails closed (false) when the backend is unreachable', async () => {
  const checkGrant = createGrantChecker({ baseUrl: 'http://127.0.0.1:1', secret: SECRET });
  assert.equal(await checkGrant({ identity: 'a', project: 'b' }), false);
});
