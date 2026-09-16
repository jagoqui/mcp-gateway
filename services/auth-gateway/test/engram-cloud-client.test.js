import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { listUsers, createUser, grantProject, issueToken } from '../src/engram-cloud-client.js';

const ADMIN_TOKEN = 'test-engram-cloud-admin-token';

before(() => {
  process.env.ENGRAM_CLOUD_ADMIN = ADMIN_TOKEN;
});

/** @type {http.Server} */
let backend;
/** @type {{ method?: string, url?: string, headers?: any, body?: string }} */
let lastRequest;
/** @type {{ status: number, body: any }} */
let nextResponse;

beforeEach(async () => {
  lastRequest = {};
  nextResponse = { status: 200, body: {} };
  backend = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      lastRequest = { method: req.method, url: req.url, headers: req.headers, body: raw };
      res.writeHead(nextResponse.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(nextResponse.body));
    });
  });
  await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
  const address = /** @type {any} */ (backend.address());
  process.env.ENGRAM_CLOUD_SERVER = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise((resolve) => backend.close(resolve));
});

test('listUsers sends GET /admin/users with the Bearer admin token, no body', async () => {
  nextResponse = { status: 200, body: [{ principal_id: 'p1', username: 'alice' }] };
  const result = await listUsers();
  assert.equal(lastRequest.method, 'GET');
  assert.equal(lastRequest.url, '/admin/users');
  assert.equal(lastRequest.headers.authorization, `Bearer ${ADMIN_TOKEN}`);
  assert.equal(lastRequest.body, '');
  assert.deepEqual(result, [{ principal_id: 'p1', username: 'alice' }]);
});

test('createUser sends POST /admin/users with the exact request shape', async () => {
  nextResponse = {
    status: 201,
    body: { principal_id: 'p2', username: 'bob', role: 'member', enabled: true },
  };
  const result = await createUser({ username: 'bob', email: 'bob@example.com', role: 'member' });
  assert.equal(lastRequest.method, 'POST');
  assert.equal(lastRequest.url, '/admin/users');
  assert.equal(lastRequest.headers.authorization, `Bearer ${ADMIN_TOKEN}`);
  // JSON.stringify drops an undefined-valued key entirely — displayName
  // was never passed, so display_name is correctly absent, not null.
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastRequest.body)), {
    username: 'bob',
    email: 'bob@example.com',
    role: 'member',
  });
  assert.equal(result.principal_id, 'p2');
});

test('grantProject sends POST /admin/users/:id/grants with the project body', async () => {
  nextResponse = {
    status: 201,
    body: { principal_id: 'p2', project: 'acme', granted_by_principal_id: 'p1' },
  };
  const result = await grantProject({ principalId: 'p2', project: 'acme' });
  assert.equal(lastRequest.method, 'POST');
  assert.equal(lastRequest.url, '/admin/users/p2/grants');
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastRequest.body)), { project: 'acme' });
  assert.equal(result.project, 'acme');
});

test('grantProject URL-encodes a principalId containing special characters', async () => {
  await grantProject({ principalId: 'p/2 x', project: 'acme' });
  assert.equal(lastRequest.url, '/admin/users/p%2F2%20x/grants');
});

test('issueToken sends POST /admin/users/:id/tokens with an optional name, and returns raw_token', async () => {
  nextResponse = {
    status: 201,
    body: { raw_token: 'shown-once-value', token: { id: 't1', principal_id: 'p2' } },
  };
  const result = await issueToken({ principalId: 'p2', name: 'laptop' });
  assert.equal(lastRequest.url, '/admin/users/p2/tokens');
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastRequest.body)), { name: 'laptop' });
  assert.equal(result.raw_token, 'shown-once-value');
});

test('issueToken omits the name field entirely when no label is given', async () => {
  await issueToken({ principalId: 'p2' });
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastRequest.body)), {});
});

test('threat: a non-2xx response throws an Error whose message never contains the admin token', async () => {
  nextResponse = { status: 500, body: { error: 'internal' } };
  await assert.rejects(
    () => listUsers(),
    (/** @type {any} */ err) => {
      assert.ok(err instanceof Error);
      assert.ok(!err.message.includes(ADMIN_TOKEN));
      assert.ok(!JSON.stringify(err).includes(ADMIN_TOKEN));
      return true;
    },
  );
});

test('every client function throws when ENGRAM_CLOUD_ADMIN is unset, before ever sending a request', async () => {
  const original = process.env.ENGRAM_CLOUD_ADMIN;
  try {
    delete process.env.ENGRAM_CLOUD_ADMIN;
    await assert.rejects(() => listUsers());
    assert.deepEqual(lastRequest, {});
  } finally {
    process.env.ENGRAM_CLOUD_ADMIN = original;
  }
});
