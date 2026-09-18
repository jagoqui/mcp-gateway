import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  listUsers,
  createUser,
  grantProject,
  listGrants,
  issueToken,
  listTokens,
  revokeCloudToken,
  loginDashboard,
} from '../src/engram-cloud-client.js';

const ADMIN_TOKEN = 'test-engram-cloud-admin-token';

before(() => {
  process.env.ENGRAM_CLOUD_ADMIN_TOKEN = ADMIN_TOKEN;
});

/** @type {http.Server} */
let backend;
/** @type {{ method?: string, url?: string, headers?: any, body?: string }} */
let lastRequest;
/** @type {{ status: number, body: any, headers?: Record<string, string> }} */
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
      res.writeHead(nextResponse.status, {
        'Content-Type': 'application/json',
        ...nextResponse.headers,
      });
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

test('listGrants sends GET /admin/users/:id/grants, no body, and returns the array as-is', async () => {
  nextResponse = {
    status: 200,
    body: [
      { principal_id: 'p2', project: 'jagoqui.demo', granted_by_principal_id: 'p1', created_at: '2026-01-01T00:00:00Z' },
    ],
  };
  const result = await listGrants({ principalId: 'p2' });
  assert.equal(lastRequest.method, 'GET');
  assert.equal(lastRequest.url, '/admin/users/p2/grants');
  assert.equal(lastRequest.body, '');
  assert.deepEqual(result, [
    { principal_id: 'p2', project: 'jagoqui.demo', granted_by_principal_id: 'p1', created_at: '2026-01-01T00:00:00Z' },
  ]);
});

test('listGrants URL-encodes a principalId containing special characters', async () => {
  await listGrants({ principalId: 'p/2 x' });
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

test('listTokens sends GET /admin/users/:id/tokens, no body, and returns the array as-is', async () => {
  nextResponse = {
    status: 200,
    body: [
      {
        id: 't1',
        principal_id: 'p2',
        token_prefix: 'eg_abcd',
        name: 'console-sso',
        created_by_principal_id: 'p1',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
        revoked_by_principal_id: null,
        revocation_reason: null,
      },
    ],
  };
  const result = await listTokens({ principalId: 'p2' });
  assert.equal(lastRequest.method, 'GET');
  assert.equal(lastRequest.url, '/admin/users/p2/tokens');
  assert.equal(lastRequest.body, '');
  assert.equal(result.length, 1);
  assert.equal(result[0].token_prefix, 'eg_abcd');
});

test('listTokens URL-encodes a principalId containing special characters', async () => {
  await listTokens({ principalId: 'p/2 x' });
  assert.equal(lastRequest.url, '/admin/users/p%2F2%20x/tokens');
});

test('revokeCloudToken sends POST /admin/tokens/:id/revoke with the reason body', async () => {
  nextResponse = { status: 200, body: { id: 't1', revoked_at: '2026-01-02T00:00:00Z' } };
  const result = await revokeCloudToken({ tokenId: 't1', reason: 'revoked via admin panel' });
  assert.equal(lastRequest.method, 'POST');
  assert.equal(lastRequest.url, '/admin/tokens/t1/revoke');
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastRequest.body)), {
    reason: 'revoked via admin panel',
  });
  assert.equal(result.id, 't1');
});

test('revokeCloudToken URL-encodes a tokenId containing special characters', async () => {
  await revokeCloudToken({ tokenId: 't/1 x', reason: 'r' });
  assert.equal(lastRequest.url, '/admin/tokens/t%2F1%20x/revoke');
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

test('loginDashboard posts the token as a form field, not an Authorization header', async () => {
  nextResponse = {
    status: 303,
    body: {},
    headers: {
      Location: '/dashboard/',
      'Set-Cookie': 'engram_dashboard_token=abc; Path=/dashboard; HttpOnly; SameSite=Lax',
    },
  };
  await loginDashboard('a-principal-own-token');
  assert.equal(lastRequest.method, 'POST');
  assert.equal(lastRequest.url, '/dashboard/login');
  assert.equal(lastRequest.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(lastRequest.headers.authorization, undefined);
  assert.equal(lastRequest.body, 'token=a-principal-own-token');
});

test('loginDashboard does not follow the 303 redirect and returns the raw Set-Cookie value', async () => {
  nextResponse = {
    status: 303,
    body: {},
    headers: {
      Location: '/dashboard/',
      'Set-Cookie': 'engram_dashboard_token=abc; Path=/dashboard; HttpOnly; SameSite=Lax',
    },
  };
  const result = await loginDashboard('a-principal-own-token');
  assert.equal(result.setCookie, 'engram_dashboard_token=abc; Path=/dashboard; HttpOnly; SameSite=Lax');
});

test('loginDashboard throws on a non-303 response, message never contains the token', async () => {
  nextResponse = { status: 401, body: { error: 'invalid_token' } };
  await assert.rejects(
    () => loginDashboard('a-secret-value'),
    (/** @type {any} */ err) => {
      assert.ok(err instanceof Error);
      assert.ok(!err.message.includes('a-secret-value'));
      return true;
    },
  );
});

test('every client function throws when ENGRAM_CLOUD_ADMIN_TOKEN is unset, before ever sending a request', async () => {
  const original = process.env.ENGRAM_CLOUD_ADMIN_TOKEN;
  try {
    delete process.env.ENGRAM_CLOUD_ADMIN_TOKEN;
    await assert.rejects(() => listUsers());
    assert.deepEqual(lastRequest, {});
  } finally {
    process.env.ENGRAM_CLOUD_ADMIN_TOKEN = original;
  }
});
