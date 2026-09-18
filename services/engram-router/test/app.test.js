import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer } from '../src/app.js';

/** Starts a plain HTTP server on an ephemeral port, returns { port, close }. */
function startBackend(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ port: /** @type {any} */ (address).port, close: () => server.close() });
    });
  });
}

function makeStubProcessManager(resolvedPort, { reject, rejectWith } = {}) {
  const calls = [];
  return {
    calls,
    getOrCreateChild(project) {
      calls.push(project);
      if (rejectWith) {
        return Promise.reject(rejectWith);
      }
      if (reject) {
        return Promise.reject(new Error('engram-router: at capacity'));
      }
      return Promise.resolve({ port: resolvedPort });
    },
  };
}

test('request with valid identity is proxied to the resolved child port', async () => {
  const backend = await startBackend((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      res.writeHead(200, { 'X-Echo-Header': req.headers['x-test-header'] ?? '' });
      res.end(`echo:${body}`);
    });
  });

  const pm = makeStubProcessManager(backend.port);
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  const response = await fetch(`http://127.0.0.1:${routerPort}/mcp/engram`, {
    method: 'POST',
    headers: { 'x-gateway-user': 'jagoqui', 'x-test-header': 'hello' },
    body: 'ping',
  });
  const text = await response.text();

  assert.equal(response.status, 200);
  assert.equal(text, 'echo:ping');
  assert.equal(response.headers.get('x-echo-header'), 'hello');
  assert.deepEqual(pm.calls, ['jagoqui']);

  server.close();
  backend.close();
});

test('a subproject header now reaches the process manager as a BARE project (engram-shared-projects — no more identity prefix)', async () => {
  const backend = await startBackend((req, res) => res.end('ok'));
  const pm = makeStubProcessManager(backend.port);
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  await fetch(`http://127.0.0.1:${routerPort}/mcp/engram`, {
    headers: { 'x-gateway-user': 'jagoqui', 'x-engram-subproject': 'skills-registry' },
  });

  assert.deepEqual(pm.calls, ['skills-registry']);

  server.close();
  backend.close();
});

test('a GrantDeniedError from the process manager surfaces as 403, distinct from the capacity 503', async () => {
  const { GrantDeniedError } = await import('../src/process-manager.js');
  const pm = makeStubProcessManager(9999, { rejectWith: new GrantDeniedError('no grant') });
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  const response = await fetch(`http://127.0.0.1:${routerPort}/mcp/engram`, {
    headers: { 'x-gateway-user': 'jagoqui', 'x-engram-subproject': 'team-alpha' },
  });

  assert.equal(response.status, 403);

  server.close();
});

test('request with missing identity is rejected before touching the process manager', async () => {
  const pm = makeStubProcessManager(9999);
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  const response = await fetch(`http://127.0.0.1:${routerPort}/mcp/engram`);

  assert.equal(response.status, 401);
  assert.deepEqual(pm.calls, []);

  server.close();
});

test('a capacity rejection from the process manager surfaces as 503', async () => {
  const pm = makeStubProcessManager(9999, { reject: true });
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  const response = await fetch(`http://127.0.0.1:${routerPort}/mcp/engram`, {
    headers: { 'x-gateway-user': 'jagoqui' },
  });

  assert.equal(response.status, 503);

  server.close();
});

test('a chunked backend response is forwarded as it streams, not buffered until complete', async () => {
  let secondChunkWrittenAt = 0;
  const backend = await startBackend((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('chunk-one');
    setTimeout(() => {
      secondChunkWrittenAt = Date.now();
      res.write('chunk-two');
      res.end();
    }, 80);
  });

  const pm = makeStubProcessManager(backend.port);
  const server = createServer(pm);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const routerPort = /** @type {any} */ (server.address()).port;

  try {
    // Waits for the FULL response (both chunks) so secondChunkWrittenAt is
    // guaranteed set before comparing — comparing right after the first
    // 'data' event would race against the still-unset (0) timestamp.
    const firstChunkReceivedAt = await new Promise((resolve, reject) => {
      let firstAt = 0;
      const clientReq = http.get(
        `http://127.0.0.1:${routerPort}/mcp/engram`,
        { headers: { 'x-gateway-user': 'jagoqui' } },
        (res) => {
          res.once('data', () => {
            firstAt = Date.now();
          });
          res.on('end', () => resolve(firstAt));
          res.on('error', reject);
        },
      );
      clientReq.on('error', reject);
    });

    assert.ok(
      firstChunkReceivedAt < secondChunkWrittenAt,
      'the first chunk must arrive at the client before the backend even writes the second one',
    );
  } finally {
    server.close();
    backend.close();
  }
});
