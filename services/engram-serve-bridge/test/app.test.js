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

test('a request to the wrapper is proxied to the fixed backend port', async () => {
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

  const server = createServer(() => backend.port);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const bridgePort = /** @type {any} */ (server.address()).port;

  try {
    const response = await fetch(`http://127.0.0.1:${bridgePort}/health`, {
      method: 'POST',
      headers: { 'x-test-header': 'hello' },
      body: 'ping',
    });
    const text = await response.text();

    assert.equal(response.status, 200);
    assert.equal(text, 'echo:ping');
    assert.equal(response.headers.get('x-echo-header'), 'hello');
  } finally {
    server.close();
    backend.close();
  }
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

  const server = createServer(() => backend.port);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const bridgePort = /** @type {any} */ (server.address()).port;

  try {
    const firstChunkReceivedAt = await new Promise((resolve, reject) => {
      let firstAt = 0;
      const clientReq = http.get(`http://127.0.0.1:${bridgePort}/stream`, (res) => {
        res.once('data', () => {
          firstAt = Date.now();
        });
        res.on('end', () => resolve(firstAt));
        res.on('error', reject);
      });
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

test('a backend connection error surfaces as 502', async () => {
  const server = createServer(() => 1);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const bridgePort = /** @type {any} */ (server.address()).port;

  try {
    const response = await fetch(`http://127.0.0.1:${bridgePort}/health`);
    assert.equal(response.status, 502);
  } finally {
    server.close();
  }
});
