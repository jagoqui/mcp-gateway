import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { startEngramServe } from '../src/spawn.js';

const noWait = async () => {};

test('startEngramServe spawns the child with the right port and env', async () => {
  const calls = [];
  const spawnChild = ({ port, env }) => {
    calls.push({ port, env });
    return { exitCode: null };
  };

  await startEngramServe({
    port: 17000,
    env: { ENGRAM_CLOUD_AUTOSYNC: '1', ENGRAM_CLOUD_TOKEN: 't', ENGRAM_CLOUD_SERVER: 's' },
    spawnChild,
    waitUntilReady: noWait,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].port, 17000);
  assert.equal(calls[0].env.ENGRAM_CLOUD_AUTOSYNC, '1');
  assert.equal(calls[0].env.ENGRAM_CLOUD_TOKEN, 't');
  assert.equal(calls[0].env.ENGRAM_CLOUD_SERVER, 's');
});

test('startEngramServe does not resolve until the child is actually ready', async () => {
  const order = [];
  const spawnChild = () => {
    order.push('spawned');
    return { exitCode: null };
  };
  const waitUntilReady = async () => {
    order.push('ready');
  };

  await startEngramServe({ port: 17001, env: {}, spawnChild, waitUntilReady });

  assert.deepEqual(order, ['spawned', 'ready']);
});

test('startEngramServe propagates a readiness timeout without swallowing it', async () => {
  const spawnChild = () => ({ exitCode: null });
  const waitUntilReady = async () => {
    throw new Error('did not become ready within 150ms');
  };

  await assert.rejects(
    () => startEngramServe({ port: 17002, env: {}, spawnChild, waitUntilReady }),
    /did not become ready/i,
  );
});

test('the real waitUntilReady resolves once the port is actually accepting connections', async () => {
  const port = 17300;
  /** @type {import('node:net').Server} */
  let server;
  const spawnChild = () => {
    setTimeout(() => {
      server = net.createServer();
      server.listen(port, '127.0.0.1');
    }, 60);
    return { exitCode: null };
  };

  try {
    await startEngramServe({
      port,
      env: {},
      spawnChild,
      readyTimeoutMs: 2000,
      readyIntervalMs: 20,
    });
  } finally {
    server?.close();
  }
});
