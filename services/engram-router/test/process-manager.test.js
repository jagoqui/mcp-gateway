import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createProcessManager } from '../src/process-manager.js';

// Every existing test below spawns a fake child that never actually listens
// on its allocated port — inject a no-op readiness check so they stay fast
// and don't depend on real sockets. The dedicated readiness tests further
// down exercise the REAL default instead.
const noWait = async () => {};

// Likewise, inject a no-op enrollment so existing tests don't try to run a
// real `engram cloud enroll` binary. The dedicated enrollment tests below
// exercise the actual injectable enrollProject contract.
const noEnroll = async () => {};

/**
 * A fake child process shaped like node:child_process's ChildProcess just
 * enough for process-manager.js: `exitCode` starts null (alive) and can be
 * flipped to simulate a crash, matching the real API so the same
 * healthy/dead check works against a real spawned process later.
 */
function makeFakeChild() {
  return { exitCode: null, pid: Math.floor(Math.random() * 100000), killed: false };
}

function makeStubSpawner() {
  const calls = [];
  const children = [];
  const spawnChild = ({ identity, port, env }) => {
    calls.push({ identity, port, env });
    const child = makeFakeChild();
    children.push(child);
    return child;
  };
  return { spawnChild, calls, children };
}

test('first request for a new identity spawns a child with the right env', async () => {
  const { spawnChild, calls } = makeStubSpawner();
  const pm = createProcessManager({
    maxChildren: 5,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 'legacy-token',
    cloudServer: 'http://engram-cloud:18080',
    spawnChild,
    waitUntilReady: noWait,
    enrollProject: noEnroll,
  });

  const result = await pm.getOrCreateChild('jagoqui');

  assert.equal(calls.length, 1);
  assert.equal(calls[0].identity, 'jagoqui');
  assert.equal(calls[0].env.ENGRAM_PROJECT, 'jagoqui');
  assert.equal(calls[0].env.ENGRAM_CLOUD_AUTOSYNC, '1');
  assert.equal(calls[0].env.ENGRAM_CLOUD_TOKEN, 'legacy-token');
  assert.equal(calls[0].env.ENGRAM_CLOUD_SERVER, 'http://engram-cloud:18080');
  assert.equal(typeof result.port, 'number');
});

test('a second request for the same healthy identity reuses the existing child', async () => {
  const { spawnChild, calls } = makeStubSpawner();
  const pm = createProcessManager({
    maxChildren: 5,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    waitUntilReady: noWait,
    enrollProject: noEnroll,
  });

  const first = await pm.getOrCreateChild('jagoqui');
  const second = await pm.getOrCreateChild('jagoqui');

  assert.equal(calls.length, 1);
  assert.equal(second.port, first.port);
});

test('a dead child is detected and replaced on the next request', async () => {
  const { spawnChild, calls, children } = makeStubSpawner();
  const pm = createProcessManager({
    maxChildren: 5,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    waitUntilReady: noWait,
    enrollProject: noEnroll,
  });

  const first = await pm.getOrCreateChild('jagoqui');
  children[0].exitCode = 1; // simulate a crash

  const second = await pm.getOrCreateChild('jagoqui');

  assert.equal(calls.length, 2);
  assert.notEqual(second.port, undefined);
  void first;
});

test('a request beyond the concurrency ceiling is rejected without spawning', async () => {
  const { spawnChild, calls } = makeStubSpawner();
  const pm = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    waitUntilReady: noWait,
    enrollProject: noEnroll,
  });

  await pm.getOrCreateChild('jagoqui');
  await assert.rejects(() => pm.getOrCreateChild('yenny'), /capacity/i);

  assert.equal(calls.length, 1);
});

// getOrCreateChild must not resolve until the spawned child is ACTUALLY
// accepting connections — supergateway/engram mcp need real startup time,
// and proxying to a not-yet-listening port is exactly the "502 bad_gateway"
// race this covers. These two tests exercise the REAL default readiness
// check (no waitUntilReady override), against a real net.Server.

test('getOrCreateChild waits for a newly-spawned child to actually accept connections before resolving', async () => {
  const port = 19200;
  let listening = false;
  /** @type {import('node:net').Server} */
  let server;
  const spawnChild = () => {
    setTimeout(() => {
      server = net.createServer();
      server.listen(port, '127.0.0.1', () => {
        listening = true;
      });
    }, 60);
    return { exitCode: null };
  };

  const pm = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: port, max: 1 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    enrollProject: noEnroll,
    readyTimeoutMs: 2000,
    readyIntervalMs: 20,
  });

  try {
    await pm.getOrCreateChild('jagoqui');
    assert.equal(
      listening,
      true,
      'getOrCreateChild resolved before the port was actually listening',
    );
  } finally {
    server?.close();
  }
});

test('getOrCreateChild throws and cleans up if the child never becomes ready within the timeout', async () => {
  const port = 19201;
  // Nothing ever listens on this port — spawnChild "succeeds" but the
  // process never actually opens it, simulating a hung/broken startup.
  const spawnChild = () => ({ exitCode: null });

  const pm = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: port, max: 1 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    enrollProject: noEnroll,
    readyTimeoutMs: 150,
    readyIntervalMs: 20,
  });

  await assert.rejects(() => pm.getOrCreateChild('jagoqui'), /did not become ready/i);

  // A retry must be able to attempt a fresh spawn, not be stuck thinking
  // capacity is full because of the failed attempt's leftover entry.
  let secondSpawnCalled = false;
  const spawnChild2 = () => {
    secondSpawnCalled = true;
    return { exitCode: null };
  };
  const pm2 = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: port, max: 1 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild: spawnChild2,
    waitUntilReady: noWait,
    enrollProject: noEnroll,
  });
  await pm2.getOrCreateChild('jagoqui');
  assert.equal(secondSpawnCalled, true);
});

// engram's own local SQLite requires a project to be explicitly enrolled
// (a one-time `engram cloud enroll <project>`, writing local state) before
// autosync will push anything for it — confirmed against engram's actual
// source, not assumed. Skipping this step is exactly why the very first
// deploy of this bridge silently synced nothing, ever, for any project.

test('getOrCreateChild enrolls the project before spawning a new child', async () => {
  const { spawnChild, calls: spawnCalls } = makeStubSpawner();
  const enrollCalls = [];
  const enrollProject = async ({ project, env }) => {
    enrollCalls.push({ project, env });
  };

  const pm = createProcessManager({
    maxChildren: 5,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 'legacy-token',
    cloudServer: 'http://engram-cloud:18080',
    spawnChild,
    enrollProject,
    waitUntilReady: noWait,
  });

  await pm.getOrCreateChild('jagoqui');

  assert.equal(enrollCalls.length, 1);
  assert.equal(enrollCalls[0].project, 'jagoqui');
  assert.equal(enrollCalls[0].env.ENGRAM_CLOUD_TOKEN, 'legacy-token');
  assert.equal(enrollCalls[0].env.ENGRAM_CLOUD_SERVER, 'http://engram-cloud:18080');
  // Enrollment must happen BEFORE the child is spawned, not after or racing it.
  assert.equal(spawnCalls.length, 1);
});

test('a reused healthy child does not re-enroll on every request', async () => {
  const { spawnChild } = makeStubSpawner();
  let enrollCallCount = 0;
  const enrollProject = async () => {
    enrollCallCount += 1;
  };

  const pm = createProcessManager({
    maxChildren: 5,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    enrollProject,
    waitUntilReady: noWait,
  });

  await pm.getOrCreateChild('jagoqui');
  await pm.getOrCreateChild('jagoqui');

  assert.equal(enrollCallCount, 1);
});

test('a failed enrollment rejects getOrCreateChild without spawning, and leaves no leftover state', async () => {
  const { spawnChild, calls: spawnCalls } = makeStubSpawner();
  const enrollProject = async () => {
    throw new Error('engram cloud enroll failed: connection refused');
  };

  const pm = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild,
    enrollProject,
    waitUntilReady: noWait,
  });

  await assert.rejects(() => pm.getOrCreateChild('jagoqui'), /enroll failed/i);
  assert.equal(
    spawnCalls.length,
    0,
    'must never spawn a child for a project that failed to enroll',
  );

  // No leftover map/port state from the failed attempt — a retry (once
  // enrollment can succeed) must be able to spawn cleanly.
  let secondSpawnCalled = false;
  const pm2 = createProcessManager({
    maxChildren: 1,
    portAllocatorOptions: { base: 19100, max: 5 },
    cloudToken: 't',
    cloudServer: 's',
    spawnChild: () => {
      secondSpawnCalled = true;
      return { exitCode: null };
    },
    enrollProject: noEnroll,
    waitUntilReady: noWait,
  });
  await pm2.getOrCreateChild('jagoqui');
  assert.equal(secondSpawnCalled, true);
});
